#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
#
#  Copyright 2002  The FreeRADIUS server project
#  Copyright 2002  Boian Jordanov <bjordanov@orbitel.bg>
#

#
# Example code for use with rlm_perl
#
# You can use every module that comes with your perl distribution!
#

use strict;
#use diagnostics;
use FindBin;
use lib "$FindBin::Bin/";
use Carp ;
use Try::Tiny;
$Carp::Verbose = 1;

my $testmode = $ARGV[0];

# use ...
# This is very important ! Without this script will not get the filled hashes from main.
use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK %RAD_CONFIG);

use ToopherAPI;
use Net::LDAP;
use toopher_radius_config;
use Data::Dumper;
use Net::OAuth::SignatureMethod::HMAC_SHA1;

use constant    CHALLENGE_STATE_PAIR=> 'challenge_state_pair';
use constant    CHALLENGE_STATE_OTP => 'challenge_state_otp';

use constant    RLM_MODULE_REJECT=>    0;#  /* immediately reject the request */
use constant    RLM_MODULE_FAIL=>      1;#  /* module failed, don't reply */
use constant    RLM_MODULE_OK=>        2;#  /* the module is OK, continue */
use constant    RLM_MODULE_HANDLED=>   3;#  /* the module handled the request, so stop. */
use constant    RLM_MODULE_INVALID=>   4;#  /* the module considers the request invalid. */
use constant    RLM_MODULE_USERLOCK=>  5;#  /* reject the request (user is locked out) */
use constant    RLM_MODULE_NOTFOUND=>  6;#  /* user not found */
use constant    RLM_MODULE_NOOP=>      7;#  /* module succeeded without doing anything */
use constant    RLM_MODULE_UPDATED=>   8;#  /* OK (pairs modified) */
use constant    RLM_MODULE_NUMCODES=>  9;#  /* How many return codes there are */

our $api;

my $config = toopher_radius_config::get_config;

sub _log {
  my ($msg) = @_;
  if($testmode){
    print($msg . "\n");
  } else { 
    &radiusd::radlog(0, $msg);
  }
}

$ToopherAPI::_log = \&_log;

sub issue_pairing_challenge_prompt {
  $RAD_REPLY{'State'} = CHALLENGE_STATE_PAIR;
  $RAD_REPLY{'Reply-Message'} = $config->{'prompts'}{'pairing_challenge'};
  $RAD_CHECK{'Response-Packet-Type'} = 'Access-Challenge';
  return RLM_MODULE_HANDLED;
}

sub issue_otp_challenge_prompt {
  $RAD_REPLY{'State'} = CHALLENGE_STATE_OTP;
  $RAD_REPLY{'Reply-Message'} = $config->{'prompts'}{'otp_challenge'};
  $RAD_CHECK{'Response-Packet-Type'} = 'Access-Challenge';
  return RLM_MODULE_HANDLED;
}

sub poll_for_auth {
  my ($auth) = @_;
  my $poll_count = 0;
  while($auth->pending){
    sleep(1);
    try {
      $auth = $api->get_authentication_status($auth->id);
    } catch {
      return fail('Error contacting the Toopher API: ' . $_);
    };
    $poll_count++;
    if ($poll_count > $config->{'toopher_api'}{'poll_timeout'}){
      return &issue_otp_challenge_prompt();
    }
  }
  if($auth->granted){
    return RLM_MODULE_OK;
  } else {
    $RAD_REPLY{'Reply-Message'} = 'Failed toopher authentication: ' . $auth->reason;
    return RLM_MODULE_REJECT;
  } 
}
sub check_with_toopher {
  my ($toopherPairingId, $toopherTerminalName) = @_;
  
  return poll_for_auth($api->authenticate($toopherPairingId, $toopherTerminalName));
}

sub pair_with_toopher {
  my ($pairingPhrase, $userName) = @_;
  my $pairing;
  try {
    $pairing = $api->pair($pairingPhrase, $userName);
  } catch {
    return fail("Error while pairing: " . $_);
  };

  while(!$pairing->enabled){
    sleep(1);
    try {
      $pairing = $api->get_pairing_status($pairing->id);
    } catch {
      return fail("Error contacting the Toopher API: " . $_);
    };
  }
  if($pairing->enabled){
    return $pairing->id;
  } else {
    $RAD_REPLY{'Reply-Message'} = "Pairing was not completed on mobile device";
    return RLM_MODULE_REJECT;
  }
}


# just do Toopher authentication.  Assumes some other module is handling primary authentication
sub authenticate_simple {
  if (defined $RAD_REPLY{'Toopher-Pairing-Id'}){
    return &check_with_toopher($RAD_REPLY{'Toopher-Pairing-Id'}, undef, undef, 'false');
  } else {
    return RLM_MODULE_OK;
  }
}

# Zero-requester-storage authentication
sub authenticate_zrs {
  my $username = $RAD_REQUEST{'User-Name'};
  my $terminal_identifier = "";
  foreach my $term_id_attr_name ($config->{'terminal_identifier'}) {
    $terminal_identifier .= $RAD_REQUEST{$term_id_attr_name};
  }
  try {
    return poll_for_auth($api->authenticate_by_user_name($username, $terminal_identifier));
  } catch {
    if ($_ eq ToopherAPI::ERROR_USER_DISABLED) {
      return RLM_MODULE_OK;
    } elsif ($_ eq ToopherAPI::ERROR_UNKNOWN_USER) {
      return &issue_pairing_challenge_prompt();
    } elsif ($_ eq ToopherAPI::ERROR_UNKNOWN_TERMINAL) {
      # can't really deal with this in a RADIUS context due to UI restrictions
    } elsif ($_ eq ToopherAPI::ERROR_PAIRING_DEACTIVATED) {
      return &issue_pairing_challenge_prompt();
    } else {
      _log('unknown error: ' . $_);
      fail('Unknown error while authenticating: ' . $_);
    }
  };    
}

sub authenticate_ad_username_password {
  my $username = $RAD_REQUEST{'User-Name'};
  my $passwd = $RAD_REQUEST{'User-Password'};
  my $ldap = Net::LDAP->new($config->{'ldap'}{'host'}) or die "$@";
  my $message = $ldap->bind($username . '@' . $config->{'ldap'}{'principal'}, password => $passwd);
  if ($message->is_error){
    _log('bad initial bind');
    $RAD_REPLY{'Reply-Message'} = 'bad username or password';
    return RLM_MODULE_REJECT;
  }
  my $toopherPairingId = '';
  my $doToopherAuthOnLogin = 0;
  my $userCN = '';
  if (defined $RAD_REPLY{'Toopher-Pairing-Id'}){
    # Toopher pairing info supplied from some other source, don't look for it in AD
    $toopherPairingId = $RAD_REPLY{'Toopher-Pairing-Id'};
    $doToopherAuthOnLogin = 1;
    undef $RAD_REPLY{'Toopher-Pairing-Id'};
  } else {
    my $search = $ldap->search(
      base => $config->{'ldap'}{'dc'},
      filter => "(&(objectCategory=Person)(objectClass=User)(sAMAccountName=" . $username . "))");
    my @entries = $search->entries;
    if (length(@entries) != 1) {

      $RAD_REPLY{'REPLY_MESSAGE'} = 'Unexpected error querying active directory!';
      return RLM_MODULE_REJECT;
    }
    $userCN = $entries[0]->get_value('cn');
    if ($entries[0]->exists('toopherPairingID')){
      $toopherPairingId = $entries[0]->get_value('toopherPairingID');
    }
    if ($entries[0]->exists('toopherAuthenticateLogon')){
      $doToopherAuthOnLogin = $entries[0]->get_value('toopherAuthenticateLogon') eq 'TRUE';
    }
  }
  if ($doToopherAuthOnLogin){
    if($toopherPairingId){
      return &check_with_toopher($toopherPairingId, $RAD_REQUEST{'Calling-Station-Id'});
    } else {
      return &issue_pairing_challenge_prompt();
    }
    my $auth = $api->authenticate($toopherPairingId, $RAD_REQUEST{'Calling-Station-Id'});
    while($auth->pending){
      sleep(1);
      $auth = $api->get_authentication_status($auth->id);
    }
    if($auth->granted){
      return RLM_MODULE_OK;
    } else {
      $RAD_REPLY{'Reply-Message'} = 'Failed toopher authentication: ' . $auth->reason;
      return RLM_MODULE_REJECT;
    } 
  } else {
    return RLM_MODULE_OK;
  }
}

sub fail
{
  my ($message) = @_;
  $RAD_REPLY{'Reply-Message'} = $message;
  $RAD_REPLY{'State'} = 'init';
  return RLM_MODULE_REJECT;
}
sub handle_pairing_challenge_reply
{
  my $username = $RAD_REQUEST{'User-Name'};
  my $pairing_phrase = $RAD_REQUEST{'User-Password'};
  try {
    &pair_with_toopher($pairing_phrase, $username);
    return RLM_MODULE_OK;
  } catch {
    return fail('Error while pairing with ToopherAPI: ' . $_);
  };
}

sub handle_otp_challenge_reply
{
  my $username = $RAD_REQUEST{'User-Name'};
  my $otp = $RAD_REQUEST{'User-Password'};
  try {
    my $auth = $api->authenticate_by_user_name($username, '', '', { otp => $otp });
    if ($auth->granted) {
      return RLM_MODULE_OK;
    } else {
      $RAD_REPLY{'Reply-Message'} = $auth->reason;
      return RLM_MODULE_REJECT;
    }
  } catch {
    return fail('Failed to authenticate with the Toopher API');
  }
}
sub handle_pairing_challenge_reply_ad{
  my $username = $RAD_REQUEST{'User-Name'};
  my $pairing_phrase = $RAD_REQUEST{'User-Password'};

  my $ldap = Net::LDAP->new($config->{'ldap'}{'host'}) or die "$@";
  my $message = $ldap->bind($config->{'ldap'}{'username'} . '@' . $config->{'ldap'}{'principal'}, password => $config->{'ldap'}{'password'});
  if ($message->is_error){
    _log('unable to bind to radius client user account');
    _log('ldap return code is ' . $message->code());
  }
  my $search = $ldap->search(
    base => $config->{'ldap'}{'dc'},
    filter => "(&(objectCategory=Person)(objectClass=User)(sAMAccountName=" . $username . "))");
  my @entries = $search->entries;
  if (length(@entries) != 1) {
    return fail('Unexpected error querying active directory!');
  }
  my $ldapUser = $entries[0];
  my $userCN = $ldapUser->get_value('CN');
  
  my $pairingId = &pair_with_toopher($pairing_phrase, $userCN);
  if(!$pairingId){
    _log("Failed to pair user $username");
    return fail('Failed to pair account with ToopherAPI');
  }
  _log("Paired user $username with Toopher.  Pairing id=$pairingId");

  $message = $ldapUser->add( toopherPairingID => $pairingId )->update($ldap);
  if ($message->is_error){
    _log('unable to update user account with Toopher Pairing ID.');
    _log('ldap return code is ' . $message->code());
  }

  return RLM_MODULE_OK;
}

sub do_authentication_state_machine
{
  my ($authentication_func, $pairing_func, $otp_func) = @_;
  my $state = 'init';
  if($RAD_REQUEST{'State'}){
    if($RAD_REQUEST{'State'} =~ /^0x/){
      $state = pack('H*', substr($RAD_REQUEST{'State'}, 2));
    } else {
      $state = $RAD_REQUEST{'State'};
    }
    $RAD_REQUEST{'State'} = 'init';
  }
  if($state eq 'init'){
    return $authentication_func->();
  } elsif($state =~ CHALLENGE_STATE_PAIR){
    return $pairing_func->();
  } elsif($state =~ CHALLENGE_STATE_OTP){
    return $otp_func->();
  } else {
    $RAD_REPLY{'Reply-Message'} = 'unknown State message: ' . $state;
    $RAD_REPLY{'State'} = 'init';
    return RLM_MODULE_REJECT;
  }
}

# authenticate through Active Directory, then do Toopher authentication
sub authenticate_ad {
  return do_authentication_state_machine(\&authenticate_ad_username_password, \&handle_pairing_challenge_reply_ad, \&handle_otp_challenge_reply);
}

sub authenticate_zrs_entry {
  return do_authentication_state_machine(\&authenticate_zrs, \&handle_pairing_challenge_reply, \&handle_otp_challenge_reply);
}

sub test_ad_toopher_rlm_perl {
  print('disable toopher for user dshafer and hit ENTER');
  <STDIN>;
  _log('testing simple login');
  $RAD_REQUEST{'User-Name'} = 'dshafer';
  $RAD_REQUEST{'User-Password'} = 'p@ssw0rd';
  $RAD_REQUEST{'State'} = 'init';
  croak("Didn't return OK") unless authenticate_ad() == RLM_MODULE_OK;
  _log('OK.');
  print('enable toopher for user dshafer and hit ENTER');
  <STDIN>;
  _log('testing pairing challenge login');
  $RAD_REQUEST{'User-Name'} = 'dshafer';
  $RAD_REQUEST{'User-Password'} = 'p@ssw0rd';
  $RAD_REQUEST{'State'} = 'init';
  croak("Didn't return OK") unless authenticate_ad() == RLM_MODULE_HANDLED;
  croak("didn't get radius challenge") unless $RAD_REPLY{'State'} eq 'challenge_reply';
  croak("didn't get correct channenge") unless $RAD_REPLY{'Reply-Message'} eq $config->{'prompts'}{'pairing_challenge'};
  croak("wrong packet type") unless $RAD_CHECK{'Response-Packet-Type'} eq 'Access-Challenge';

  _log('enter a pairing phrase from mobile device');
  $RAD_REQUEST{'User-Name'} = 'dshafer';
  my $pp = <STDIN>;
  chomp($pp);
  $RAD_REQUEST{'User-Name'} = 'dshafer';
  $RAD_REQUEST{'User-Password'} = $pp;
  $RAD_REQUEST{'State'} = 'challenge_reply';
  croak("Didn't return OK") unless authenticate_ad() == RLM_MODULE_OK;


  _log('authenticating dshafer');
  $RAD_REQUEST{'User-Name'} = 'dshafer';
  $RAD_REQUEST{'User-Password'} = 'p@ssw0rd';
  $RAD_REQUEST{'State'} = 'init';
  croak("Didn't return OK") unless authenticate_ad() == RLM_MODULE_OK;
  _log('Should have pushed message to toopher app...');
}

sub unittest_toopher_rlm_perl
{
  my ($ua) = @_;
  my $userName = 'user@example.com';
  my $passwd = 'password';
  my $pairingPhrase = 'awkward turtle';

  # first time user login
  $RAD_REQUEST{'User-Name'} = $userName;
  $RAD_REQUEST{'User-Password'} = $passwd;
  delete $RAD_REQUEST{'State'};

  $ua->response->code(409);
  $ua->response->content('{"error_code":705, "error_message":"No matching user exists."}');
  _log("about to start");
  croak("Didn't return RLM_MODULE_HANDLED") unless authenticate_zrs_entry() == RLM_MODULE_HANDLED;
  croak("didn't get radius challenge") unless $RAD_REPLY{'State'} eq CHALLENGE_STATE_PAIR;
  croak("didn't get correct channenge") unless $RAD_REPLY{'Reply-Message'} eq $config->{'prompts'}{'pairing_challenge'};
  croak("wrong packet type") unless $RAD_CHECK{'Response-Packet-Type'} eq 'Access-Challenge';

  # submit pairing phrase
  $RAD_REQUEST{'User-Name'} = $userName;
  $RAD_REQUEST{'User-Password'} = $pairingPhrase;
  $RAD_REQUEST{'State'} = $RAD_REPLY{'State'};
  $ua->response->code(200);
  $ua->response->content('{"id":"1", "enabled":true, "user":{"id":"1","name":"some user"}}');
  _log('submitting pairing phrase');
  croak("Didn't complete pairing") unless authenticate_zrs_entry() == RLM_MODULE_OK;
  

  # regular log-in
  $RAD_REQUEST{'User-Name'} = $userName;
  $RAD_REQUEST{'User-Password'} = $passwd;
  delete $RAD_REQUEST{'State'};
  $ua->response->code(200);
  $ua->response->content('{"id":"1", "pending":false, "granted":true, "automated":false, "reason":"its a test", "terminal":{"id":"1", "name":"test terminal"}}');
  _log("authenticating");
  croak("Failed to log in") unless authenticate_zrs_entry() == RLM_MODULE_OK;
  _log("All tests finished ok");
}

sub instantiate_toopher_api
{
  if($config->{'toopher_api'}{'key'} eq 'YOUR TOOPHER API KEY'){
    die("Before using the Toopher RADIUS server you must edit " . $FindBin::Bin . "/toopher_radius_config.pm to set your Requester API Credentials.\n");
  }
  
  $api = ToopherAPI->new(key=>$config->{'toopher_api'}{'key'},
                          secret=>$config->{'toopher_api'}{'secret'},
                          api_url=>$config->{'toopher_api'}{'url'});
}

if($ARGV[0] eq 'unittest'){
  # H/T to http://perldesignpatterns.com/?InnerClasses for this "inner class" design pattern
  my $ua = eval {
    package UA_Mock;
    use HTTP::Response;
    use URI;
    use URL::Encode qw ( url_params_mixed );
    sub new {
      my ($class) = @_;
      my $self = {
        '_response' => new HTTP::Response(200),
        '_last_request' => {}
      };
      return bless $self, $class;
    }
    sub request
    {
      my ($self, $request) = @_;
      if ($request) {
        $request->{'post_data'} = url_params_mixed($request->content);
        if (URI->new($request->uri)->query) {
          $request->{'query_data'} = url_params_mixed(URI->new($request->uri)->query);
        }
        $self->{'_last_request'} = $request;
        return $self->{'_response'};
      } else {
        return $self->{'_last_request'};
      }
    }
    sub response
    {
      my ($self) = @_;
      return $self->{'_response'};
    }
    __PACKAGE__;
  }->new();
  $api = ToopherAPI->new(key => 'key', secret => 'secret'); 
  $api->{'_ua'} = $ua;
  unittest_toopher_rlm_perl($ua);
} elsif($ARGV[0] eq 'test'){
  instantiate_toopher_api();
  test_ad_toopher_rlm_perl();
} else {
  instantiate_toopher_api();
}

1;
