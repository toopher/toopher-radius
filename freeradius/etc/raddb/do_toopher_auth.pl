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
use lib "$FindBin::Bin/lib";
use Carp;
$Carp::Verbose = 1;

my $testmode = $ARGV[0] eq 'test';

# use ...
# This is very important ! Without this script will not get the filled hashes from main.
use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK %RAD_CONFIG);

use ToopherAPI;
use Net::LDAP;
#use YAML;
#use JSON qw{ decode_json };
use toopher_radius_config;
use Data::Dumper;
use Net::OAuth::SignatureMethod::HMAC_SHA1;

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

#$config = YAML::LoadFile('toopher_radius_config.yaml');
#my $contents = do { local $/; local @ARGV = "toopher_radius_config.json"; <> };
#$config = decode_json($contents);
my $config = toopher_radius_config::get_config;
$api = ToopherAPI->new(key=>$config->{'toopher_api'}{'key'},
                          secret=>$config->{'toopher_api'}{'secret'},
                          api_url=>$config->{'toopher_api'}{'url'});

sub _log {
  my ($msg) = @_;
  if($testmode){
    print($msg . "\n");
  } else { 
    &radiusd::radlog(0, $msg);
  }
}
# Function to handle authorize
sub authorize {
  $RAD_CHECK{'Auth-Type'} = 'TOOPHER_AD';
  return RLM_MODULE_OK;
}

sub issue_pairing_challenge_prompt {
  $RAD_REPLY{'State'} = 'challenge_reply';
  $RAD_REPLY{'Reply-Message'} = $config->{'prompts'}{'pairing_challenge'};
  $RAD_CHECK{'Response-Packet-Type'} = 'Access-Challenge';
  return RLM_MODULE_HANDLED;
}

sub check_with_toopher {
  my ($toopherPairingId, $toopherTerminalName) = @_;
  
  my $auth = $api->authenticate($toopherPairingId, $toopherTerminalName);
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
}

sub pair_with_toopher {
  my ($pairingPhrase, $userName) = @_;
  my $pairing;
  eval { $pairing = $api->pair($pairingPhrase, $userName);};
  if($@){
    _log("Error in pairing: " . $@);
    return 0;
  }
  while(!$pairing->enabled){
    sleep(1);
    eval { $pairing = $api->get_pairing_status($pairing->id); };
    if($@){
      _log("Error in pairing: " . $@);
      return 0;
    }
  }
  if($pairing->enabled){
    return $pairing->id;
  } else {
    return 0;
  }
}

# just do Toopher authentication.  Assumes some other module is handling primary authentication
sub authenticate_simple {
  if (defined $RAD_REPLY{'Toopher-Pairing-Id'}){
    return &check_with_toopher($RAD_REPLY{'Toopher-Pairing-Id'}, undef, undef, 'false');
  } else {
    return RLM_MODULE_OK
  }
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

sub handle_pairing_challenge_reply{
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
    $RAD_REPLY{'REPLY_MESSAGE'} = 'Unexpected error querying active directory!';
    return RLM_MODULE_REJECT;
  }
  my $ldapUser = $entries[0];
  my $userCN = $ldapUser->get_value('CN');
  
  my $pairingId = &pair_with_toopher($pairing_phrase, $userCN);
  if(!$pairingId){
    _log("Failed to pair user $username");
    $RAD_REPLY{'Reply-Message'} = 'Failed to pair account with ToopherAPI';
    $RAD_REPLY{'State'} = 'init';
    return RLM_MODULE_REJECT;
  }
  _log("Paired user $username with Toopher.  Pairing id=$pairingId");

  $message = $ldapUser->add( toopherPairingID => $pairingId )->update($ldap);
  if ($message->is_error){
    _log('unable to update user account with Toopher Pairing ID.');
    _log('ldap return code is ' . $message->code());
  }

  return RLM_MODULE_OK;
}

# authenticate through Active Directory, then do Toopher authentication
sub authenticate_ad {
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
    return authenticate_ad_username_password();
  } elsif($state =~ 'challenge_reply'){
    return handle_pairing_challenge_reply();
  } else {
    $RAD_REPLY{'Reply-Message'} = 'unknown State message: ' . $state;
    $RAD_REPLY{'State'} = 'init';
    return RLM_MODULE_REJECT;
  }
}

sub test_toopher_rlm_perl {
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

if($ARGV[0] eq 'test'){
  test_toopher_rlm_perl();
} 

1;
