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
use FindBin;
use lib "$FindBin::Bin/";
$Carp::Verbose = 1;
# use ...
# This is very important ! Without this script will not get the filled hashes from main.
use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK %RAD_CONFIG);
use Data::Dumper;
use ToopherAPI;
use Net::LDAP;
use YAML;
use DBI;


# This is hash wich hold original request from radius
#my %RAD_REQUEST;
# In this hash you add values that will be returned to NAS.
#my %RAD_REPLY;
#This is for check items
#my %RAD_CHECK;

#
# This the remapping of return values
#
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

use constant AD_HOST => '172.16.0.4';
use constant AD_PRINCIPAL => 'vpn.toopher.com';
use constant AD_DC => 'DC=vpn,DC=toopher,DC=com';


our $api;
our $config;

$config = YAML::LoadFile('toopher_radius_config.yaml');
$api = ToopherAPI->new(key=>$config->{'toopher_api'}{'key'},
                          secret=>$config->{'toopher_api'}{'secret'},
                          api_url=>$config->{'toopher_api'}{'url'});
my $dbh = DBI->connect($config->{'session_store'}{'connection_string'});
$dbh->do('CREATE TABLE IF NOT EXISTS session_store(state TEXT PRIMARY KEY, username TEXT)');
$dbh->disconnect();

# Function to handle authorize
sub authorize {
  $RAD_CHECK{'Auth-Type'} = 'TOOPHER_AD';
  return RLM_MODULE_OK;
}

sub get_saved_username_from_state{
  my ($state) = @_;

  my $dbh = DBI->connect($config->{'session_store'}{'connection_string'});
  my $sth = $dbh.prepare("SELECT username FROM session_store WHERE state=?");
  $sth.execute($state);
  my $result = $sth.fetch();
  $sth.finish();
  $dbh->disconnect();
  return $result;
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
    &radiusd::radlog(0, "Error in pairing: " . $@);
    return 0;
  }
  while(!$pairing->enabled){
    sleep(1);
    eval { $pairing = $api->get_pairing_status($pairing->id); };
    if($@){
      &radiusd::radlog(0, "Error in pairing: " . $@);
      return 0;
    }
  }
  if($pairing->enabled =~ /rue/){
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
  &radiusd::radlog(0, 'ldap config is:');
  &radiusd::radlog(0, $config->{'ldap'});
  my $ldap = Net::LDAP->new($config->{'ldap'}{'host'}) or die "$@";
  my $message = $ldap->bind($username . '@' . $config->{'ldap'}{'principal'}, password => $passwd);
  if ($message->is_error){

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
    &radiusd::radlog(0, 'Got Toopher Pairing ID of ' . $toopherPairingId . ' from RAD_REPLY');
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
      &radiusd::radlog(0, 'Got Toopher Pairing ID of ' . $toopherPairingId . ' from AD');
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
  &radiusd::radlog(0, 'handle_pairing_challenge_reply');
  my $username = $RAD_REQUEST{'User-Name'};
  my $pairing_phrase = $RAD_REQUEST{'User-Password'};

  my $ldap = Net::LDAP->new($config->{'ldap'}{'host'}) or die "$@";
  my $message = $ldap->bind($config->{'ldap'}{'username'} . '@' . $config->{'ldap'}{'principal'}, password => $config->{'ldap'}{'password'});
  if ($message->is_error){
    &radiusd::radlog(0, 'unable to bind to radius client user account');
    &radiusd::radlog(0, 'ldap return code is ' . $message->code());
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
  &radiusd::radlog(0, "username is $username, CN is $userCN, pairing phrase is $pairing_phrase"); 

  
  my $pairingId = &pair_with_toopher($pairing_phrase, $userCN);
  if(!$pairingId){
    &radiusd::radlog(0, "Failed to pair user $username with pairing phrase $pairing_phrase");
    $RAD_REPLY{'Reply-Message'} = 'Failed to pair account with ToopherAPI';
    $RAD_REPLY{'State'} = 'init';
    return RLM_MODULE_REJECT;
  }
  &radiusd::radlog(0, "Paired user $username with Toopher.  Pairing id=$pairingId");

  $message = $ldapUser->add( toopherPairingID => $pairingId )->update($ldap);
  if ($message->is_error){
    &radiusd::radlog(0, 'unable to update user account with Toopher Pairing ID.');
    &radiusd::radlog(0, 'ldap return code is ' . $message->code());
  }

  return RLM_MODULE_OK;
}

# authenticate through Active Directory, then do Toopher authentication
sub authenticate_ad {
  log_request_attributes();
  my $state = 'init';
  if($RAD_REQUEST{'State'}){
    if($RAD_REQUEST{'State'} =~ /^0x/){
      $state = pack('H*', substr($RAD_REQUEST{'State'}, 2));
    } else {
      $state = $RAD_REQUEST{'State'};
    }
    $RAD_REQUEST{'State'} = 'init';
  }
  &radiusd::radlog(0, "Decoded state is $state");
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

# Function to handle preacct
sub preacct {
    # For debugging purposes only
#       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle accounting
sub accounting {
    # For debugging purposes only
#       &log_request_attributes;

    # You can call another subroutine from here
    &test_call;

    return RLM_MODULE_OK;
}

# Function to handle checksimul
sub checksimul {
    # For debugging purposes only
#       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle pre_proxy
sub pre_proxy {
    # For debugging purposes only
#       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle post_proxy
sub post_proxy {
    # For debugging purposes only
#       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle post_auth
sub post_auth {
    # For debugging purposes only
#       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle xlat
sub xlat {
    # For debugging purposes only
#       &log_request_attributes;

    # Loads some external perl and evaluate it
    my ($filename,$a,$b,$c,$d) = @_;
    &radiusd::radlog(1, "From xlat $filename ");
    &radiusd::radlog(1,"From xlat $a $b $c $d ");
    local *FH;
    open FH, $filename or die "open '$filename' $!";
    local($/) = undef;
    my $sub = <FH>;
    close FH;
    my $eval = qq{ sub handler{ $sub;} };
    eval $eval;
    eval {main->handler;};
}

# Function to handle detach
sub detach {
    # For debugging purposes only
#       &log_request_attributes;

    # Do some logging.
    &radiusd::radlog(0,"rlm_perl::Detaching. Reloading. Done.");
}

sub log_request_attributes {
    for (keys %RAD_REQUEST) {
            &radiusd::radlog(1, "RAD_REQUEST: $_ = $RAD_REQUEST{$_}");
    }
    for (keys %RAD_REPLY) {
            &radiusd::radlog(1, "RAD_REPLY  : $_ = $RAD_REPLY{$_}");
    }
    for (keys %RAD_CHECK) {
            &radiusd::radlog(1, "RAD_CHECK  : $_ = $RAD_CHECK{$_}");
    }
    for (keys %RAD_CONFIG) {
            &radiusd::radlog(1, "RAD_CONFIG  : $_ = $RAD_CONFIG{$_}");
    }
}


1;
