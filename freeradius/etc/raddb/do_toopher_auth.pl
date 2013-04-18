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
# use ...
# This is very important ! Without this script will not get the filled hashes from main.
use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK %RAD_CONFIG);
use Data::Dumper;
use ToopherAPI;
use Net::LDAP;

my $api = ToopherAPI->new(key=>$ENV{'TOOPHER_CONSUMER_KEY'}, secret=>$ENV{'TOOPHER_CONSUMER_SECRET'});

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


# Function to handle authorize
sub authorize {
  $RAD_CHECK{'Auth-Type'} = 'TOOPHER_AD';
  return RLM_MODULE_OK;
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

# just do Toopher authentication.  Assumes some other module is handling primary authentication
sub authenticate_simple {
  if (defined $RAD_REPLY{'Toopher-Pairing-Id'}){
    return &check_with_toopher($RAD_REPLY{'Toopher-Pairing-Id'}, undef, undef, 'false');
  } else {
    return RLM_MODULE_OK
  }
}

# authenticate through Active Directory, then do Toopher authentication
sub authenticate_ad {

  my $username = $RAD_REQUEST{'User-Name'};
  my $passwd = $RAD_REQUEST{'User-Password'};
  my $ldap = Net::LDAP->new(AD_HOST) or die "$@";
  my $message = $ldap->bind($username . '@' . AD_PRINCIPAL, password => $passwd);
  if ($message->is_error){

    $RAD_REPLY{'Reply-Message'} = 'Failed AD check';
    return RLM_MODULE_REJECT;
  }
  my $toopherPairingId = '';
  my $doToopherAuthOnLogin = 0;
  if (defined $RAD_REPLY{'Toopher-Pairing-Id'}){
    $toopherPairingId = $RAD_REPLY{'Toopher-Pairing-Id'};
    $doToopherAuthOnLogin = 1;
    &radiusd::radlog(0, 'Got Toopher Pairing ID of ' . $toopherPairingId . ' from RAD_REPLY');
    undef $RAD_REPLY{'Toopher-Pairing-Id'};
  } else {
    my $search = $ldap->search(
      base => AD_DC,
      filter => "(&(objectCategory=Person)(objectClass=User)(sAMAccountName=" . $username . "))");
    my @entries = $search->entries;
    if (length(@entries) != 1) {

      $RAD_REPLY{'REPLY_MESSAGE'} = 'Unexpected error querying active directory!';
      return RLM_MODULE_REJECT;
    }
    if ($entries[0]->exists('toopherPairingID')){
      $toopherPairingId = $entries[0]->get_value('toopherPairingID');
      &radiusd::radlog(0, 'Got Toopher Pairing ID of ' . $toopherPairingId . ' from AD');
    }
    if ($entries[0]->exists('toopherAuthenticateLogon')){
      $doToopherAuthOnLogin = $entries[0]->get_value('toopherAuthenticateLogon') == 'TRUE';
    }
  }
  if ($doToopherAuthOnLogin){
    return &check_with_toopher($toopherPairingId, $RAD_REQUEST{'Calling-Station-Id'});
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

#
# Some functions that can be called from other functions
#

sub test_call {
    # Some code goes here
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
