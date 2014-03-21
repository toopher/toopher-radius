#!/usr/bin/perl
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
#  Copyright 2013  Toopher, Inc (https://www.toopher.com)
#


use strict;
use FindBin;
use lib "$FindBin::Bin/";
use Carp ;
use Try::Tiny;
use Digest::SHA qw(sha256_base64);
$Carp::Verbose = 1;

my $standalone = $ARGV[0];

# use ...
# This is very important ! Without this script will not get the filled hashes from main.
use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK %RAD_CONFIG);

use ToopherAPI;
use toopher_radius_config;
use Data::Dumper;
use Net::OAuth::SignatureMethod::HMAC_SHA1;

use constant    CHALLENGE_STATE_PAIR=> '0x6368616c6c656e67655f73746174655f70616972'; # unpack('H*', 'challenge_state_pair');
use constant    CHALLENGE_STATE_OTP => '0x6368616c6c656e67655f73746174655f6f7470';   # unpack('H*', 'challenge_state_otp');
use constant    CHALLENGE_STATE_TERMINAL => '0x7465726d696e616c5f69643a'; # unpack("H*", "terminal_id:");

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

use constant    LOG_DBG => 1;
use constant    LOG_INFO=> 3;
use constant    LOG_ERR => 4;

our $api;

my $config = toopher_radius_config::get_config;

sub _log {
  my ($level, $msg) = @_;
  ($level, $msg) = (LOG_DBG, $level) unless $msg;
  if($standalone){
    print($msg . "\n");
  } else { 
    &radiusd::radlog($level, $msg);
  }
}

$ToopherAPI::_log = \&_log;

sub issue_pairing_challenge_prompt {
  _log('issue_pairing_challenge_prompt');
  $RAD_REPLY{'State'} = CHALLENGE_STATE_PAIR;
  $RAD_REPLY{'Prompt'} = 'Echo';
  $RAD_REPLY{'Reply-Message'} = $config->{'prompts'}{'pairing_challenge'};
  $RAD_CHECK{'Response-Packet-Type'} = 'Access-Challenge';
  return RLM_MODULE_HANDLED;
}

sub issue_otp_challenge_prompt {
  $RAD_REPLY{'State'} = CHALLENGE_STATE_OTP;
  $RAD_REPLY{'Reply-Message'} = $config->{'prompts'}{'otp_challenge'} . " " . $config->{'prompts'}{'self_reset'};
  $RAD_CHECK{'Response-Packet-Type'} = 'Access-Challenge';
  return RLM_MODULE_HANDLED;
}

sub issue_name_terminal_challenge_prompt {
  my ($terminal_identifier) = @_;
  $RAD_REPLY{'State'} = CHALLENGE_STATE_TERMINAL . unpack("H*", $terminal_identifier);
  $RAD_REPLY{'Prompt'} = 'Echo';
  $RAD_REPLY{'Reply-Message'} = $config->{'prompts'}{'name_terminal_challenge'};
  $RAD_CHECK{'Response-Packet-Type'} = 'Access-Challenge';
  return RLM_MODULE_HANDLED;
}

sub poll_for_auth {
  my ($auth) = @_;
  _log('poll_for_auth');
  my $start_time = time();
  while($auth->pending){
    sleep(1);
    try {
      _log('  getting status from Toopher API');
      $auth = $api->get_authentication_status($auth->id);
    } catch {
      return &fail('Error contacting the Toopher API: ' . $_);
    };
    if (time() - $start_time > $config->{'toopher_api'}{'poll_timeout'}){
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

sub pair_with_toopher {
  my ($pairingPhrase, $userName) = @_;
  my $pairing;
  try {
    $pairing = $api->pair($pairingPhrase, $userName);
  } catch {
    return &fail("Error while pairing: " . $_);
  };
  my $start_time = time();

  while($pairing->pending){
    sleep(1);
    try {
      $pairing = $api->get_pairing_status($pairing->id);
      if (time() - $start_time > $config->{'toopher_api'}{'poll_timeout'}){
        return &fail("Timeout while waiting for pairing completion");
      }
    } catch {
      return &fail("Error contacting the Toopher API: " . $_);
    };
  }
  if($pairing->enabled){
    return RLM_MODULE_OK;
  } else {
    return &fail("Pairing was not completed on mobile device");
  }
}

sub get_terminal_identifier
{
  my $terminal_identifier = "";
  my $username = $RAD_REQUEST{'User-Name'};
  foreach my $term_id_attr_name (@{$config->{'terminal_identifier'}}) {
    _log('adding terminal identifier attribute: ' . $term_id_attr_name);
    $terminal_identifier .= $RAD_REQUEST{$term_id_attr_name};
  }
  if (length $terminal_identifier) { 
    return sha256_base64($username . $terminal_identifier);
  } else {
    return '';
  }
}

# Zero-requester-storage authentication
sub authenticate_zrs {
  my ($terminal_identifier) = @_;
  my $username = $RAD_REQUEST{'User-Name'};
  if (length $terminal_identifier == 0) {
    $terminal_identifier = &get_terminal_identifier;
  }
  try {
    return &poll_for_auth($api->authenticate_by_user_name($username, $terminal_identifier));
  } catch {
    chomp();
    _log('Caught error on request: ' . $_);
    if ($_ eq ToopherAPI::ERROR_USER_DISABLED) {
      return RLM_MODULE_OK;
    } elsif ($_ eq ToopherAPI::ERROR_USER_UNKNOWN) {
      return &issue_pairing_challenge_prompt();
    } elsif ($_ eq ToopherAPI::ERROR_TERMINAL_UNKNOWN) {
      return &issue_name_terminal_challenge_prompt($terminal_identifier);
    } elsif ($_ eq ToopherAPI::ERROR_PAIRING_DEACTIVATED) {
      return &issue_pairing_challenge_prompt();
    } else {
      _log('unknown error: ' . $_);
      return &fail('Unknown error while authenticating: ' . $_);
    }
  };    
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
    return &pair_with_toopher($pairing_phrase, $username);
  } catch {
    return &fail('Error while pairing with ToopherAPI: ' . $_);
  };
}

sub handle_pairing_reset_request
{
  _log('handle_pairing_reset_request');
  my $username = $RAD_REQUEST{'User-Name'};
  my $resetEmail = $RAD_CHECK{'Toopher-Reset-Email'};
  try {
    my $result = $api->send_pairing_reset_email($username, $resetEmail);
    my $resultText = $config->{'prompts'}{'reset_link_sent'};
    $resultText =~ s/\%email\%/$resetEmail/;
    return &fail($resultText);
  } catch {
    _log('Error while sending reset email: ' . $_);
    return &fail('Failed to send Toopher Pairing Reset Email.  Please contact your administrator.');
  }
}
sub handle_otp_challenge_reply
{
  _log('handle_otp_challenge_reply');
  my $username = $RAD_REQUEST{'User-Name'};
  my $otp = $RAD_REQUEST{'User-Password'};
  if ($otp =~ /^reset$/i) {
    return &handle_pairing_reset_request();
  } else {
    try {
      my $auth = $api->authenticate_by_user_name($username, '', '', { otp => $otp });
      if ($auth->granted) {
        return RLM_MODULE_OK;
      } else {
        $RAD_REPLY{'Reply-Message'} = $auth->reason;
        _log(Dumper($auth));
        return RLM_MODULE_REJECT;
      }
    } catch {
      _log('Error while submitting OTP: ' . $_);
      return fail('Failed to authenticate with the Toopher API');
    }
  }
}

sub handle_name_terminal_challenge_reply
{
  my ($terminal_identifier) = @_;
  _log('handle_name_terminal_challenge_reply: terminal_id = ' . $terminal_identifier);
  my $username = $RAD_REQUEST{'User-Name'};
  my $terminal_name = $RAD_REQUEST{'User-Password'};
  try {
    $api->create_user_terminal($username, $terminal_name, $terminal_identifier);
    return &authenticate_zrs($terminal_identifier);
  } catch {
    _log('Error while naming user terminal: ' . $_);
    return fail('Failed to name user terminal');
  }
}

sub do_authentication_state_machine
{
  my ($authentication_func, $pairing_func, $otp_func, $name_terminal_func) = @_;
  _log('do_authentication_state_machine');
  foreach my $foo (qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK %RAD_CONFIG)) {
    _log('  ' . $foo);
    my %hsh = eval($foo);
    foreach my $k (keys %hsh) {
      if ($k =~ /password/i){
        _log('    ' . $k . ' -> ************');
      } else {
        _log('    ' . $k . ' -> ' . $hsh{$k});
      }
    }
  }
  _log("-----------");
  my $state = 'init';
  if($RAD_REQUEST{'State'}){
    $state = $RAD_REQUEST{'State'};
    $RAD_REQUEST{'State'} = 'init';
  }
  my $result;
  if($state eq 'init'){
    $result = $authentication_func->();
  } elsif($state =~ CHALLENGE_STATE_PAIR){
    _log('  CHALLENGE_STATE_PAIR');
    $result = $pairing_func->();
  } elsif($state =~ CHALLENGE_STATE_OTP){
    _log('  CHALLENGE_STATE_OTP');
    $result = $otp_func->();
  } elsif($state =~ CHALLENGE_STATE_TERMINAL){
    _log('  CHALLENGE_STATE_TERMINAL');
    my $term_id_unpacked = substr($state, length(CHALLENGE_STATE_TERMINAL));
    my $terminal_identifier = pack("H*", $term_id_unpacked);
    _log('    terminal_identifier = ' . $terminal_identifier);
    $result = $name_terminal_func->($terminal_identifier);
  } else {
    $RAD_REPLY{'Reply-Message'} = 'unknown State message: ' . $state;
    $RAD_REPLY{'State'} = 'init';
    $result = RLM_MODULE_REJECT;
  }
  _log('RAD_REPLY:');
  for my $k (keys %RAD_REPLY) {
    _log("  $k : " . $RAD_REPLY{$k});
  }
  return $result;
}

sub authenticate_zrs_entry {
  _log('authenticate_zrs_entry');
  return do_authentication_state_machine(\&authenticate_zrs, \&handle_pairing_challenge_reply, \&handle_otp_challenge_reply, \&handle_name_terminal_challenge_reply);
}

sub unittest_toopher_rlm_perl
{
  my ($ua) = @_;
  my $userName = 'user@example.com';
  my $passwd = 'password';
  my $pairingPhrase = 'awkward turtle';
  my $terminalIdentifier = 'abcd1234';
  my $terminalName = 'my terminal';

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

  #missing terminal name
  $RAD_REQUEST{'User-Name'} = $userName;
  $RAD_REQUEST{'User-Password'} = $passwd;
  $config->{'terminal_identifier'} = ['Some-Random-Key'];
  $RAD_REQUEST{'Some-Random-Key'} = $terminalIdentifier;
  delete $RAD_REQUEST{'State'};

  $ua->response->code(409);
  $ua->response->content('{"error_code":706, "error_message":"No matching terminal exists."}');
  croak("Didn't return RLM_MODULE_HANDLED") unless authenticate_zrs_entry() == RLM_MODULE_HANDLED;
  croak("didn't get radius challenge") unless $RAD_REPLY{'State'} eq CHALLENGE_STATE_TERMINAL;
  croak("didn't get correct channenge") unless $RAD_REPLY{'Reply-Message'} eq $config->{'prompts'}{'name_terminal_challenge'};
  croak("wrong packet type") unless $RAD_CHECK{'Response-Packet-Type'} eq 'Access-Challenge';
  
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
  _log('running unittests');
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
} elsif($ARGV[0] eq 'reset-pairing') {
  my $user_name = $ARGV[1];
  if (not $user_name) {
    print "*****************************\n";
    print "**  Toopher Pairing Reset  **\n";
    print "*****************************\n";
    print "\nUsername to Reset > ";
    $user_name = <STDIN>;
    chomp($user_name);
  }
  die ("Usage: $0 reset-pairing [username]\n") unless $user_name;
  try {
    instantiate_toopher_api();
    $api->deactivate_pairings_for_username($user_name);
    print("OK\n");
  } catch {
    die("Error while resetting user pairing: $_\n");
  };
} else {
  instantiate_toopher_api();
}

1;
