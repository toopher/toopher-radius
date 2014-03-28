#!/usr/bin/perl -w

# Thomas Glanzmann 16:06 2012-05-21
# First Argument is username, second argument is password
# Authen::Radius requires a legacy dictionary without advanced
# keywords like encrypted or $INCLUDEs

use strict;
use warnings FATAL => 'all';

use Term::ReadPassword;
use Authen::Radius;
use Data::Dumper;
use IO::Socket::INET;

use constant RADIUS_HOST => '127.0.0.1';
use constant RADIUS_SECRET => 'testing123';
use constant RADIUS_TIMEOUT => 70;
use constant CALLING_STATION_ID => 'detect';
use constant RADDB => '/etc/raddb';

# autoflush stdout
$| = 1;

sub get_local_ip_address {
  my $socket = IO::Socket::INET->new(
      Proto       => 'udp',
      PeerAddr    => '198.41.0.4', # a.root-servers.net
      PeerPort    => '53', # DNS
  );

  # A side-effect of making a socket connection is that our IP address
  # is available from the 'sockhost' method
  my $local_ip_address = $socket->sockhost;

  return $local_ip_address;
}

my $calling_station_id;
if (CALLING_STATION_ID eq 'detect') {
  $calling_station_id = get_local_ip_address();
} else {
  $calling_station_id = CALLING_STATION_ID;
}


my %response_codes = (
        1   =>   'Access-Request',
        2   =>   'Access-Accept',
        3   =>   'Access-Reject',
        4   =>   'Accounting-Request',
        5   =>   'Accounting-Response',
        11  =>   'Access-Challenge',
        12  =>   'Status-Server (experimental)',
        13  =>   'Status-Client (experimental)',
        255 =>   'Reserved',

);


my $username = $ARGV[0];
my $password = $ARGV[1];

unless (defined($username)) {
  print "Enter username: ";
  $username = <STDIN>;
  chomp($username);
}

unless (defined($password)) {
  $password = read_password('Enter password: ');
}

my $r = new Authen::Radius(Host => RADIUS_HOST, Secret => RADIUS_SECRET, Timeout=>RADIUS_TIMEOUT);
Authen::Radius->load_dictionary();
Authen::Radius->load_dictionary(RADDB . '/dictionary');

$r->add_attributes (
    { Name => 'User-Name', Value => $username },
    { Name => 'User-Password', Value => $password },
    { Name => 'Calling-Station-Id', Value => $calling_station_id },
);

$r->set_timeout(time() + RADIUS_TIMEOUT);
print "sending RADIUS request\n";
$r->send_packet(ACCESS_REQUEST)  || die;
my $type = $r->recv_packet() || die($r->get_error());

print "server response type = $response_codes{$type} ($type)\n";

my ($state, $replyMessage, $otp, $echoPrompt);

while($type == ACCESS_CHALLENGE){
  $state = undef;
  $replyMessage = "enter otp:";
  $echoPrompt = 0;

  for $a ($r->get_attributes()) {
    #print $a->{Name} . ' -> ' . $a->{RawValue} . "\n";
    if ($a->{Name} eq 'State') {
      $state = $a->{RawValue};
    } elsif ($a->{Name} eq 'Reply-Message') {
      $replyMessage = $a->{RawValue};
    } elsif ($a->{Name} eq 'Prompt') {
      $echoPrompt = $a->{RawValue};
    }
  }

  print $replyMessage . ' ';
  if ($echoPrompt) {
    $otp = <STDIN>;
  } else {
    $otp = read_password('');
  }
  chomp($otp);

  $r->add_attributes (
      { Name => 'User-Name', Value => $username },
      { Name => 'User-Password', Value => $otp },
  );

  $r->set_timeout(time() + 60);
  $r->send_packet(ACCESS_REQUEST)  || die;
  $type = $r->recv_packet() || die($r->get_error());
  print "server response type = $response_codes{$type} ($type)\n";
}

for $a ($r->get_attributes()) {
  print $a->{Name} . ' -> ' . $a->{RawValue} . "\n";
}

exit 1 unless $type == 2;
