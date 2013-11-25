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

my $r = new Authen::Radius(Host => '127.0.0.1', Secret => 'testing123', Timeout=>60);
Authen::Radius->load_dictionary();
Authen::Radius->load_dictionary('/home/drew/dictionary');

$r->add_attributes (
                { Name => 'User-Name', Value => $username },
                { Name => 'User-Password', Value => $password },
);

$r->set_timeout(time() + 60);
$r->send_packet(ACCESS_REQUEST)  || die;
my $type = $r->recv_packet() || die($r->get_error());

print "server response type = $response_codes{$type} ($type)\n";

exit 1 unless $type == 11;

my $state = undef;
my $replyMessage = "enter otp:";

for $a ($r->get_attributes()) {
	print $a->{Name} . ' -> ' . $a->{RawValue} . "\n";
        if ($a->{Name} eq 'State') {
                $state = $a->{RawValue};
        } elsif ($a->{Name} eq 'Reply-Message') {
		$replyMessage = $a->{RawValue};
	}
}

print $replyMessage . ' ';
my $otp = <STDIN>;
chomp($otp);

$r->add_attributes (
                { Name => 'User-Name', Value => $username },
                { Name => 'User-Password', Value => $otp },
);

$r->set_timeout(time() + 60);
$r->send_packet(ACCESS_REQUEST)  || die;
$type = $r->recv_packet() || die($r->get_error());

print "server response type = $response_codes{$type} ($type)\n";

exit 1 unless $type == 2;
