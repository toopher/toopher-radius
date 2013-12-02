#!/usr/bin/perl

use Data::Dumper;
use Try::Tiny;
my @TEMPLATED_FILES = ("modules/files", "modules/ldap", "modules/perl", "sites-available/default", "toopher_radius_config.pm", "toopher_radius.pl", "toopher_users", "dictionary.toopher", "ToopherAPI.pm");
my $outputDir;
my $inputDir;
my $raddb;

BEGIN {
  $outputDir = $ARGV[0];
  $inputDir = $ARGV[1];
  $raddb = $ARGV[2];

  if ($raddb) {
    print 'raddb is ' . $raddb;
    require "$raddb/toopher_radius_config.pm";
  }
}


die ("Usage: prep-config-files.pl <outputDir> <inputDir> [raddbDir]\n") unless ($outputDir and $inputDir);
print "using radius library at $raddb\n" if $raddb;


# extracts existing Toopher-RADIUS setup into
# common config file format that can be
# applied to a new install

# configuration items are stored in this hashref
my $toopherConfiguration = {};

sub parse_module_conf
{
  my ($fName) = @_;
  my $lineNumber = 0;
  my $confNode = {};
  my @stack = [];
  open(my $fh, "<", $fName) or die "Unable to open $fName\n";
  while(my $line = <$fh>) {
    $lineNumber++;
    $line =~ s/^\s+|\s+$//g;  # strip whitespace
    #print "$lineNumber : $line\n";
    next unless $line; # skip blank lines
    next if ($line =~ /^#/); # skip comments
    if ($line =~ /^(\w+)\s*=\s*(.*?)$/){
      # normal name=value line
      my $name = $1;
      my $value = $2;
      if ($value =~ /^"(.*)"$/){
        $value = $1;
      }
      $confNode->{$name} = $value;
    } elsif ($line =~ /^(\w+)\s*\{$/) {
      # start new sub-node
      push @stack, $1;
      push @stack, $confNode;
      $confNode = {};
    } elsif ($line =~ /^\}$/) {
      # close sub-node
      my $subNode = $confNode;
      $confNode = pop @stack;
      $confNode->{pop @stack} = $subNode; 
    } else {
      # parser error
      close $fh;
      die "Module conf parser error: $fName line $lineNumber\n\t$line\n";
    }
  }
  close $fh;
  if ($stack) {
    die "Unclosed sub-node in $fName\n";
  }
  return $confNode;
}

sub extract_users_file_entries
{
  my ($fName) = @_;
  open(my $fh, "<", $fName) or die "Unable to open $fName\n";
  my $keep = 0;
  my $result = '';
  while(my $line = <$fh>) {
    if ($keep) {
      $result .= $line;
    }
    if ($line =~ /^# MAKE EDITS BELOW THIS LINE./) {
      $keep = 1;
    }
  }
  close $fh;
  return $result;
}

sub update
{
  my ($dest, $destKey, $src, $srcKey) = @_;
  $dest->{$destKey} = $src->{$srcKey} if $src->{$srcKey};
}

# version 0 - pretty much everything is in toopher_radius_config.
# Assume Active Directory
sub fromVersion0
{
  my $config;
  eval {
    $config = toopher_radius_config::get_config;
  };
  $toopherConfiguration->{'TOOPHER_API_URL'} = $config->{'toopher_api'}{'url'};
  $toopherConfiguration->{'TOOPHER_API_KEY'} = $config->{'toopher_api'}{'key'};
  $toopherConfiguration->{'TOOPHER_API_SECRET'} = $config->{'toopher_api'}{'secret'};

  my $ldapUsername = $config->{'ldap'}{'username'};
  my $baseDn = 'cn=users,' . $config->{'ldap'}{'dc'};
  $toopherConfiguration->{'LDAP_IDENTITY'} = 'cn=' . $ldapUsername . ',' . $baseDn;
  $toopherConfiguration->{'LDAP_PASSWORD'} = $config->{'ldap'}{'password'};
  $toopherConfiguration->{'LDAP_HOST'} = $config->{'ldap'}{'host'};
  $toopherConfiguration->{'LDAP_BASEDN'} = $baseDn;

  $toopherConfiguration->{'PROMPT_PAIRING_CHALLENGE'} = $config->{'prompts'}{'pairing_challenge'};

  # because there was not a "DO NOT EDIT BELOW THIS LINE" marker in version0, cannot preserve users edits
}

sub fromVersion1
{
  my $config;
  eval {
    $config = toopher_radius_config::get_config;
  };
  $toopherConfiguration->{'TOOPHER_API_URL'} = $config->{'toopher_api'}{'url'};
  $toopherConfiguration->{'TOOPHER_API_KEY'} = $config->{'toopher_api'}{'key'};
  $toopherConfiguration->{'TOOPHER_API_SECRET'} = $config->{'toopher_api'}{'secret'};
  $toopherConfiguration->{'TOOPHER_POLL_TIMEOUT'} = $config->{'toopher_api'}{'poll_timeout'};

  $toopherConfiguration->{'PROMPT_PAIRING_CHALLENGE'} = $config->{'prompts'}{'pairing_challenge'};
  $toopherConfiguration->{'PROMPT_OTP_CHALLENGE'} = $config->{'prompts'}{'otp_challenge'};
  $Data::Dumper::Terse = 1;
  my $terminalIdentifier = '' . Dumper($config->{'terminal_identifier'});
  $Data::Dumper::Terse = 0;
  chomp $terminalIdentifier;
  $toopherConfiguration->{'TERMINAL_IDENTIFIER'} = $terminalIdentifier;

  my $ldapConf = parse_module_conf($raddb . '/modules/ldap')->{'ldap'};

  update($toopherConfiguration, 'LDAP_HOST', $ldapConf, 'server');
  update($toopherConfiguration, 'LDAP_PORT', $ldapConf, 'port');
  update($toopherConfiguration, 'LDAP_IDENTITY', $ldapConf, 'identity');
  update($toopherConfiguration, 'LDAP_PASSWORD', $ldapConf, 'password');
  update($toopherConfiguration, 'LDAP_BASEDN', $ldapConf, 'basedn');
  update($toopherConfiguration, 'LDAP_SEARCH_FILTER', $ldapConf, 'filter');
  update($toopherConfiguration, 'LDAP_GROUP_MEMBERSHIP_FILTER', $ldapConf, 'groupmembership_filter');

  $toopherConfiguration->{'EXISTING_USERS_FILE_ENTRIES'} = extract_users_file_entries("$raddb/toopher_users");
}

sub getInstalledVersion
{
  my $result = 0;
  eval {
    if (toopher_radius_config::VERSION) {
      $result = toopher_radius_config::VERSION;
    };
  };
  if ($@) {
    die "error: $@\n";
  }
  return '' . $result;
}

sub expand_templates
{
  my ($inputFile, $outputFile) = @_;
  open (my $ih, "<", $inputFile) or die "Couldn't open $inputFile for reading: $@\n";
  open (my $oh, ">", $outputFile) or die "Couldn't open $outputFile for writing: $@";
  while(my $line = <$ih>){
    if ($line =~ /^##!DEFAULT (\S+)\s+(.*?)\s*$/) {
      if (! (exists $toopherConfiguration->{$1})) {
        $toopherConfiguration->{$1} = $2;
      }
    } else {
      while($line =~ /\{\{\s*(\S+)\s*\}\}/){
        my $configItemName = $1;
        if (! (exists $toopherConfiguration->{$configItemName})) {
          die "Error: no template substitution value for $configItemName\n"
        }
        my $expandedVal = $toopherConfiguration->{$configItemName};
        $line =~ s/\{\{.*?\}\}/$expandedVal/;
      }
      print $oh $line;
    }
  }
  close $ih;
  close $oh;
}

my $versionParsers = {
  '0' => \&fromVersion0,
  '1' => \&fromVersion1,
};

if ($raddb) {
  my $installedVersion = getInstalledVersion();

  print "reading existing configuration...";
  if(exists $versionParsers->{$installedVersion}) {
    print "Installed version is " . $installedVersion . "\n";
    $versionParsers->{$installedVersion}();
  } else {
    print "Unable to determine installed version.  Assuming version 0\n";
    $versionParsers->{'0'}();
  }
  print " done.\n";
  print "Detected configuration : \n";
  foreach my $key (sort keys %{$toopherConfiguration}){
    print "  $key = " . $toopherConfiguration->{$key} . "\n";
  }
}

print "Expanding config file templates...\n";
foreach my $file (@TEMPLATED_FILES) {
  print "  $file\n";
  expand_templates("$inputDir/$file", "$outputDir/$file");
}

print "Done.  Toopher-RADIUS config files have been created in $outputDir\n"; 
