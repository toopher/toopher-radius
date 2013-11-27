#!/bin/bash
# vim: ts=2:sts=2:expandtab:sw=2

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

ARCH=`uname -m`
if [ ${ARCH} == 'x86_64' ]; then
  DPKG_ARCH=amd64
else
  DPKG_ARCH=i386
fi

dpkg-query -l build-essential 2>&1 | grep -q 'No packages found'
if [ $? -eq 0 ]; then
  echo "Please install the build-essential package before executing this script"
  exit 1
fi

TEMP_DIR=`mktemp -d`
echo Created temporary directory at $TEMP_DIR
mkdir $TEMP_DIR/raddb
mkdir $TEMP_DIR/raddb/modules
mkdir $TEMP_DIR/raddb/sites-available

dpkg-query -l freeradius 2>&1 | grep -q 'No packages found'
if [ $? -ne 0 ]; then
  echo "Uninstalling existing freeradius packages"
  apt-get -y remove freeradius
  apt-get -y remove libfreeradius2
fi

if [ -e /etc/freeradius/toopher_radius_config.pm ]; then
  echo backing up existing configuration to $TEMP_DIR/oldconfig.tgz
  tar czvf $TEMP_DIR/oldconfig.tgz /etc/freeradius
  perl prep-config-files.pl $TEMP_DIR/raddb ../freeradius/etc/raddb  /etc/freeradius
else
  perl prep-config-files.pl $TEMP_DIR/raddb ../freeradius/etc/raddb
fi

# remove old auth script (renamed to toopher_radius.pl)
if [ -e /etc/freeradius/do_toopher_auth.pl ]; then
  rm /etc/freeradius/do_toopher_auth.pl
fi

echo 
echo installing freeradius...
dpkg -i deb/freeradius-common*.deb deb/*freeradius*${DPKG_ARCH}.deb
echo installing unmet dependencies
apt-get -f -y install

service freeradius stop

echo Copying Toopher Freeradius confg files
for f in ToopherAPI.pm toopher_users dictionary.toopher toopher_radius.pl toopher_radius_config.pm modules/files modules/perl modules/ldap sites-available/default
do
  cp $TEMP_DIR/raddb/$f /etc/freeradius/$f
done
for f in ToopherAPI.pm toopher_users dictionary.toopher toopher_radius.pl toopher_radius_config.pm modules/files modules/perl modules/ldap sites-available/default
do
  chown root:freerad /etc/freeradius/$f
  chmod 644 /etc/freeradius/$f
done

echo \$INCLUDE dictionary.toopher >> /etc/freeradius/dictionary

apt-get -y install libwww-perl
apt-get -y install libcrypt-ssleay-perl
echo Installing/Updating CPAN modules.  Some modules might take several attempts.
# install needed CPAN modules.  This can still fail for unknown reasons, so
# grep for failure messages and retry for each module
CPAN_MODULES=( Net::OAuth::ConsumerRequest JSON::XS JSON LWP::Protocol::https Try::Tiny URL::Encode URI::Escape )

# make sure cpan is configured first
echo exit | cpan
for module in "${CPAN_MODULES[@]}"
do
  counter=0
  mod_install_success=0
  while [ $mod_install_success -eq 0 ]
  do
    let counter=counter+1
    echo Installing $module \(attempt ${counter}\)
    yes | cpan $module 2>&1 | grep 'fatal error'
    mod_install_success=$?
  done
done

echo Removing $TEMP_DIR
rm -fr $TEMP_DIR

service freeradius start
