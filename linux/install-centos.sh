#!/bin/bash
# vim: ts=2:sts=2:expandtab:sw=2

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

RADDB_DIR=/etc/raddb

ARCH=`uname -m`

#dpkg-query -l build-essential 2>&1 | grep -q 'No packages found'
#if [ $? -eq 0 ]; then
#  echo "Please install the build-essential package before executing this script"
#  exit 1
#fi

TEMP_DIR=`mktemp -d`
echo Created temporary directory at $TEMP_DIR
mkdir $TEMP_DIR/raddb
mkdir $TEMP_DIR/raddb/modules
mkdir $TEMP_DIR/raddb/sites-available

echo installing development tools if necessary
yum -y groupinstall 'Development Tools'

echo Installing/Updating CPAN modules.  Some modules might take several attempts.
# install needed CPAN modules.  This can still fail for unknown reasons, so
# grep for failure messages and retry for each module
#apt-get -y install libwww-perl
#apt-get -y install libcrypt-ssleay-perl
CPAN_MODULES=( Net::OAuth::ConsumerRequest JSON::XS JSON LWP::Protocol::https Try::Tiny URL::Encode URI::Escape Digest::SHA )

for module in "${CPAN_MODULES[@]}"
do
  counter=0
  mod_install_success=0
  while [ $mod_install_success -eq 0 ]
  do
    let counter=counter+1
    echo Installing $module \(attempt ${counter}\)
    ./cpanm $module 2>&1 | grep 'Bailing out the installation'
    mod_install_success=$?
  done
done


echo "Uninstalling existing freeradius packages"
rpm -qa freeradius\* | xargs rpm -e --nodeps

if [ -e $RADDB_DIR/toopher_radius_config.pm ]; then
  echo backing up existing configuration to $TEMP_DIR/oldconfig.tgz
  tar czvf $TEMP_DIR/oldconfig.tgz /etc/freeradius
  perl prep-config-files.pl $TEMP_DIR/raddb ../freeradius/etc/raddb $RADDB_DIR
else
  perl prep-config-files.pl $TEMP_DIR/raddb ../freeradius/etc/raddb
fi

# remove old auth script (renamed to toopher_radius.pl)
if [ -e $RADDB_DIR/do_toopher_auth.pl ]; then
  rm $RADDB_DIR/do_toopher_auth.pl
fi

echo installing freeradius packages and dependencies.
yum -y --nogpgcheck localinstall centos/freeradius*${ARCH}.rpm

service radiusd stop

echo Copying Toopher Freeradius confg files
for f in ToopherAPI.pm toopher_users dictionary.toopher toopher_radius.pl toopher_radius_config.pm modules/files modules/perl modules/ldap sites-available/default
do
  cp $TEMP_DIR/raddb/$f $RADDB_DIR/$f
done
for f in ToopherAPI.pm toopher_users dictionary.toopher toopher_radius.pl toopher_radius_config.pm modules/files modules/perl modules/ldap sites-available/default
do
  chown root:radiusd $RADDB_DIR/$f
  chmod 644 $RADDB_DIR/$f
done

chmod 744 $RADDB_DIR/toopher_radius.pl

echo Disabling EAP in radiusd.conf
sed -i '/^\s*\$INCLUDE eap.conf/s/^/#/' $RADDB_DIR/radiusd.conf

echo Removing inner-tunnel config
unlink $RADDB_DIR/sites-enabled/inner-tunnel

echo \$INCLUDE dictionary.toopher >> $RADDB_DIR/dictionary

echo Removing $TEMP_DIR
rm -fr $TEMP_DIR

service radiusd start
