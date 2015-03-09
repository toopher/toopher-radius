#!/bin/bash
# vim: ts=2:sts=2:expandtab:sw=2

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

# architecture / distro detection
ARCH=`uname -m`

which yum && PACKAGE_FORMAT=rpm
which apt-get && PACKAGE_FORMAT=deb

if [ "$PACKAGE_FORMAT" = "rpm" ]
then
  echo "rpm installer detected"
  RADDB_DIR=/etc/raddb
  RADIUS_USER=radiusd
  RADIUS_SERVICE=radiusd
elif [ "$PACKAGE_FORMAT" = "deb" ]
then
  echo "deb installer detected"
  RADDB_DIR=/etc/freeradius
  RADIUS_USER=freerad
  RADIUS_SERVICE=freeradius
  if [ ${ARCH} == 'x86_64' ]
  then
    DPKG_ARCH=amd64
  else
    DPKG_ARCH=i386
  fi
else
  echo "Error: unsupported distribution.  Toopher-RADIUS supports CentOS 6+ and Ubuntu 12.04 LTS"
  exit 1
fi


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
if [ "$PACKAGE_FORMAT" = "rpm" ]
then
  yum -y groupinstall 'Development Tools'
elif [ "$PACKAGE_FORMAT" = "deb" ]
then
  apt-get -y install build-essential
  apt-get -y install libwww-perl
  apt-get -y install libcrypt-ssleay-perl
fi

echo Installing/Updating CPAN modules.  Some modules might take several attempts.
# install needed CPAN modules.  This can still fail for unknown reasons, so
# grep for failure messages and retry for each module
CPAN_MODULES=( Net::OAuth::ConsumerRequest JSON::XS JSON LWP::Protocol::https Try::Tiny URL::Encode URI::Escape Digest::SHA Term::ReadPassword Authen::Radius )

for module in "${CPAN_MODULES[@]}"
do
  if [ "$module" = "Term::ReadPassword" ]
  then
    ./cpanm --notest $module 2>&1
  else
    ./cpanm $module 2>&1
  fi
done

CONFIG_FILES=( clients.conf ToopherAPI.pm toopher_users dictionary.toopher toopher_radius.pl toopher_radius_config.pm modules/files modules/perl modules/ldap sites-available/default ldap.attrmap pap_challenge_request.pl )

if [ -e $RADDB_DIR/toopher_radius_config.pm ]; then
  cp $RADDB_DIR/clients.conf $TEMP_DIR/raddb/clients.conf
  perl prep-config-files.pl $TEMP_DIR/raddb ../freeradius/etc/raddb $RADDB_DIR
else
  perl prep-config-files.pl $TEMP_DIR/raddb ../freeradius/etc/raddb
fi

# remove old auth script if present (renamed to toopher_radius.pl)
if [ -e $RADDB_DIR/do_toopher_auth.pl ]; then
  rm $RADDB_DIR/do_toopher_auth.pl
fi

echo "Uninstalling existing freeradius packages"
if [ "$PACKAGE_FORMAT" = "rpm" ]
then
  rpm -qa freeradius\* | xargs rpm -e --nodeps
elif [ "$PACKAGE_FORMAT" = "deb" ]
then
    apt-get -y remove freeradius
    apt-get -y remove libfreeradius2
    apt-get -y remove freeradius-common
    apt-get -y autoremove
fi


echo installing freeradius packages and dependencies.
if [ "$PACKAGE_FORMAT" = "rpm" ]
then
  yum -y --nogpgcheck localinstall centos/freeradius*${ARCH}.rpm
elif [ "$PACKAGE_FORMAT" = "deb" ]
then
  dpkg -i deb/*freeradius*_all.deb deb/*freeradius*${DPKG_ARCH}.deb
  echo installing unmet dependencies
  apt-get -f -y install
fi

service ${RADIUS_SERVICE} stop

echo Copying Toopher Freeradius confg files
for f in "${CONFIG_FILES[@]}"
do
  cp $TEMP_DIR/raddb/$f $RADDB_DIR/$f
  chown root:${RADIUS_USER} $RADDB_DIR/$f
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

service ${RADIUS_SERVICE} start
