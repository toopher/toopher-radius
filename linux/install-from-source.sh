#!/bin/bash

#if [[ $EUID -ne 0 ]]; then
#   echo "This script must be run as root" 
#   exit 1
#fi


FREERADIUS_VERSION=2.2.0
FREERADIUS_PREFIX=/usr

BUILD_DIR=`pwd`

FREERADIUS_SRC=freeradius-server-${FREERADIUS_VERSION}
FREERADIUS_SRC_TARBALL=freeradius-server-${FREERADIUS_VERSION}.tar.gz
FREERADIUS_CONFIGURE_ARGUMENTS="--prefix=${FREERADIUS_PREFIX} --disable-static --with-rlm_perl"

fatal() {
   printf -- "\nFATAL: %s\n\n" "$*" >&2
   exit 1
}

verbose() {
   printf -- "%s\n" "$*"
}

verblock() {
   verbose
   verbose "***"
   while read line; do
      verbose "*** $line"
   done
   verbose "***"
   verbose
}


wget ftp://ftp.freeradius.org/pub/freeradius/${FREERADIUS_SRC_TARBALL} || fatal "Unable to download FreeRadus source"
tar xzvf ${FREERADIUS_SRC_TARBALL} || fatal "Unable to decompress FreeRadius source"
rm ${FREERADIUS_SRC_TARBALL}

cd ${FREERADIUS_SRC}
./configure ${FREERADIUS_CONFIGURE_ARGUMENTS} 2>&1 | tee freerad.config.output
grep -q 'not building rlm_perl' freerad.config.output
if [ $? -eq 0 ]
then
  verblock <<EOF
Error: the freeradius rlm_perl module cannot be built.  Please ensure
that perl is available on your system, and libperl.so is installed.

In Ubuntu, you can run "apt-get install libperl-dev" to satisfy this.
EOF
  fatal 'rlm_perl not available'
fi
rm freerad.config.output

exit
fakeroot dpkg-buildpackage -b -uc
#make || fatal "Failed to build freeradius."

#make install || fatal "Failed to install freeradius."
cd ${BUILD_DIR}

cp -rf ../freeradius/* ${FREERADIUS_PREFIX}/ || fatal "Couldn't install toopher-freeradius configuration files"
echo \$INCLUDE dictionary.toopher >> ${FREERADIUS_PREFIX}/etc/raddb/dictionary


echo Changing ownership of /etc/raddb and /share/freeradius to freerad
chown -R freerad:freerad ${FREERADIUS_PREFIX}/etc/raddb/*
chown -R freerad:freerad ${FREERADIUS_PREFIX}/share/freeradius/*

# unlink inner-tunnel and control-socket sites
unlink ${FREERADIUS_PREFIX}/etc/raddb/sites-enabled/inner-tunnel
unlink ${FREERADIUS_PREFIX}/etc/raddb/sites-enabled/control-socket

#clean up after ourselves
#rm -fr ${FREERADIUS_SRC}
