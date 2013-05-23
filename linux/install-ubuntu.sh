#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi


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
