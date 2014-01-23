set PERL_LWP_SSL_CA_FILE=%~dp0\etc\raddb\Mozilla\CA\cacert.pem
set CYGWIN=nodosfilewarning
cd sbin
radiusd.exe -f -d ../etc/raddb -l ../var/log/radius/radius.log
