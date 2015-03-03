cd %~dp0
set CYGWIN=nodosfilewarning
call test_config.cmd
if ERRORLEVEL 1 goto :eof
set PERL_LWP_SSL_CA_FILE=%~dp0\etc\raddb\Mozilla\CA\cacert.pem
cd sbin
radiusd.exe -f -d ../etc/raddb -l ../var/log/radius/radius.log
