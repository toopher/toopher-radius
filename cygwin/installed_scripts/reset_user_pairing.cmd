cd %~dp0
set CYGWIN=nodosfilewarning
set PERL_LWP_SSL_CA_FILE=%~dp0\etc\raddb\Mozilla\CA\cacert.pem
sbin\perl etc\raddb\toopher_radius.pl reset-pairing
