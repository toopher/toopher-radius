@echo off
echo *******************************************
echo ** DEBUG MODE - NOT FOR PRODUCTION USE!  **
echo *******************************************
echo.
echo You are about to start the Toopher-RADIUS server in DEBUG mode, which will
echo cause a large amount of information to be logged to the console, including
echo low-level RADIUS protocol information.  Because most RADIUS clients use a
echo plaintext authentication mechanism, this is a potential security risk.
echo.
echo POTENTIALLY SENSITIVE INFORMATION, INCLUDING USER PASSWORDS, MAY BE DISPLAYED
echo ON THE CONSOLE WHEN RUNNING THIS SCRIPT.  THIS SCRIPT SHOULD NOT BE RUN IN A
echo PRODUCTION ENVIRONMENT.
echo.
echo Press [Enter] to continue starting the server, or [Ctrl-C] to abort
pause

cd %~dp0
set CYGWIN=nodosfilewarning
call test_config.cmd
if ERRORLEVEL 1 goto :eof
set PERL_LWP_SSL_CA_FILE=%~dp0\etc\raddb\Mozilla\CA\cacert.pem
cd sbin
radiusd.exe -f -d ../etc/raddb -Xxx
