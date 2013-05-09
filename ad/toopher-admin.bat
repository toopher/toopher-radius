@ECHO OFF
SetLocal

REM Set this to the name of your Toopher Administrators group
set TOOPHER_ADMIN_GROUP_NAME=ToopherAdministrators


set ADMIN_COMMAND=%1
set USERNAME=%2

if [%ADMIN_COMMAND%] == [enable] (
call :SET_TOOPHER_ENABLED TRUE
) else (
if [%ADMIN_COMMAND%] == [disable] (
call :SET_TOOPHER_ENABLED FALSE
) else (
if [%ADMIN_COMMAND%] == [reset-pairing] (
call :TOOPHER_RESET_PAIRING
) else (
if [%ADMIN_COMMAND%] == [show-users] (
call :SHOW_TOOPHER_USERS
) else (
call :USAGE
))))

EndLocal
GOTO END


REM subroutines
:USAGE
	echo toopher-admin.bat : Automate administration of Toopher User Attributes in Active Directory
	echo.
	echo USAGE: toopher-admin COMMAND UserName
	echo.
	echo Available Commands:
	echo   enable  [Username]       : Enable Toopher 2-factor authentication for
	echo                              a particular user when they log in.
	echo   disable [Username]       : Remove Toopher 2-factor authentication for
	echo                              a particular a user
	echo   reset-pairing [Username] : Remove the pairing between a user account
	echo                              and mobile device used for authentication.
	echo                              The user will be prompted to pair a new
	echo                              device the next time they log in unless you
	echo                              also run the "disable" command.
	echo   show-users               : list users who currently have 
	echo                              Toopher 2-factor authentication enabled
	goto :EOF
	
:GET_USER_AND_TOOPHER_ADMIN_DN
	IF [%USERNAME%] == [] call PROMPT_FOR_USERNAME
	REM get the FQDN for ToopherAdministrators and the user, as well as the Users container
	dsquery group -name %TOOPHER_ADMIN_GROUP_NAME% > toopher_temp.dn
	set /p TOOPHER_ADMINS_DN= < toopher_temp.dn
	set TOOPHER_ADMIN_GROUP_NAME=ToopherAdministrators
	dsquery user -samid %USERNAME% > toopher_temp.dn
	set /p USER_DN= < toopher_temp.dn
	del toopher_temp.dn
	goto :EOF
	
:REVOKE_TOOPHER_ADMIN_ACCESS_TO_USER
	REM Remove existing Toopher ACIs on the user
	dsacls %USER_DN% /R %TOOPHER_ADMINS% >NUL
	goto :EOF
:GRANT_TOOPHER_ADMIN_ACCESS_TO_USER
	REM revoke existing Toopher Admin ACIs to prevent duplicate rules
	call :REVOKE_TOOPHER_ADMIN_ACCESS_TO_USER
	echo   Grant %TOOPHER_ADMIN_GROUP_NAME% R/W Access to toopherAuthenticateLogon and toopherPairingId
	dsacls %USER_DN% /G %TOOPHER_ADMINS_DN%:WP;toopherAuthenticateLogon %TOOPHER_ADMINS_DN%:WP;toopherPairingID >NUL
	goto :EOF

:SHOW_TOOPHER_USERS
	dsquery * -filter "(toopherAuthenticateLogon=TRUE)" -attr displayName sAMAccountName toopherAuthenticateLogon toopherPairingID
	goto :EOF
	
:TOOPHER_RESET_PAIRING
	call :GET_USER_AND_TOOPHER_ADMIN_DN
	
	echo Resetting Toopher Pairing information for user %USERNAME%
    call :GRANT_TOOPHER_ADMIN_ACCESS_TO_USER
	echo   deleting attribute toopherPairingID
	
	call :unquote USER_DN_NOQUOTE %USER_DN%
	echo dn: %USER_DN_NOQUOTE%> toopher_temp.ldif
	echo changetype: modify>> toopher_temp.ldif
	echo delete: toopherPairingID>> toopher_temp.ldif
	echo ->> toopher_temp.ldif

	REM run ldifde
	ldifde -i -k -f toopher_temp.ldif >NUL
	del toopher_temp.ldif
	
	echo   DONE.
	echo If %USERNAME% has Toopher Authentication enabled, they will be prompted to re-pair their account with Toopher at next login.
	goto :EOF

:SET_TOOPHER_ENABLED
	set ENABLED=%1
	call :GET_USER_AND_TOOPHER_ADMIN_DN
	
    echo Toopher-enabling user %USERNAME%
	call :GRANT_TOOPHER_ADMIN_ACCESS_TO_USER
	echo   setting attribute toopherAuthenticateLogon: %ENABLED%
	
	call :unquote USER_DN_NOQUOTE %USER_DN%
	echo dn: %USER_DN_NOQUOTE%> toopher_temp.ldif
	echo changetype: modify>> toopher_temp.ldif
	echo add: toopherAuthenticateLogon>> toopher_temp.ldif
	echo toopherAuthenticateLogon: %ENABLED%>> toopher_temp.ldif
	echo ->> toopher_temp.ldif
	echo.>> toopher_temp.ldif
	echo dn: %USER_DN_NOQUOTE%>> toopher_temp.ldif
	echo changetype: modify>> toopher_temp.ldif
	echo replace: toopherAuthenticateLogon>> toopher_temp.ldif
	echo toopherAuthenticateLogon: %ENABLED%>> toopher_temp.ldif
	echo ->> toopher_temp.ldif

	REM run ldifde
	ldifde -i -k -f toopher_temp.ldif >NUL
	del toopher_temp.ldif
	
	echo   DONE.
	if [%ENABLED%] == [TRUE] echo If %USERNAME% has not paired a mobile device with their account, they will be prompted to do so on their next login.
	goto :EOF

:unquote
  set %1=%~2
  goto :EOF
  
:PROMPT_FOR_USERNAME
  set /p USERNAME="Toopher Admin> Please enter name of user to enable: "
  goto :EOF

:END



