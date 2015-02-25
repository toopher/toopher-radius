cd %~dp0
call test_config.cmd
if ERRORLEVEL 1 goto :eof
set WORKING_DIR=%~dp0
nssm install toopher-freeradius "%WORKING_DIR%run_toopher_radius.cmd"
net start toopher-freeradius
