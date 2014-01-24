call test_config.cmd
if ERRORLEVEL 1 goto :eof
nssm install toopher-freeradius %~dp0\run_toopher_radius.cmd
net start toopher-freeradius