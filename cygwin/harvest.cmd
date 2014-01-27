@echo off

rem first, remove a few files that we don't want to harvest
del toopher-RADIUS-build\etc\raddb\clients.conf
del toopher-RADIUS-build\etc\raddb\modules\files
del toopher-RADIUS-build\etc\raddb\modules\ldap
del toopher-RADIUS-build\etc\raddb\modules\perl

rem now, build the file list
heat dir toopher-RADIUS-build -nologo -dr INSTALLDIR -cg ServerFiles -gg -srd -sfrag -indent 2 -var wix.ServerFiles -out serverfiles.wxs