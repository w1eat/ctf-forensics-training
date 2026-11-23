@echo off
"%~dp0..\tools\imdisk\cli\amd64\imdisk.exe" %*
@exit /b %errorlevel%
