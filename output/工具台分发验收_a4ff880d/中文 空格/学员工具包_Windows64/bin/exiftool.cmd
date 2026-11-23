@echo off
"%~dp0..\tools\exiftool\exiftool.exe" %*
@exit /b %errorlevel%
