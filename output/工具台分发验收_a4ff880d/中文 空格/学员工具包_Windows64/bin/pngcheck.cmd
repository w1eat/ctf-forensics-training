@echo off
"%~dp0..\tools\pngcheck\pngcheck.exe" %*
@exit /b %errorlevel%
