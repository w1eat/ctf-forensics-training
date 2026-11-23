@echo off
"%~dp0..\tools\7zip\7z.exe" %*
@exit /b %errorlevel%
