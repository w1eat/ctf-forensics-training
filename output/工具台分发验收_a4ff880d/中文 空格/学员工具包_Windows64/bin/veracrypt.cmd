@echo off
"%~dp0..\tools\veracrypt\VeraCrypt.exe" %*
@exit /b %errorlevel%
