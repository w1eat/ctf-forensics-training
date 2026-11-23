@echo off
"%~dp0..\tools\sqlite\sqlite3.exe" %*
@exit /b %errorlevel%
