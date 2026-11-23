@echo off
"%~dp0..\tools\busybox\busybox.exe" xxd %*
@exit /b %errorlevel%
