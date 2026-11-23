@echo off
"%~dp0..\tools\busybox\busybox.exe" base64 %*
@exit /b %errorlevel%
