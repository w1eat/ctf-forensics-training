@echo off
"%~dp0..\tools\busybox\busybox.exe" dd %*
@exit /b %errorlevel%
