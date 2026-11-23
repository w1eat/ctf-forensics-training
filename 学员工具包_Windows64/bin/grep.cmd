@echo off
"%~dp0..\tools\busybox\busybox.exe" grep %*
@exit /b %errorlevel%
