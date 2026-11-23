@echo off
"%~dp0..\tools\busybox\busybox.exe" sha256sum %*
@exit /b %errorlevel%
