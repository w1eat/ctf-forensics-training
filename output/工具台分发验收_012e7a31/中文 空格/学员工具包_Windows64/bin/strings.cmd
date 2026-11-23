@echo off
"%~dp0..\tools\busybox\busybox.exe" strings %*
@exit /b %errorlevel%
