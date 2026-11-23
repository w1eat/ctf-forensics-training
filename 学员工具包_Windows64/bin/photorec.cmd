@echo off
setlocal
set "__COMPAT_LAYER=RunAsInvoker"
"%~dp0..\tools\testdisk\photorec_win.exe" %*
@exit /b %errorlevel%
