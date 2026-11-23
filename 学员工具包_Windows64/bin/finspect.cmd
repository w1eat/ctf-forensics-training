@echo off
"%~dp0..\runtime\python\python.exe" "%~dp0..\tools\finspect.py" %*
@exit /b %errorlevel%
