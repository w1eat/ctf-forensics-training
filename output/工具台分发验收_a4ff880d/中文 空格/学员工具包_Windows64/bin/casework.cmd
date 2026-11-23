@echo off
"%~dp0..\runtime\python\python.exe" "%~dp0..\tools\casework.py" %*
@exit /b %errorlevel%
