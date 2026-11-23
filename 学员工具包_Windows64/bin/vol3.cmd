@echo off
"%~dp0..\runtime\python\python.exe" "%~dp0..\tools\volatility3\vol.py" -p "%~dp0..\tools\volatility3_extra" %*
@exit /b %errorlevel%
