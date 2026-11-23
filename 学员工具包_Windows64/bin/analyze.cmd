@echo off
"%~dp0..\runtime\python\python.exe" "%~dp0..\tools\analysis_engine.py" %*
@exit /b %errorlevel%
