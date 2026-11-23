@echo off
chcp 65001 >nul
set LANG=C
set LC_ALL=C
set PYTHONUTF8=1
"%~dp0runtime\python\python.exe" "%~dp0tools\check_environment.py"
pause
