@echo off
chcp 65001 >nul
"%~dp0runtime\python\python.exe" "%~dp0tools\serve_local.py"
pause
