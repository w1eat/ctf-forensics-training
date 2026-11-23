@echo off
chcp 65001 >nul
setlocal DisableDelayedExpansion
set "CTF_SETUP_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "CTF_SETUP_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
set "CTF_SETUP_SCRIPT=%~dp0tools\bootstrap.ps1"
if not exist "%CTF_SETUP_SCRIPT%" for /d %%D in ("%~dp0*") do if exist "%%~fD\tools\bootstrap.ps1" set "CTF_SETUP_SCRIPT=%%~fD\tools\bootstrap.ps1"
if not exist "%CTF_SETUP_SCRIPT%" set "CTF_SETUP_SCRIPT=%~dp0bootstrap.ps1"
if not exist "%CTF_SETUP_SCRIPT%" (
  echo Missing bootstrap.ps1. Extract the complete Windows toolkit first.
  pause
  exit /b 20
)
"%CTF_SETUP_PS%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%CTF_SETUP_SCRIPT%" -Mode Repair -WorkspaceRoot "%~dp0." -NoLaunch %*
set "CTF_SETUP_EXIT=%errorlevel%"
pause
exit /b %CTF_SETUP_EXIT%
