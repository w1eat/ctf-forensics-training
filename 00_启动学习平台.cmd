@echo off
chcp 65001 >nul
setlocal DisableDelayedExpansion
set "CTF_FORENSICS_MODE=full"
set "CTF_BOOTSTRAP=%~dp0tools\bootstrap.ps1"
if not exist "%CTF_BOOTSTRAP%" for /d %%D in ("%~dp0*") do if exist "%%~fD\tools\bootstrap.ps1" set "CTF_BOOTSTRAP=%%~fD\tools\bootstrap.ps1"
if exist "%CTF_BOOTSTRAP%" (
  "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%CTF_BOOTSTRAP%" -Mode Launch -WorkspaceRoot "%~dp0." -NoLaunch -NoBrowser -NonInteractive
  if errorlevel 20 exit /b 20
  if errorlevel 10 set "CTF_FORENSICS_MODE=basic"
)
set "CTF_PLATFORM_PY="
if exist "%~dp0runtime\python\python.exe" set "CTF_PLATFORM_PY=%~dp0runtime\python\python.exe"
if not defined CTF_PLATFORM_PY for /d %%D in ("%~dp0*") do if exist "%%~fD\runtime\python\python.exe" set "CTF_PLATFORM_PY=%%~fD\runtime\python\python.exe"
if not defined CTF_PLATFORM_PY (
  echo This package does not include the Windows runtime. Use the complete Windows toolkit.
  pause
  exit /b 20
)
set "CTF_PLATFORM_SERVER=%~dp0tools\learning_server.py"
if not exist "%CTF_PLATFORM_SERVER%" for /d %%D in ("%~dp0*") do if exist "%%~fD\learning_server.py" set "CTF_PLATFORM_SERVER=%%~fD\learning_server.py"
if not exist "%CTF_PLATFORM_SERVER%" (
  echo Missing learning_server.py. Extract the complete package first.
  pause
  exit /b 1
)
"%CTF_PLATFORM_PY%" "%CTF_PLATFORM_SERVER%" --root "%~dp0." %*
if errorlevel 1 pause
