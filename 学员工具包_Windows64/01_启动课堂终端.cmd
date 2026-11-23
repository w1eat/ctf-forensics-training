@echo off
chcp 65001 >nul
powershell.exe -NoLogo -NoProfile -NoExit -ExecutionPolicy Bypass -File "%~dp0env.ps1"
