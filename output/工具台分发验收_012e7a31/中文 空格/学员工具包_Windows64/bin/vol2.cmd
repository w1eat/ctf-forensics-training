@echo off
setlocal DisableDelayedExpansion
set "PYTHONIOENCODING="
set "PYTHONUTF8="
"%~dp0..\tools\volatility2\windows\volatility_2.6_win64_standalone.exe" --plugins="%~dp0..\tools\volatility2\extra_plugins" --cache-directory=out/vol2_cache %*
@exit /b %errorlevel%
