@echo off
"%~dp0..\runtime\ruby\bin\ruby.exe" "%~dp0..\runtime\ruby\bin\zsteg" --no-file %*
@exit /b %errorlevel%
