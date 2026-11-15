@echo off
rem Stop only this user's GitHub Publisher service (not other Python processes).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0stop-publisher.ps1"
exit /b %ERRORLEVEL%
