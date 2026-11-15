@echo off
rem Prints the service token (NOT a GitHub credential) for the Open WebUI Tool valve.
cd /d "%~dp0.."
py -3 -m publisher --config "%LOCALAPPDATA%\GitHubPublisher\publisher.json" show-token
pause
