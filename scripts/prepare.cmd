@echo off
rem Read-only prepare from the command line, e.g.:  prepare.cmd saferoute
cd /d "%~dp0.."
py -3 -m publisher --config "%LOCALAPPDATA%\GitHubPublisher\publisher.json" prepare %1
pause
