@echo off
rem GitHub Publisher service (loopback only). Close this window or press Ctrl+C to stop.
cd /d "%~dp0.."
title GitHub Publisher
py -3 -m publisher --config "%LOCALAPPDATA%\GitHubPublisher\publisher.json" serve
pause
