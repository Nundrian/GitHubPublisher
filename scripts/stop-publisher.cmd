@echo off
rem Stops only the GitHub Publisher service process (matched by its command line).
powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name like py%%.exe or Name like python%%.exe\" | Where-Object { $_.CommandLine -match -m publisher .* serve } | ForEach-Object { Stop-Process -Id $_.ProcessId; Write-Host (Stopped PID  + $_.ProcessId) }"
