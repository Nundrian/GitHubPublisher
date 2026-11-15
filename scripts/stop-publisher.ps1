# Stop this user's GitHub Publisher service, without affecting other Python processes.
# Matches the exact module, configuration path, and 'serve' command used by start-publisher.cmd.
$ErrorActionPreference = 'Stop'

if (-not $env:LOCALAPPDATA) {
    throw 'LOCALAPPDATA is not set; cannot identify this user''s publisher service.'
}

$configPath = Join-Path $env:LOCALAPPDATA 'GitHubPublisher\publisher.json'
$configPattern = '(?i)(?:^|\s)--config\s+"?' + [regex]::Escape($configPath) + '"?\s+serve\s*$'
$modulePattern = '(?i)(?:^|\s)-m\s+publisher(?=\s|$)'

$processes = Get-CimInstance Win32_Process -Filter "Name = 'python.exe' OR Name = 'pythonw.exe' OR Name = 'py.exe' OR Name = 'pyw.exe'"
$stopped = 0

foreach ($process in $processes) {
    $commandLine = [string]$process.CommandLine
    if ($commandLine -notmatch $modulePattern -or $commandLine -notmatch $configPattern) {
        continue
    }

    Stop-Process -Id $process.ProcessId -ErrorAction Stop
    Write-Output ("Stopped GitHub Publisher service (PID {0})." -f $process.ProcessId)
    $stopped++
}

if ($stopped -eq 0) {
    Write-Output 'No matching GitHub Publisher service process is running.'
}
