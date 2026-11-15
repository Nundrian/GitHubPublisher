# GitHub Publisher - one-time setup for the current Windows user (no admin rights, no PATH changes).
# Run from the app folder:  powershell -ExecutionPolicy Bypass -File scripts\install.ps1
# Safe to re-run: existing config and token are kept.
[CmdletBinding()]
param(
    [string]$DataDir = "$env:LOCALAPPDATA\GitHubPublisher",
    [string]$GitleaksVersion = '8.30.0'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$App = Split-Path -Parent $PSScriptRoot

function Find-Exe([string]$name, [string[]]$candidates) {
    foreach ($c in $candidates) { if ($c -and (Test-Path -LiteralPath $c)) { return (Resolve-Path -LiteralPath $c).Path } }
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

Write-Host "GitHub Publisher setup" -ForegroundColor Cyan
$py = Find-Exe 'py.exe' @("$env:WINDIR\py.exe", "$env:LOCALAPPDATA\Programs\Python\Launcher\py.exe")
if (-not $py) { throw "Python launcher (py.exe) not found. Install Python 3.10+ from python.org." }
& $py -3 -c "import sys; assert sys.version_info >= (3, 10), sys.version; print('Python', sys.version.split()[0])"
if ($LASTEXITCODE -ne 0) { throw "Python 3.10 or newer is required." }

$git = Find-Exe 'git.exe' @("$env:ProgramFiles\Git\cmd\git.exe")
if (-not $git) { throw "Git for Windows not found. Install it from https://git-scm.com/download/win" }
Write-Host "git: $git"
$gh = Find-Exe 'gh.exe' @("$env:ProgramFiles\GitHub CLI\gh.exe", "$env:LOCALAPPDATA\Programs\GitHub CLI\gh.exe")
if (-not $gh) {
    Write-Warning "GitHub CLI not found. Install it with:  winget install --id GitHub.cli -e"
    Write-Warning "Then run:  gh auth login --hostname github.com --git-protocol https --web --scopes workflow"
} else { Write-Host "gh:  $gh" }

New-Item -ItemType Directory -Force -Path $DataDir, "$DataDir\bin" | Out-Null

# --- gitleaks (MIT) : download the official release and verify its published SHA-256 ---
$gl = "$DataDir\bin\gitleaks.exe"
if (-not (Test-Path -LiteralPath $gl)) {
    $base = "https://github.com/gitleaks/gitleaks/releases/download/v$GitleaksVersion"
    $zipName = "gitleaks_${GitleaksVersion}_windows_x64.zip"
    $tmp = Join-Path $env:TEMP ("ghpub-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -UseBasicParsing -Uri "$base/$zipName" -OutFile "$tmp\$zipName"
        Invoke-WebRequest -UseBasicParsing -Uri "$base/gitleaks_${GitleaksVersion}_checksums.txt" -OutFile "$tmp\sums.txt"
        $line = Select-String -LiteralPath "$tmp\sums.txt" -SimpleMatch $zipName | Select-Object -First 1
        if (-not $line) { throw "checksum for $zipName not found" }
        $expected = ($line.Line -split '\s+')[0].ToLowerInvariant()
        $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath "$tmp\$zipName").Hash.ToLowerInvariant()
        if ($expected -ne $actual) { throw "gitleaks checksum mismatch - refusing to install" }
        Expand-Archive -LiteralPath "$tmp\$zipName" -DestinationPath "$tmp\x"
        Copy-Item -LiteralPath "$tmp\x\gitleaks.exe" -Destination $gl
        Write-Host "gitleaks $GitleaksVersion installed (sha256 verified): $gl"
    } finally { Remove-Item -Recurse -Force -LiteralPath $tmp -ErrorAction SilentlyContinue }
} else { Write-Host "gitleaks already present: $gl" }

# --- configuration (kept if it exists) ---
$cfg = "$DataDir\publisher.json"
if (-not (Test-Path -LiteralPath $cfg)) {
    $json = Get-Content -Raw -LiteralPath "$App\config\publisher.example.json" | ConvertFrom-Json
    $json.github.git_path = $git
    if ($gh) { $json.github.gh_path = $gh }
    $json.scanner.gitleaks_path = $gl
    $json.data_dir = $DataDir
    ($json | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $cfg -Encoding UTF8
    Write-Host "Config written: $cfg  (review project paths/exclusions before first use)"
} else { Write-Host "Config kept: $cfg" }

Push-Location $App
try {
    & $py -3 -m publisher --config $cfg status | Out-Host
    $null = & $py -3 -m publisher --config $cfg show-token
} finally { Pop-Location }
Write-Host ""
Write-Host "Next: start the service with scripts\start-publisher.cmd, then run scripts\show-token.cmd" -ForegroundColor Yellow
Write-Host "and paste the token into the Open WebUI Tool valve 'service_token'." -ForegroundColor Yellow
