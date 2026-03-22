# shade installer — Windows PowerShell
# irm https://raw.githubusercontent.com/TheNeoNovo/Shadechat/main/install.ps1 | iex

$ErrorActionPreference = "Stop"
$REPO = "https://raw.githubusercontent.com/TheNeoNovo/Shadechat/main"

function Ok   { Write-Host "  [ok] $args" -ForegroundColor Green }
function Warn { Write-Host "  [!]  $args" -ForegroundColor Yellow }
function Fail { Write-Host "  [x]  $args" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "  shade installer" -ForegroundColor Magenta
Write-Host "  encrypted LAN chat" -ForegroundColor DarkGray
Write-Host ""

function Find-Python {
    $candidates = @()
    $pyBase = "$env:USERPROFILE\AppData\Local\Programs\Python"
    if (Test-Path $pyBase) {
        Get-ChildItem $pyBase -Directory | Sort-Object Name -Descending | ForEach-Object {
            $exe = "$($_.FullName)\python.exe"
            if (Test-Path $exe) { $candidates += $exe }
        }
    }
    $candidates += @("python3","python","py")
    foreach ($cmd in $candidates) {
        try {
            $ok = & $cmd -c "import sys;print(int(sys.version_info>=(3,7)))" 2>$null
            if ($ok -eq "1") { return $cmd }
        } catch {}
    }
    return $null
}

$PYTHON = Find-Python

if (-not $PYTHON) {
    Warn "Python 3.7+ not found."
    $ans = Read-Host "  Install Python now? [Y/n]"
    if ($ans -eq "" -or $ans -match "^[Yy]") {
        $tmp = "$env:TEMP\python_installer.exe"
        Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe" -OutFile $tmp -UseBasicParsing
        Start-Process -FilePath $tmp -ArgumentList "/quiet","InstallAllUsers=0","PrependPath=1","Include_launcher=0" -Wait
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        $PYTHON = Find-Python
        if (-not $PYTHON) { Warn "Open a new terminal and run again."; exit 0 }
    } else { Fail "Python 3.7+ required." }
}

Ok "Python: $(& $PYTHON --version 2>&1)"

$DIR    = "$env:USERPROFILE\.shade-app"
$BINDIR = "$env:USERPROFILE\.neo\bin"
New-Item -ItemType Directory -Force -Path $DIR    | Out-Null
New-Item -ItemType Directory -Force -Path $BINDIR | Out-Null

Invoke-WebRequest -Uri "$REPO/shade.py" -OutFile "$DIR\shade.py" -UseBasicParsing
Ok "Downloaded shade.py"

Set-Content -Path "$BINDIR\shade.cmd" -Value "@echo off`r`n`"$PYTHON`" `"$DIR\shade.py`" %*"
Ok "Created shade command"

$cur = [Environment]::GetEnvironmentVariable("PATH","User")
if ($cur -notlike "*$BINDIR*") {
    [Environment]::SetEnvironmentVariable("PATH","$BINDIR;$cur","User")
    Ok "Added to PATH"
}

Write-Host ""
Ok "shade installed. Open a new terminal and type:"
Write-Host ""
Write-Host "    shade <room>         join an encrypted room" -ForegroundColor Magenta
Write-Host "    shade keys           your key fingerprint" -ForegroundColor Magenta
Write-Host "    shade help           all commands" -ForegroundColor Magenta
Write-Host ""
