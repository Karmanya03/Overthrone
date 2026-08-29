# Overthrone installer for Windows PowerShell
# Usage: irm https://raw.githubusercontent.com/Karmanya03/Overthrone/main/install.ps1 | iex

$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$Repo = "Karmanya03/Overthrone"
$InstallDir = "$env:USERPROFILE\.local\bin"
$BinaryName = "overthrone.exe"
$Shorthand = "ovt.exe"

function Draw-Progress {
    param([int]$Pct, [int]$Width = 40)
    $Filled = [math]::Round($Width * $Pct / 100)
    $Empty = $Width - $Filled
    $Bar = ("█" * $Filled) + ("░" * $Empty)
    Write-Host "`r      [$Bar] " -NoNewline -ForegroundColor Cyan
    Write-Host "$([string]::Format('{0,3}', $Pct))% " -NoNewline -ForegroundColor White
}

Write-Host ""
Write-Host "  ██████╗ ██╗   ██╗███████╗██████╗ ████████╗██╗  ██╗██████╗  ██████╗ ███╗   ██╗███████╗" -ForegroundColor Red
Write-Host " ██╔═══██╗██║   ██║██╔════╝██╔══██╗╚══██╔══╝██║  ██║██╔══██╗██╔═══██╗████╗  ██║██╔════╝" -ForegroundColor Red
Write-Host " ██║   ██║██║   ██║█████╗  ██████╔╝   ██║   ███████║██████╔╝██║   ██║██╔██╗ ██║█████╗  " -ForegroundColor Red
Write-Host " ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗   ██║   ██╔══██║██╔══██╗██║   ██║██║╚██╗██║██╔══╝  " -ForegroundColor Red
Write-Host " ╚██████╔╝ ╚████╔╝ ███████╗██║  ██║   ██║   ██║  ██║██║  ██║╚██████╔╝██║ ╚████║███████╗" -ForegroundColor Red
Write-Host "  ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝" -ForegroundColor Red
Write-Host ""
Write-Host "  Active Directory Exploitation Framework" -ForegroundColor White
Write-Host "  Every throne falls." -NoNewline -ForegroundColor DarkGray
Write-Host " 👑⚔️" -ForegroundColor Yellow
Write-Host ""
Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# ─────────────────────────────────────────────────────────────
# Step 1: Detect platform
# ─────────────────────────────────────────────────────────────
Write-Host "  [1/5] " -NoNewline -ForegroundColor Yellow
Write-Host "Detecting platform..." -ForegroundColor White

$Arch = $env:PROCESSOR_ARCHITECTURE
if ($Arch -eq "AMD64") {
    $Platform = "windows-x86_64"
} elseif ($Arch -eq "ARM64") {
    $Platform = "windows-aarch64"
} else {
    Write-Host "      x Unsupported architecture: $Arch" -ForegroundColor Red
    exit 1
}

Write-Host "      + Platform:  " -NoNewline -ForegroundColor Green
Write-Host "$Platform" -ForegroundColor White
Write-Host "      + OS:        " -NoNewline -ForegroundColor Green
Write-Host "Windows" -ForegroundColor White
Write-Host "      + Arch:      " -NoNewline -ForegroundColor Green
Write-Host "$Arch" -ForegroundColor White
Write-Host ""

# ─────────────────────────────────────────────────────────────
# Step 2: Detect latest release
# ─────────────────────────────────────────────────────────────
Write-Host "  [2/5] " -NoNewline -ForegroundColor Yellow
Write-Host "Checking latest release..." -ForegroundColor White

$ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"
try {
    $ProgressPreference = 'SilentlyContinue'
    $Release = Invoke-RestMethod -Uri $ApiUrl
    $TagName = $Release.tag_name
} catch {
    Write-Host "      x Failed to detect latest release: $_" -ForegroundColor Red
    Write-Host "      Check https://github.com/$Repo/releases" -ForegroundColor Yellow
    exit 1
}

if (-not $TagName) {
    Write-Host "      x Failed to extract latest release tag." -ForegroundColor Red
    exit 1
}

Write-Host "      + Latest:    " -NoNewline -ForegroundColor Green
Write-Host "$TagName" -ForegroundColor White
Write-Host ""

# ─────────────────────────────────────────────────────────────
# Step 3: Download binary with progress bar
# ─────────────────────────────────────────────────────────────
Write-Host "  [3/5] " -NoNewline -ForegroundColor Yellow
Write-Host "Downloading binary..." -ForegroundColor White

$DownloadUrl = "https://github.com/$Repo/releases/download/$TagName/overthrone-$Platform.exe"

if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

Write-Host "      URL: $DownloadUrl" -ForegroundColor DarkGray
Write-Host ""

# Download with progress bar
try {
    $ProgressPreference = 'SilentlyContinue'
    $wc = New-Object System.Net.WebClient
    $DestinationPath = "$InstallDir\$BinaryName"

    $ProgressTracker = {
        param($sender, $e)
        if ($e.TotalBytesToReceive -gt 0) {
            $pct = [math]::Round(($e.BytesReceived / $e.TotalBytesToReceive) * 100)
            Draw-Progress -Pct $pct -Width 40
        }
    }
    $wc.add_DownloadProgressChanged($ProgressTracker)
    $wc.DownloadFile($DownloadUrl, $DestinationPath)
    Write-Host ""
    $wc.Dispose()
} catch {
    Write-Host ""
    Write-Host "      x Download failed: $_" -ForegroundColor Red
    exit 1
}

# Verify download
if (-not (Test-Path $DestinationPath) -or (Get-Item $DestinationPath).Length -eq 0) {
    Write-Host "      x Download failed or file is empty." -ForegroundColor Red
    Remove-Item -Path $DestinationPath -Force -ErrorAction SilentlyContinue
    exit 1
}

Write-Host ""

# ─────────────────────────────────────────────────────────────
# Step 4: Install binary + create shorthand
# ─────────────────────────────────────────────────────────────
Write-Host "  [4/5] " -NoNewline -ForegroundColor Yellow
Write-Host "Installing..." -ForegroundColor White

Copy-Item -Path "$InstallDir\$BinaryName" -Destination "$InstallDir\$Shorthand" -Force

Write-Host "      + Binary:    " -NoNewline -ForegroundColor Green
Write-Host "$InstallDir\$BinaryName" -ForegroundColor White
Write-Host "      + Shorthand: " -NoNewline -ForegroundColor Green
Write-Host "$InstallDir\$Shorthand" -ForegroundColor White

# Verify installation
try {
    $InstalledVersion = & "$InstallDir\$BinaryName" -V 2>&1 | Select-Object -First 1
    Write-Host "      + Version:   " -NoNewline -ForegroundColor Green
    Write-Host "$InstalledVersion" -ForegroundColor White
} catch {
    Write-Host "      ! Could not verify version." -ForegroundColor Yellow
}
Write-Host ""

# ─────────────────────────────────────────────────────────────
# Step 5: Post-install checks
# ─────────────────────────────────────────────────────────────
Write-Host "  [5/5] " -NoNewline -ForegroundColor Yellow
Write-Host "Post-install checks..." -ForegroundColor White

$Warnings = 0

# Check PATH
$PathArray = $env:PATH -split ';'
if ($PathArray -notcontains $InstallDir) {
    Write-Host "      ! " -NoNewline -ForegroundColor Yellow
    Write-Host "$InstallDir" -NoNewline -ForegroundColor White
    Write-Host " is not in your PATH." -ForegroundColor Yellow
    Write-Host "      Adding it now (user PATH)..." -ForegroundColor Yellow

    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($UserPath -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
        $env:PATH = "$env:PATH;$InstallDir"
        Write-Host "      + Added to PATH. Restart your terminal for it to take effect." -ForegroundColor Green
    }
    $Warnings++
} else {
    Write-Host "      + PATH includes $InstallDir" -ForegroundColor Green
}

Write-Host "      + Windows has SMB client built-in. Good to go." -ForegroundColor Green
Write-Host ""

# ─────────────────────────────────────────────────────────────
# Done!
# ─────────────────────────────────────────────────────────────
Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "      Run: " -NoNewline -ForegroundColor White
Write-Host "overthrone --help" -ForegroundColor White
Write-Host "      Or:  " -NoNewline -ForegroundColor White
Write-Host "ovt --help" -ForegroundColor White
Write-Host ""

if ($Warnings -gt 0) {
    Write-Host "  ^ $Warnings warning(s) above -- check before first use." -ForegroundColor Yellow
    Write-Host ""
}

Write-Host "  Every throne falls." -NoNewline -ForegroundColor DarkGray
Write-Host " 👑⚔️" -ForegroundColor Yellow
Write-Host ""
