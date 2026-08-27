# Overthrone installer for Windows PowerShell
# Usage: irm https://raw.githubusercontent.com/Karmanya03/Overthrone/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo = "Karmanya03/Overthrone"
$InstallDir = "$env:USERPROFILE\.local\bin"
$BinaryName = "overthrone.exe"
$Shorthand = "ovt.exe"

Write-Host ""
Write-Host "  ██████╗ ███████╗███╗   ███╗██╗ ██████╗ " -ForegroundColor Red
Write-Host "  ██╔══██╗██╔════╝████╗ ████║██║██╔═══██╗" -ForegroundColor Red
Write-Host "  ██████╔╝█████╗  ██╔████╔██║██║██║   ██║" -ForegroundColor Red
Write-Host "  ██╔══██╗██╔══╝  ██║╚██╔╝██║██║██║   ██║" -ForegroundColor Red
Write-Host "  ██║  ██║███████╗██║ ╚═╝ ██║██║╚██████╔╝" -ForegroundColor Red
Write-Host "  ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝ ╚═════╝ " -ForegroundColor Red
Write-Host ""
Write-Host "  Active Directory Exploitation Framework" -ForegroundColor White
Write-Host "  Every throne falls." -ForegroundColor DarkGray
Write-Host ""
Write-Host "---------------------------------------------------"
Write-Host ""

# Detect architecture
$Arch = $env:PROCESSOR_ARCHITECTURE
if ($Arch -eq "AMD64") {
    $Platform = "windows-x86_64"
} elseif ($Arch -eq "ARM64") {
    $Platform = "windows-aarch64"
} else {
    Write-Host "  [X] Unsupported architecture: $Arch" -ForegroundColor Red
    exit 1
}

Write-Host "  [*] Detected platform:  " -NoNewline -ForegroundColor Cyan
Write-Host "$Platform" -ForegroundColor White
Write-Host ""

# Get latest release tag from GitHub API
$ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"
try {
    $ProgressPreference = 'SilentlyContinue'
    $Release = Invoke-RestMethod -Uri $ApiUrl
    $TagName = $Release.tag_name
} catch {
    Write-Host "  [X] Failed to detect latest release: $_" -ForegroundColor Red
    Write-Host "      Check https://github.com/$Repo/releases" -ForegroundColor Yellow
    exit 1
}

if (-not $TagName) {
    Write-Host "  [X] Failed to extract latest release tag." -ForegroundColor Red
    exit 1
}

Write-Host "  [+] Latest release:    " -NoNewline -ForegroundColor Green
Write-Host "$TagName" -ForegroundColor White
Write-Host ""

# Build download URL from the resolved tag
$DownloadUrl = "https://github.com/$Repo/releases/download/$TagName/overthrone-$Platform.exe"

# Create install directory
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

Write-Host "  [*] Downloading..." -ForegroundColor Cyan
Write-Host "      $DownloadUrl" -ForegroundColor DarkGray
Write-Host ""

# Download binary with progress bar
try {
    $ProgressPreference = 'SilentlyContinue'
    $wc = New-Object System.Net.WebClient
    $DestinationPath = "$InstallDir\$BinaryName"

    # Register progress tracking
    $ProgressTracker = {
        param($sender, $e)
        if ($e.TotalBytesToReceive -gt 0) {
            $pct = [math]::Round(($e.BytesReceived / $e.TotalBytesToReceive) * 100)
            $barLen = 30
            $filled = [math]::Round($barLen * $pct / 100)
            $empty = $barLen - $filled
            $bar = ("█" * $filled) + ("░" * $empty)
            Write-Host "`r      `e[33m[$bar]`e[0m $pct%  " -NoNewline
        }
    }
    $wc.add_DownloadProgressChanged($ProgressTracker)
    $wc.DownloadFile($DownloadUrl, $DestinationPath)
    Write-Host ""
    $wc.Dispose()
} catch {
    Write-Host ""
    Write-Host "  [X] Download failed: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  [*] Installing..." -ForegroundColor Cyan

# Create shorthand copy
Copy-Item -Path "$InstallDir\$BinaryName" -Destination "$InstallDir\$Shorthand" -Force

Write-Host "  [+] Binary:    " -NoNewline -ForegroundColor Green
Write-Host "$InstallDir\$BinaryName" -ForegroundColor White
Write-Host "  [+] Shorthand: " -NoNewline -ForegroundColor Green
Write-Host "$InstallDir\$Shorthand" -ForegroundColor White
Write-Host ""

# Check if install dir is in PATH
$PathArray = $env:PATH -split ';'
if ($PathArray -notcontains $InstallDir) {
    Write-Host "  [!] " -NoNewline -ForegroundColor Yellow
    Write-Host "$InstallDir" -NoNewline -ForegroundColor White
    Write-Host " is not in your PATH." -ForegroundColor Yellow
    Write-Host "      Adding it now (user PATH)..." -ForegroundColor Yellow

    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($UserPath -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
        $env:PATH = "$env:PATH;$InstallDir"
        Write-Host "      Added to PATH. Restart your terminal for it to take effect." -ForegroundColor Green
    }
    Write-Host ""
}

# Check for SMB (Windows has it by default, just inform)
Write-Host "  [*] Windows has SMB client built-in. You're good to go." -ForegroundColor Cyan
Write-Host ""

Write-Host "---------------------------------------------------"
Write-Host ""
Write-Host "  [+] " -NoNewline -ForegroundColor Green
Write-Host "Installation complete!" -ForegroundColor White
Write-Host ""
Write-Host "      Run: " -NoNewline
Write-Host "overthrone --help" -ForegroundColor White
Write-Host "      Or:  " -NoNewline
Write-Host "ovt --help" -ForegroundColor White
Write-Host ""
Write-Host "  Every throne falls. " -NoNewline -ForegroundColor DarkGray
Write-Host "👑⚔️" -ForegroundColor Yellow
Write-Host ""
