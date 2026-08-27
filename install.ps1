# Overthrone installer for Windows PowerShell
# Usage: irm https://raw.githubusercontent.com/Karmanya03/Overthrone/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo = "Karmanya03/Overthrone"
$InstallDir = "$env:USERPROFILE\.local\bin"
$BinaryName = "overthrone.exe"
$Shorthand = "ovt.exe"

Write-Host "Installing Overthrone..." -ForegroundColor Cyan

# Detect architecture
$Arch = $env:PROCESSOR_ARCHITECTURE
if ($Arch -eq "AMD64") {
    $Platform = "windows-x86_64"
} elseif ($Arch -eq "ARM64") {
    $Platform = "windows-aarch64"
} else {
    Write-Host "Unsupported architecture: $Arch" -ForegroundColor Red
    exit 1
}

Write-Host "Detected platform: $Platform" -ForegroundColor Yellow

# Get latest release tag from GitHub API
$ApiUrl = "https://api.github.com/repos/$Repo/releases/latest"
try {
    $ProgressPreference = 'SilentlyContinue'
    $Release = Invoke-RestMethod -Uri $ApiUrl
    $TagName = $Release.tag_name
} catch {
    Write-Host "Failed to detect latest release: $_" -ForegroundColor Red
    Write-Host "Check https://github.com/$Repo/releases" -ForegroundColor Yellow
    exit 1
}

if (-not $TagName) {
    Write-Host "Failed to extract latest release tag." -ForegroundColor Red
    exit 1
}

Write-Host "Latest release: $TagName" -ForegroundColor Green

# Build download URL from the resolved tag
$DownloadUrl = "https://github.com/$Repo/releases/download/$TagName/overthrone-$Platform.exe"

# Create install directory
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

# Download binary
Write-Host "Downloading from $DownloadUrl..." -ForegroundColor Yellow
try {
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $DownloadUrl -OutFile "$InstallDir\$BinaryName" -UseBasicParsing
} catch {
    Write-Host "Download failed: $_" -ForegroundColor Red
    exit 1
}

# Create shorthand copy
Copy-Item -Path "$InstallDir\$BinaryName" -Destination "$InstallDir\$Shorthand" -Force

Write-Host "Installed $TagName to $InstallDir\$BinaryName" -ForegroundColor Green
Write-Host "Shorthand: $InstallDir\$Shorthand" -ForegroundColor Green

# Check if install dir is in PATH
$PathArray = $env:PATH -split ';'
if ($PathArray -notcontains $InstallDir) {
    Write-Host ""
    Write-Host "WARNING: $InstallDir is not in your PATH." -ForegroundColor Yellow
    Write-Host "   Adding it now (user PATH)..."
    
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($UserPath -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
        $env:PATH = "$env:PATH;$InstallDir"
        Write-Host "Added to PATH. Restart your terminal for it to take effect." -ForegroundColor Green
    }
}

# Check for SMB (Windows has it by default, just inform)
Write-Host ""
Write-Host "Windows has SMB client built-in. You're good to go." -ForegroundColor Cyan

Write-Host ""
Write-Host "Installation complete!" -ForegroundColor Green
Write-Host "   Run: overthrone --help"
Write-Host "   Or:  ovt --help"
Write-Host ""
