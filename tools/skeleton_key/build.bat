@echo off
REM Build script for skeleton_key.dll
REM Requires Visual Studio Build Tools (MSVC)

setlocal enabledelayedexpansion

REM Find cl.exe
set "CL_PATH="
for /f "delims=" %%I in ('where /r "C:\Program Files (x86)\Microsoft Visual Studio" cl.exe 2^>nul') do (
    if not defined CL_PATH set "CL_PATH=%%I"
)

if not defined CL_PATH (
    echo [ERROR] cl.exe not found. Install Visual Studio Build Tools.
    exit /b 1
)

echo [INFO] Using compiler: %CL_PATH%

REM Set up include/lib paths from the same directory tree
for %%F in ("%CL_PATH%") do set "BIN_DIR=%%~dpF"
for %%D in ("%BIN_DIR%..\..") do set "VC_ROOT=%%~fD"

REM Find Windows SDK
set "SDK_PATH="
for /f "delims=" %%I in ('dir /b /s "C:\Program Files (x86)\Windows Kits\10\Include\*\um\windows.h" 2^>nul ^| findstr /r "[0-9]" ^| sort /r') do (
    for %%J in ("%%~dpI..") do (
        if not defined SDK_PATH set "SDK_PATH=%%~fJ"
    )
)

if not defined SDK_PATH (
    echo [ERROR] Windows SDK not found. Install Windows 10 SDK.
    exit /b 1
)

REM Extract SDK version from path
for %%F in ("%SDK_PATH%") do set "SDK_VERSION=%%~nxF"

echo [INFO] Windows SDK: %SDK_VERSION%

REM Include paths
set "INCLUDES=/I\"%VC_ROOT%\include\" /I\"%SDK_PATH%\um\" /I\"%SDK_PATH%\ucrt\" /I\"%SDK_PATH%\shared\""

REM Library paths
set "LIBS=/LIBPATH:\"%VC_ROOT%\lib\x64\" /LIBPATH:\"%SDK_PATH%\um\x64\" /LIBPATH:\"%SDK_PATH%\ucrt\x64\""

REM Compile
echo [INFO] Compiling skeleton_key.dll...
"%CL_PATH%" /LD /O2 /Os /GS- /W3 /WX- /Gy /Gm- /Zi /Fe"skeleton_key.dll" /Fd"skeleton_key.pdb" skeleton_key.c %INCLUDES% %LIBS% dbghelp.lib advapi32.lib kernel32.lib user32.lib

if %ERRORLEVEL% EQU 0 (
    echo [SUCCESS] skeleton_key.dll built successfully
    echo [INFO] Output: %CD%\skeleton_key.dll
    dir /b skeleton_key.*
) else (
    echo [ERROR] Compilation failed
    exit /b %ERRORLEVEL%
)

endlocal
