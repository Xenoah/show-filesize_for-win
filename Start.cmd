@echo off
setlocal
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" goto arm
if /i "%PROCESSOR_ARCHITEW6432%"=="ARM64" goto arm
if /i "%PROCESSOR_ARCHITECTURE%"=="AMD64" goto x64
if /i "%PROCESSOR_ARCHITEW6432%"=="AMD64" goto x64
start "" "%~dp0x86\FolderSizeGuard.exe"
exit /b
:x64
start "" "%~dp0x64\FolderSizeGuard.exe"
exit /b
:arm
echo ARM64 is not supported by this preview.
pause
exit /b 1
