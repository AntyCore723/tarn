@echo off
REM SPDX-License-Identifier: GPL-3.0-only
REM ============================================================================
REM  Tarn - Uninstaller
REM  Removes the native messaging host registry keys, the "tarndpi" DPI service
REM  and the app directory. Deleting the service requires Administrator rights
REM  (delete permission is not granted to normal users); if this script runs
REM  without elevation the service is left in place with a warning.
REM  The WinDivert kernel driver is left in place (other tools may use it).
REM ============================================================================
setlocal enabledelayedexpansion
chcp 65001 >nul
title Tarn - Uninstaller

set "HOST_NAME=com.tarn.host"
set "APP_DIR=%USERPROFILE%\.tarn-tunnel"
set "LOG=%APP_DIR%\install.log"

echo.
echo ============================================================
echo   Tarn - Uninstaller
echo ============================================================
echo.
echo This will remove:
echo   - native host registry keys (Chrome/Edge/Brave)
echo   - the "tarndpi" DPI service (if present; legacy "wgdpi"/"zapret" too)
echo   - %APP_DIR%
echo.
set /p CONFIRM="Continue? (y/N): "
if /i not "%CONFIRM%"=="y" exit /b 0

REM ---- Native messaging registry keys (HKCU) ----
reg delete "HKCU\Software\Google\Chrome\NativeMessagingHosts\%HOST_NAME%" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Edge\NativeMessagingHosts\%HOST_NAME%" /f >nul 2>&1
reg delete "HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\%HOST_NAME%" /f >nul 2>&1
echo [OK] Registry keys removed

REM ---- Stop + delete our DPI services ----
REM "tarndpi" is always ours. The legacy "wgdpi"/"zapret" names are removed
REM ONLY when their ImagePath points into our app dir - a service installed
REM by other software is never stopped or deleted.
sc.exe stop tarndpi >nul 2>&1
sc.exe delete tarndpi >nul 2>&1
for %%S in (wgdpi zapret) do (
  reg query "HKLM\SYSTEM\CurrentControlSet\Services\%%S" /v ImagePath >nul 2>&1
  if !errorlevel! equ 0 (
    for /f "tokens=2,* delims= " %%A in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\%%S" /v ImagePath 2^>nul ^| findstr /i "ImagePath"') do set "DPI_IMG=%%B"
    echo !DPI_IMG! | findstr /i "tarn-tunnel wg-browser-tunnel" >nul 2>&1
    if !errorlevel! equ 0 (
      sc.exe stop %%S >nul 2>&1
      sc.exe delete %%S >nul 2>&1
    )
  )
)
set "DPI_GONE=1"
sc.exe query tarndpi >nul 2>&1
if !errorlevel! equ 0 set "DPI_GONE=0"
sc.exe query wgdpi >nul 2>&1
if !errorlevel! equ 0 set "DPI_GONE=0"
sc.exe query zapret >nul 2>&1
if !errorlevel! equ 0 set "DPI_GONE=0"
if "!DPI_GONE!"=="1" (
  echo [OK] DPI service removed
) else (
  echo [WARN] DPI service could not be removed. If it exists, run this
  echo        uninstaller again from an Administrator console.
)

REM ---- Restore hosts file + DNS/DoH settings before removing app dir ----
REM The native host left a marker block in the hosts file and (if "Force DoH"
REM was on) system DNS/DoH registry values. Run the host in CLI cleanup mode
REM to restore them while the app dir (with its state backup) still exists.
REM Requires Administrator rights for the registry parts.
if exist "%APP_DIR%\host\tarn_host.py" (
  set "HOST_PY="
  if exist "%APP_DIR%\python\python.exe" (
    set "HOST_PY=%APP_DIR%\python\python.exe"
  ) else (
    REM Embedded Python was not installed (install.bat used a system Python
    REM when one was found). Detect it so the hosts/DNS cleanup still runs —
    REM otherwise the marker block and DoH registry values would be left behind.
    for /f "delims=" %%P in ('where python 2^>nul') do if not defined HOST_PY set "HOST_PY=%%P"
    if not defined HOST_PY for /f "delims=" %%P in ('where py 2^>nul') do if not defined HOST_PY set "HOST_PY=%%P"
  )
  if defined HOST_PY (
    "%HOST_PY%" "%APP_DIR%\host\tarn_host.py" --cleanup-filter >nul 2>&1
    if !errorlevel! equ 0 (
      echo [OK] hosts file and DNS/DoH settings restored
    ) else (
      echo [WARN] hosts/DNS restore skipped - run this uninstaller from an
      echo        Administrator console to fully restore DNS/DoH settings.
    )
  ) else (
    echo [WARN] Python not found - hosts/DNS restore skipped
  )
)

REM ---- App directory (stop only OUR winws instances first) ----
powershell -NoProfile -NonInteractive -Command "Get-CimInstance Win32_Process -Filter \"Name='winws.exe'\" | Where-Object { $_.CommandLine -like '*tarn-tunnel*' -or $_.CommandLine -like '*wg-browser-tunnel*' -or $_.CommandLine -like '*engine\bins\winws.exe*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" >nul 2>&1
if exist "%APP_DIR%" (
  rmdir /s /q "%APP_DIR%"
  echo [OK] %APP_DIR% removed
)

echo.
echo Uninstall complete. The extension can be removed in chrome://extensions.
echo.
pause
exit /b 0
