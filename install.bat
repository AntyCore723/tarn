@echo off
REM SPDX-License-Identifier: GPL-3.0-only
setlocal enabledelayedexpansion
chcp 65001 >nul
title Tarn - Native Host Installer

REM ============================================================================
REM  Tarn - Native Host Installer for Windows
REM  Double-click this file after loading the extension in chrome://extensions
REM  The popup flips from "tunnel unavailable" to "available" by itself
REM  seconds after this script registers the host - no reload needed.
REM  No Administrator privileges required. No external downloads. Everything
REM  is bundled in this folder.
REM ============================================================================

REM ---- Constants (single source of truth) ----
set "HOST_NAME=com.tarn.host"
set "APP_DIR=%USERPROFILE%\.tarn-tunnel"
set "HOST_DIR=%APP_DIR%\host"
set "BIN_DIR=%APP_DIR%\bin"
set "ENGINE_DIR=%APP_DIR%\engine"
set "LOG=%APP_DIR%\install.log"
set "SCRIPT_DIR=%~dp0"
set "EXT_MANIFEST=%SCRIPT_DIR%manifest.json"

REM ---- Init log ----
if not exist "%APP_DIR%" mkdir "%APP_DIR%" >nul 2>&1
(
  echo ============================================================
  echo Tarn Installer log - %DATE% %TIME%
  echo User: %USERNAME%@%COMPUTERNAME%
  echo Script dir: %SCRIPT_DIR%
  echo Native host name: %HOST_NAME%
  echo ============================================================
  echo.
) > "%LOG%"

echo.
echo ============================================================
echo   Tarn - Native Host Installer
echo ============================================================
echo.

REM ---- Step 1: Find Python 3 (system) or fall back to the bundled embedded Python ----
call :log "Step 1/7 - Detecting Python 3"
set "PYTHON="
for %%C in (py python python3) do (
  if not defined PYTHON (
    where %%C >nul 2>&1
    if !errorlevel! equ 0 (
      for /f "delims=" %%P in ('where %%C 2^>nul ^| findstr /v /i "WindowsApps"') do if not defined PYTHON set "PYTHON=%%P"
    )
  )
)
if defined PYTHON (
  "%PYTHON%" -V >nul 2>&1
  if !errorlevel! neq 0 set "PYTHON="
)
if not defined PYTHON (
  call :log "System Python not found - using the bundled embedded Python"
  if exist "%SCRIPT_DIR%python-embed-amd64.zip" (
    REM Integrity gate: refuse an embedded Python whose SHA-256 doesn't match
    REM the pinned hash. A tampered zip would run arbitrary code as the user.
    set "EMBED_PIN=8D3F33BE9EB810F23C102F08475AF2854E50484B8E4E06275E937BE61CE3D2FB"
    for /f "delims=" %%H in ('powershell -NoProfile -Command "(Get-FileHash -Algorithm SHA256 -LiteralPath '%SCRIPT_DIR%python-embed-amd64.zip').Hash"') do set "EMBED_HASH=%%H"
    if /i not "!EMBED_HASH!"=="!EMBED_PIN!" (
      call :log "[ERROR] python-embed-amd64.zip SHA-256 mismatch - refused to extract (tampered file?)"
      echo Python embed integrity check failed. See %LOG%.
      pause
      exit /b 1
    )
    if not exist "%APP_DIR%\python\python.exe" (
      mkdir "%APP_DIR%\python" >nul 2>&1
      tar -xf "%SCRIPT_DIR%python-embed-amd64.zip" -C "%APP_DIR%\python" >>"%LOG%" 2>&1
      if !errorlevel! neq 0 (
        powershell -NoProfile -Command "Expand-Archive -LiteralPath '%SCRIPT_DIR%python-embed-amd64.zip' -DestinationPath '%APP_DIR%\python' -Force" >>"%LOG%" 2>&1
      )
    )
    if exist "%APP_DIR%\python\python.exe" set "PYTHON=%APP_DIR%\python\python.exe"
  )
)
if not defined PYTHON (
  call :log "[ERROR] Python 3 not found and the bundled Python is unavailable. Re-download the files from the Tarn popup or install from https://python.org"
  echo Python 3 not found. See %LOG%.
  pause
  exit /b 1
)
call :log "[OK] Python: %PYTHON%"

REM ---- Step 2: Derive the deterministic extension ID from manifest.json ----
call :log "Step 2/7 - Derive extension ID from manifest.json"
set "EXT_ID="
if not exist "%EXT_MANIFEST%" (
  call :log "[ERROR] manifest.json not found at %EXT_MANIFEST%"
  echo manifest.json is missing next to install.bat. Re-download the release zip.
  pause
  exit /b 1
)
"%PYTHON%" "%SCRIPT_DIR%tools\ext_id.py" "%EXT_MANIFEST%" > "%TEMP%\_tarn_ext_id.txt" 2>&1
set /p EXT_ID=<"%TEMP%\_tarn_ext_id.txt"

set "ID_OK="
if not "!EXT_ID!"=="" (
  if "!EXT_ID:~31!" neq "" if "!EXT_ID:~32!" equ "" (
    findstr /r /c:"[^a-p]" "%TEMP%\_tarn_ext_id.txt" >nul
    if !errorlevel! neq 0 set "ID_OK=1"
  )
)
del "%TEMP%\_tarn_ext_id.txt" >nul 2>&1
if not defined ID_OK (
  call :log "[WARN] ext_id.py did not produce a valid ID (raw output: !EXT_ID!). Using pinned fallback ID."
  set "EXT_ID=jiadcegfgdohggekdciecfialalkbnpo"
)
call :log "[OK] Extension ID: !EXT_ID!"

REM ---- Step 3: Copy wireproxy.exe ----
call :log "Step 3/7 - Install wireproxy.exe"
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%" >nul 2>&1

set "SRC_WP=%SCRIPT_DIR%engine\bins\wireproxy.exe"
set "DST_WP=%BIN_DIR%\wireproxy.exe"

if not exist "%SRC_WP%" (
  call :log "[ERROR] wireproxy.exe not bundled at %SRC_WP%"
  echo wireproxy.exe is missing in the archive. Re-download the release zip.
  pause
  exit /b 1
)

if not exist "%DST_WP%" (
  copy /y "%SRC_WP%" "%DST_WP%" >>"%LOG%" 2>&1
  if !errorlevel! neq 0 (
    call :log "[ERROR] Failed to copy wireproxy.exe"
    pause
    exit /b 1
  )
  call :log "[OK] wireproxy.exe copied"
)
if exist "%DST_WP%" call :log "[OK] wireproxy.exe already present"

REM ---- Step 4: Install native host script + write wrapper.bat + manifest ----
call :log "Step 4/7 - Install native host script"
if not exist "%HOST_DIR%" mkdir "%HOST_DIR%" >nul 2>&1

copy /y "%SCRIPT_DIR%native-host\tarn_host.py" "%HOST_DIR%\" >>"%LOG%" 2>&1

REM Clean up legacy files from older versions (OPSEC: don't leave on disk)
if exist "%HOST_DIR%\wireguard_host.py" del /q "%HOST_DIR%\wireguard_host.py" 2>nul
if exist "%HOST_DIR%\wgg_host.py" del /q "%HOST_DIR%\wgg_host.py" 2>nul

> "%HOST_DIR%\tarn_host_wrapper.bat" (
  echo @echo off
  echo chcp 65001 ^>nul
  echo "%PYTHON%" "%HOST_DIR%\tarn_host.py" %%*
)
call :log "[OK] Wrapper: %HOST_DIR%\tarn_host_wrapper.bat"

"%PYTHON%" -c "import json,sys; m={'name':'%HOST_NAME%','description':'Tarn - tunnel native messaging host','path':r'%HOST_DIR%\tarn_host_wrapper.bat','type':'stdio','allowed_origins':['chrome-extension://%EXT_ID%/']}; json.dump(m, open(r'%HOST_DIR%\%HOST_NAME%.json','w',encoding='utf-8'), indent=2)" >>"%LOG%" 2>&1
call :log "[OK] Manifest: %HOST_DIR%\%HOST_NAME%.json"

REM ---- Step 5: Register Windows registry keys (HKCU - no Admin needed) ----
call :log "Step 5/7 - Register native messaging host"
set "MANIFEST=%HOST_DIR%\%HOST_NAME%.json"

reg add "HKCU\Software\Google\Chrome\NativeMessagingHosts\%HOST_NAME%" /ve /t REG_SZ /d "%MANIFEST%" /f >nul 2>&1
if !errorlevel! equ 0 (call :log "[OK] Chrome registered") else (call :log "[ERROR] Chrome registration failed")

reg add "HKCU\Software\Microsoft\Edge\NativeMessagingHosts\%HOST_NAME%" /ve /t REG_SZ /d "%MANIFEST%" /f >nul 2>&1
if !errorlevel! equ 0 (call :log "[OK] Edge registered") else (call :log "[WARN] Edge registration failed")

reg add "HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\%HOST_NAME%" /ve /t REG_SZ /d "%MANIFEST%" /f >nul 2>&1
if !errorlevel! equ 0 (call :log "[OK] Brave registered") else (call :log "[WARN] Brave registration failed")

REM ---- Step 6: Copy DPI engine (winws.exe + WinDivert + bins) ----
call :log "Step 6/7 - Install DPI engine"

REM Stop ALL DPI-related services and processes BEFORE copying.
REM The WinDivert kernel driver holds handles to WinDivert.dll/.sys — it must
REM be stopped too, not just the DPI service, or xcopy fails for ~30s until
REM the OS releases the file locks.
sc.exe query tarndpi >nul 2>&1
if !errorlevel! equ 0 (
  sc.exe stop tarndpi >>"%LOG%" 2>&1
  call :log "[OK] tarndpi service stop requested"
)
sc.exe query wgdpi >nul 2>&1
if !errorlevel! equ 0 (
  sc.exe stop wgdpi >>"%LOG%" 2>&1
  call :log "[OK] legacy wgdpi service stop requested"
)
sc.exe query WinDivert >nul 2>&1
if !errorlevel! equ 0 (
  sc.exe stop WinDivert >>"%LOG%" 2>&1
  call :log "[OK] WinDivert driver stop requested"
)
timeout /t 3 /nobreak >nul

REM Kill any remaining winws.exe / python host processes forcefully.
REM Matches the current marker (tarn-tunnel) AND the legacy marker
REM (wg-browser-tunnel) so an upgrade from an older build cleans up
REM orphan processes from the previous install.
powershell -NoProfile -NonInteractive -Command "Get-CimInstance Win32_Process -Filter \"Name='winws.exe'\" | Where-Object { $_.CommandLine -like '*tarn-tunnel*' -or $_.CommandLine -like '*wg-browser-tunnel*' -or $_.CommandLine -like '*engine\bins\winws.exe*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" >>"%LOG%" 2>&1
timeout /t 2 /nobreak >nul
powershell -NoProfile -NonInteractive -Command "Get-CimInstance Win32_Process -Filter \"Name='python.exe' or Name='py.exe'\" | Where-Object { $_.CommandLine -like '*tarn_host.py*' -or $_.CommandLine -like '*wgg_host.py*' -or $_.CommandLine -like '*wireguard_host.py*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" >>"%LOG%" 2>&1
timeout /t 2 /nobreak >nul

if not exist "%ENGINE_DIR%\bins" mkdir "%ENGINE_DIR%\bins" >nul 2>&1
if not exist "%ENGINE_DIR%\conf" mkdir "%ENGINE_DIR%\conf" >nul 2>&1

REM Copy engine using robocopy with built-in retry (handles locked files far
REM better than xcopy: it retries every 2s up to 10 times per file).
call :log "[OK] Copying engine bins (robocopy with retry)..."
robocopy "%SCRIPT_DIR%engine\bins" "%ENGINE_DIR%\bins" /E /R:10 /W:2 /NFL /NDL /NJH /NJS >>"%LOG%" 2>&1
if !errorlevel! leq 7 (
  REM robocopy exit codes 0-7 = success (0=no copy, 1=files copied, 2=extra files, etc.)
  call :log "[OK] engine bins copied"
) else (
  call :log "[WARN] robocopy returned errorlevel !errorlevel! — some files may be locked"
)
call :log "[OK] Copying engine conf..."
robocopy "%SCRIPT_DIR%engine\conf" "%ENGINE_DIR%\conf" /E /R:10 /W:2 /NFL /NDL /NJH /NJS >>"%LOG%" 2>&1

REM Verify critical engine files: existence AND size parity
set "ENGINE_MISMATCH=0"
for %%F in (winws.exe WinDivert.dll WinDivert64.sys cygwin1.dll wireproxy.exe fake_tls.bin fake_http.bin fake_quic.bin quic_initial_sample.bin tls_clienthello_large.bin tls_clienthello_sample.bin voice_udp.bin game_udp.bin stun.bin stun2.bin probe.bin) do (
  if not exist "%ENGINE_DIR%\bins\%%F" (
    call :log "[WARN] Missing engine bin: %%F"
    set "ENGINE_MISMATCH=1"
  ) else (
    call :verify_size "%SCRIPT_DIR%engine\bins\%%F" "%ENGINE_DIR%\bins\%%F"
  )
)
if "!ENGINE_MISMATCH!"=="1" (
  call :log "[WARN] Engine copy is partial (files were locked by a running DPI). Close the extension popup, stop the tunnel, and re-run this installer."
) else (
  call :log "[OK] filter engine installed and verified"
)

REM ---- Step 7: DPI service + WinDivert driver + game filter default ----
call :log "Step 7/7 - DPI service setup (requires elevation)"
echo.
echo Step 7: creating the filter service (requires Administrator approval).
echo A UAC prompt will appear - click "Yes".
echo.
powershell -NoProfile -Command "Start-Process -FilePath '%SCRIPT_DIR%install_service.bat' -Verb RunAs -Wait -WindowStyle Hidden"
if !errorlevel! neq 0 (
  call :log "[WARN] UAC declined or elevation failed - the service was NOT created. DPI will fall back to per-request UAC prompts."
) else (
  call :log "[OK] Service setup finished"
)
sc.exe query tarndpi >nul 2>&1
if !errorlevel! equ 0 (call :log "[OK] tarndpi service is installed") else (call :log "[WARN] tarndpi service is not installed")

if not exist "%ENGINE_DIR%\game_filter.enabled" (
  > "%ENGINE_DIR%\game_filter.enabled" echo all
  call :log "[OK] game_filter.enabled = all"
) else (
  call :log "[OK] game_filter.enabled already present"
)

echo.
echo ============================================================
echo   Installation complete!
echo.
echo   Native host:    %HOST_NAME%
echo   Manifest:        %MANIFEST%
echo   Engine dir:      %ENGINE_DIR%
echo   Filter service:  tarndpi (started/stopped automatically)
echo   Log file:        %LOG%
echo ============================================================
echo.
echo Next steps:
echo   1. Extension already loaded? Open the Tarn popup (toolbar icon) -
echo      the status is already "available". No reload needed.
echo   2. Not loaded yet? Load it now, then reopen the popup:
echo        chrome://extensions  ->  Developer mode  ->  Load unpacked
echo        select this folder:  %SCRIPT_DIR%
echo      The popup flips to "available" by itself - no restart.
echo   3. Click the Tarn icon: the packet filter needs no config -
echo      "Packet filter" tab -> "Full strategy test" -> enable the filter.
echo      Tunnel: paste your WG .conf, Connect.
echo.
echo   Direct links: chrome://extensions/?id=%EXT_ID%
echo        edge://extensions/?id=%EXT_ID%  brave://extensions/?id=%EXT_ID%
echo.
pause
exit /b 0

REM ============================================================================
REM  Subroutines
REM ============================================================================
:log
echo [%TIME%] %~1
>>"%LOG%" echo [%DATE% %TIME%] %~1
goto :eof

:verify_size
set "SRC=%~1"
set "DST=%~2"
for %%A in ("%SRC%") do set "S1=%%~zA"
for %%B in ("%DST%") do set "S2=%%~zB"
if not "%S1%"=="%S2%" (
  call :log "[WARN] Engine bin size mismatch: %~nx1 (src %S1% vs dst %S2%)"
  set "ENGINE_MISMATCH=1"
)
goto :eof
