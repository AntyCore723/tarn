@echo off
REM SPDX-License-Identifier: GPL-3.0-only
setlocal enabledelayedexpansion
chcp 65001 >nul
set "APP_DIR=%USERPROFILE%\.tarn-tunnel"
set "BINS=%APP_DIR%\engine\bins"
set "LOG=%APP_DIR%\install.log"
if not exist "%APP_DIR%" mkdir "%APP_DIR%" >nul 2>&1

call :log "Elevated service setup started"

REM ---- WinDivert kernel driver ----
sc.exe query WinDivert >nul 2>&1
if !errorlevel! equ 1060 (
  if exist "%BINS%\WinDivert64.sys" (
    REM Integrity gate: refuse to install a driver that does not match the
    REM pinned SHA-256 (the source dir is user-writable).
    for /f "delims=" %%H in ('powershell -NoProfile -Command "(Get-FileHash -Algorithm SHA256 -LiteralPath '%BINS%\WinDivert64.sys').Hash"') do set "WD_HASH=%%H"
    if /i not "!WD_HASH!"=="8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2" (
      call :log "[ERROR] WinDivert64.sys SHA-256 mismatch - driver NOT installed"
    ) else (
      copy /y "%BINS%\WinDivert64.sys" "%WINDIR%\System32\drivers\WinDivert64.sys" >>"%LOG%" 2>&1
      sc.exe create WinDivert type= kernel binPath= "\SystemRoot\System32\drivers\WinDivert64.sys" >>"%LOG%" 2>&1
      call :log "[OK] WinDivert driver service created"
    )
  ) else (
    call :log "[WARN] WinDivert64.sys not found - WinDivert service NOT created"
  )
) else (
  call :log "[OK] WinDivert driver service already present"
)
sc.exe query WinDivert >nul 2>&1
if !errorlevel! equ 0 (
  sc.exe start WinDivert >>"%LOG%" 2>&1
  sc.exe query WinDivert | findstr /i "RUNNING" >nul
  if !errorlevel! equ 0 (
    call :log "[OK] WinDivert driver is running"
  ) else (
    call :log "[WARN] WinDivert driver failed to start - the packet filter will NOT work. Re-run install.bat or check the driver file."
  )
)

REM ---- DPI service (placeholder args; the native host rewrites the
REM       binPath at runtime with the winning strategy) ----
REM Service name is "tarndpi" (v1.10). On upgrade, the old services from
REM earlier versions ("wgdpi" v1.6+, "zapret" v1.5-) are stopped and removed
REM first (migration).
for %%S in (tarndpi wgdpi zapret) do (
  sc.exe query %%S >nul 2>&1
  if !errorlevel! equ 0 (
    sc.exe stop %%S >nul 2>&1
    timeout /t 2 /nobreak >nul
    sc.exe delete %%S >>"%LOG%" 2>&1
  )
)
sc.exe query tarndpi >nul 2>&1
if !errorlevel! equ 1060 (
  if exist "%BINS%\winws.exe" (
    REM Integrity gate: the service runs winws as SYSTEM, so never point it
    REM at a binary that does not match the pinned SHA-256.
    for /f "delims=" %%H in ('powershell -NoProfile -Command "(Get-FileHash -Algorithm SHA256 -LiteralPath '%BINS%\winws.exe').Hash"') do set "WINWS_HASH=%%H"
    if /i not "!WINWS_HASH!"=="AFFB4F69D2EA302A7ABCCD5325D81826E140DDAE014F1E070BC4A6C0DD555188" (
      call :log "[ERROR] winws.exe SHA-256 mismatch - tarndpi service NOT created (tampered engine?)"
    ) else (
      REM start= demand: winws runs ONLY while the tunnel is active (the host
      REM issues `sc start`/`sc stop`). No boot-time persistence, no winws
      REM left running after a reboot.
      sc.exe create tarndpi binPath= "\"%BINS%\winws.exe\" --wf-tcp=0 --wf-udp=0" start= demand >>"%LOG%" 2>&1
      if !errorlevel! equ 0 (
        call :log "[OK] tarndpi service created (demand start)"
      ) else (
        call :log "[ERROR] tarndpi service creation failed"
      )
    )
  ) else (
    call :log "[WARN] winws.exe not found - tarndpi service NOT created"
  )
) else (
  call :log "[ERROR] tarndpi service could not be recreated"
)

REM SDDL: SYSTEM start/stop/query only (NOT full), Administrators full,
REM   Authenticated Users start/stop/query only, and the installing user gets
REM   SERVICE_CHANGE_CONFIG so the host can rewrite the binPath with the
REM   winning strategy.
REM   SECURITY: granting SERVICE_CHANGE_CONFIG to all Authenticated Users was
REM   a local privilege escalation - any local user could `sc config tarndpi
REM   binPath= <cmd>` and `sc start tarndpi` to run arbitrary code as SYSTEM.
for /f "tokens=2 delims=," %%S in ('whoami /user /fo csv /nh') do set "TARN_SID=%%~S"
if not defined TARN_SID (
  call :log "[ERROR] could not determine the current user SID - SDDL NOT hardened, strategy switching may need UAC"
) else (
  sc.exe sdset tarndpi "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;GXCCLCRC;;;AU)(A;;DC;;;!TARN_SID!)" >>"%LOG%" 2>&1
  if !errorlevel! equ 0 (
    call :log "[OK] tarndpi service SDDL hardened (users: start/stop; change-config: !TARN_SID! only)"
  ) else (
    call :log "[ERROR] tarndpi sdset failed - run install.bat again or grant change-config manually"
  )
)

exit /b 0

:log
>>"%LOG%" echo [%DATE% %TIME%] %~1
exit /b 0
