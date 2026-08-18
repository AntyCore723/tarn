# SPDX-License-Identifier: GPL-3.0-only
# diagnose.ps1 — Diagnostic script for Tarn (WG Tunnel) native messaging
# Run this to check why native host is "forbidden"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Tarn - Diagnostics" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$HOST_NAME = "com.tarn.host"
$APP_DIR = Join-Path $env:USERPROFILE ".tarn-tunnel"

# 1. Check Chrome Registry
Write-Host "--- Chrome Native Messaging Registry ---" -ForegroundColor Yellow
$chromeRegPath = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HOST_NAME"
$regEntry = Get-ItemProperty -Path $chromeRegPath -ErrorAction SilentlyContinue
if ($regEntry) {
    $manifestPath = $regEntry.'(Default)'
    Write-Host "[OK] Registry key exists: $chromeRegPath" -ForegroundColor Green
    Write-Host "     Points to: $manifestPath" -ForegroundColor White
    
    if (Test-Path $manifestPath) {
        Write-Host "[OK] Manifest file exists" -ForegroundColor Green
        Write-Host ""
        Write-Host "--- Manifest Contents ---" -ForegroundColor Cyan
        $manifest = Get-Content $manifestPath -Raw
        Write-Host $manifest
        Write-Host "--- End Manifest ---" -ForegroundColor Cyan
        Write-Host ""
        
        # Parse and check
        try {
            $json = $manifest | ConvertFrom-Json
        } catch {
            Write-Host "[ERROR] Manifest is not valid JSON - re-run install.bat" -ForegroundColor Red
            exit 1
        }
        Write-Host "  name: $($json.name)" -ForegroundColor White
        Write-Host "  type: $($json.type)" -ForegroundColor White
        Write-Host "  path: $($json.path)" -ForegroundColor White
        Write-Host "  allowed_origins: $($json.allowed_origins -join ', ')" -ForegroundColor White
        Write-Host ""
        
        # Check if path exists
        $batPath = $json.path
        if (Test-Path $batPath) {
            Write-Host "[OK] Wrapper batch file exists: $batPath" -ForegroundColor Green
        } else {
            Write-Host "[ERROR] Wrapper batch file NOT FOUND: $batPath" -ForegroundColor Red
            Write-Host "  You need to re-run install.bat" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[ERROR] Manifest file NOT FOUND at: $manifestPath" -ForegroundColor Red
        Write-Host "  Re-run install.bat to create it" -ForegroundColor Yellow
    }
} else {
    Write-Host "[ERROR] Chrome Registry key NOT FOUND" -ForegroundColor Red
    Write-Host "  Path: $chromeRegPath" -ForegroundColor White
    Write-Host "  You must run install.bat first!" -ForegroundColor Yellow
}

# 2. Check Edge Registry
Write-Host ""
Write-Host "--- Edge Native Messaging Registry ---" -ForegroundColor Yellow
$edgeRegPath = "HKCU:\Software\Microsoft\Edge\NativeMessagingHosts\$HOST_NAME"
$edgeReg = Get-ItemProperty -Path $edgeRegPath -ErrorAction SilentlyContinue
if ($edgeReg) {
    Write-Host "[OK] Edge Registry: $($edgeReg.'(Default)')" -ForegroundColor Green
} else {
    Write-Host "[-] Edge Registry not set (optional)" -ForegroundColor Gray
}

# 3. Check host directory
Write-Host ""
Write-Host "--- Host Directory Contents ---" -ForegroundColor Yellow
$hostDir = Join-Path $APP_DIR "host"
if (Test-Path $hostDir) {
    Get-ChildItem $hostDir | ForEach-Object {
        Write-Host "  $($_.Name) ($($_.Length) bytes)" -ForegroundColor White
    }
} else {
    Write-Host "[ERROR] Host directory not found: $hostDir" -ForegroundColor Red
}

# 4. Check Python
Write-Host ""
Write-Host "--- Python ---" -ForegroundColor Yellow
foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($ver -match "Python 3") {
            $path = (Get-Command $cmd).Source
            Write-Host "[OK] $cmd -> $path" -ForegroundColor Green
            break
        }
    } catch {}
}

# 5. Check wireproxy
Write-Host ""
Write-Host "--- wireproxy ---" -ForegroundColor Yellow
$wpBin = Join-Path $APP_DIR "bin\wireproxy.exe"
if (Test-Path $wpBin) {
    Write-Host "[OK] wireproxy.exe exists: $wpBin" -ForegroundColor Green
    try {
        $ver = & $wpBin --version 2>&1
        Write-Host "     Version: $ver" -ForegroundColor White
    } catch {
        Write-Host "     Could not get version" -ForegroundColor Yellow
    }
} else {
    Write-Host "[-] wireproxy.exe not found at $wpBin" -ForegroundColor Yellow
    $wpPath = Get-Command wireproxy -ErrorAction SilentlyContinue
    if ($wpPath) {
        Write-Host "[OK] But found in PATH: $($wpPath.Source)" -ForegroundColor Green
    } else {
        Write-Host "  Will be auto-downloaded on first connect" -ForegroundColor Gray
    }
}

# 6. Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$issues = @()
if (-not $regEntry) { $issues += "Chrome Registry key missing - run install.bat" }
if ($regEntry -and -not (Test-Path $regEntry.'(Default)')) { $issues += "Manifest file missing" }
if ($regEntry) {
    $mf = $null
    try {
        $mf = Get-Content $regEntry.'(Default)' -Raw | ConvertFrom-Json
    } catch {}
    if ($mf) {
        if ($mf.allowed_origins -match "EXTENSION_ID") { $issues += "Manifest has placeholder EXTENSION_ID - re-run install.bat" }
        if (-not (Test-Path $mf.path)) { $issues += "Wrapper batch not found: $($mf.path)" }
    } else {
        $issues += "Manifest could not be parsed - re-run install.bat"
    }
}

if ($issues.Count -eq 0) {
    Write-Host "[OK] Everything looks good!" -ForegroundColor Green
    Write-Host "  If still getting 'forbidden', restart Chrome completely." -ForegroundColor Yellow
} else {
    Write-Host "[ISSUES FOUND]" -ForegroundColor Red
    foreach ($issue in $issues) {
        Write-Host "  - $issue" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "FIX: Run install.bat (double-click it in the release folder):" -ForegroundColor Yellow
    Write-Host "  The extension ID is derived automatically from manifest.json" -ForegroundColor White
}

Write-Host ""
