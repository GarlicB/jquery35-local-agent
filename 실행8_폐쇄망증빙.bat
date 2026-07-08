@echo off
setlocal
REM =====================================================
REM  jquery35-local-agent v5 - airgap manifest
REM  writes airgap_manifest.json/txt for offline carry-in evidence
REM  Edit the 2 paths below for your environment.
REM =====================================================
set SOURCE=C:\work\legacy-app
set REPORT=C:\work\jquery35_report_v5
cd /d %~dp0
node run-jquery35-v5.js --source "%SOURCE%" --report "%REPORT%" --mode airgap-manifest
echo.
echo Airgap manifest: %REPORT%\airgap_manifest.txt
pause
