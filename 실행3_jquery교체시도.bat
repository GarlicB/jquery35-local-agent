@echo off
setlocal
REM =====================================================
REM  jquery35-local-agent v5 - patch-jquery
REM  put jquery-3.5.1.min.js + jquery-migrate-3.6.0.min.js in WebContent\js first
REM  add --migrate-trace below only when detailed JQMIGRATE tracing is needed
REM  Edit the 3 paths below for your environment.
REM =====================================================
set SOURCE=C:\work\legacy-app
set TARGET=C:\work\legacy-app_jquery35_tobe
set REPORT=C:\work\jquery35_report_v5
cd /d %~dp0
node run-jquery35-v5.js --source "%SOURCE%" --target "%TARGET%" --report "%REPORT%" --mode patch-jquery
echo.
echo Report: %REPORT%\index.html
pause
