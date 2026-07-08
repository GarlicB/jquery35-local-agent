@echo off
setlocal
REM =====================================================
REM  jquery35-local-agent v5 - local web dashboard
REM  Opens a browser UI for running plan/autofix/patch/review/verify/release.
REM  Edit the defaults below or change them in the browser UI.
REM =====================================================
set SOURCE=C:\work\legacy-app
set TARGET=C:\work\legacy-app_jquery35_tobe
set REPORT=C:\work\jquery35_report_v5
set PORT=18088
cd /d %~dp0
node run-jquery35-v5.js --mode ui --source "%SOURCE%" --target "%TARGET%" --report "%REPORT%" --port %PORT%
echo.
echo UI stopped.
pause
