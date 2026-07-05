@echo off
setlocal
REM =====================================================
REM  jquery35-local-agent v5 - plan
REM  analyze only, nothing is modified
REM  Edit the 3 paths below for your environment.
REM =====================================================
set SOURCE=C:\work\legacy-app
set TARGET=C:\work\legacy-app_jquery35_tobe
set REPORT=C:\work\jquery35_report_v5
cd /d %~dp0
node run-jquery35-v5.js --source "%SOURCE%" --target "%TARGET%" --report "%REPORT%" --mode plan
echo.
echo Report: %REPORT%\index.html
pause
