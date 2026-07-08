@echo off
setlocal
REM =====================================================
REM  jquery35-local-agent v5 - public release zip
REM  creates a self-contained zip without npm dependencies
REM  Edit the REPORT path below if needed.
REM =====================================================
set REPORT=%~dp0release
cd /d %~dp0
node run-jquery35-v5.js --report "%REPORT%" --mode release-zip
echo.
echo Release folder: %REPORT%
pause
