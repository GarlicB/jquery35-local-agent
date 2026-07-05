@echo off
setlocal
REM =====================================================
REM  jquery35-local-agent v5 - verify-clean (pre-release gate)
REM  SOURCE here is the TO-BE (or merged working copy) to verify.
REM  exit code 2 = FAIL (old jquery / probe leftovers / criticals)
REM =====================================================
set SOURCE=C:\work\legacy-app_jquery35_tobe
set REPORT=C:\work\jquery35_report_v5_clean
cd /d %~dp0
node run-jquery35-v5.js --source "%SOURCE%" --report "%REPORT%" --mode verify-clean
echo.
echo Result: %REPORT%\verify_clean_result.txt
pause
