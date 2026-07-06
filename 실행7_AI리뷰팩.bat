@echo off
setlocal
REM =====================================================
REM  jquery35-local-agent v5 - review-pack
REM  generates ai_review_pack.txt/json for the AI questionnaire loop (see README_KO.md section 7)
REM  Edit the 2 paths below for your environment. Re-running with the SAME REPORT folder
REM  accumulates rounds in review_loop_progress.csv.
REM =====================================================
set SOURCE=C:\work\legacy-app
set REPORT=C:\work\jquery35_report_v5
cd /d %~dp0
node run-jquery35-v5.js --source "%SOURCE%" --report "%REPORT%" --mode review-pack
echo.
echo Review pack: %REPORT%\ai_review_pack.txt
echo Paste it to an external AI, merge the JSON answer into project-profile.json, then re-run this.
pause
