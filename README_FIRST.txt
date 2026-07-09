jquery35-local-agent v5 - 빠른 시작
====================================

준비물: Node.js 16+ 만 있으면 됩니다(18+ 권장). npm install / 인터넷 불필요.

1. 이 폴더를 아무 곳에나 복사
2. 각 실행*.bat 파일 상단의 경로 3개(SOURCE/TARGET/REPORT)를 내 환경에 맞게 수정
3. 명령어를 직접 치기 싫으면 먼저 웹 대시보드부터 실행:

   실행0_웹대시보드.bat        <- http://127.0.0.1:18088/ 에서 source만 지정 후 자동 세팅/원버튼 실행/보고서 열기

4. 명령어 또는 배치파일로 순서대로 실행:

   실행1_분석만.bat            <- 반드시 이것부터. 원본/TO-BE 어떤 것도 수정 안 함
   (report\index.html 을 브라우저로 열어 현황 확인)
   (report\runtime_scenarios.html 에서 Edge IE mode 수동 검증 시나리오 확인)
   (report\runtime_parity.html 에서 Local Lab / Spring-Tomcat / IE mode 검증 범위 분리)
   실행2_TO_BE_자동수정.bat    <- 안전 자동수정만 TO-BE 폴더에 생성
   실행3_jquery교체시도.bat    <- 번들 jquery-3.5.1 / migrate 파일을 TO-BE에 자동 배치
   실행4_프로브포함.bat        <- 화면용 Runtime Probe 삽입 (Edge IE mode 대응)
   실행5_로컬랩서버.bat        <- http://localhost:18080/_pages (Tomcat 없이 미리보기)
   실행6_운영반영전검증.bat    <- 운영 반영 전 게이트. RESULT=PASS 확인
   실행7_AI리뷰팩.bat          <- (선택) 애매한 코드만 골라 외부 AI와 반복 학습 (README_KO.md 7절)
   실행8_폐쇄망증빙.bat        <- (선택) airgap_manifest.json/txt 생성
   실행9_배포ZIP생성.bat       <- (선택) 공개 배포용 ZIP 생성

- 원본 소스는 절대 수정되지 않습니다. 모든 변경은 TO-BE 폴더에만 생성됩니다.
- 웹 대시보드는 CLI 명령을 대신 실행하는 로컬 껍데기입니다. source만 지정하면 TO-BE/report/profile/server-source/verify-source를 자동 세팅하고, 실제 판정/자동수정 규칙은 배치파일과 동일합니다.
- v5.4부터 rules\*.json / project-profile.public.sample.json 으로 다른 현장용 튜닝을 코드 수정 없이 할 수 있습니다.
- 폐쇄망 반입 증빙: report\airgap_manifest.txt / airgap_manifest.json
- 공개 배포 ZIP: node run-jquery35-v5.js --report ".\release" --mode release-zip
- 외부 AI/Codex에 전달할 파일: report\voyager_packet.txt
  (CSV 파일 전달 없이 통째로 복사/붙여넣기. 요약/상위 큐/검증 시나리오/Runtime Parity/selector/AJAX 매핑 포함)
  보조 파일: report\assistant_packet.txt (호환용 요약), report\ai_review_pack.txt (애매한 지점만, 문자열은 마스킹, 반복 학습용)
- 사람이 개발계/로컬 IE mode에서 따라할 검증 지시서: report\runtime_scenarios.html / report\runtime_parity.html
- 선택형 Spring/Tomcat 실험 템플릿: runtime-lab\README_RUNTIME_LAB_KO.md (WAR/Docker/JDK/Tomcat은 포함하지 않음)
- 상세 설명: README_KO.md / 명령 예시: RUN_EXAMPLES_KO.txt
- 도구 자체 검증: node run-jquery35-v5.js --mode self-test
