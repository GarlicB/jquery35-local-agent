jquery35-local-agent v5 - 빠른 시작
====================================

준비물: Node.js 16+ 만 있으면 됩니다(18+ 권장). npm install / 인터넷 불필요.

1. 이 폴더를 아무 곳에나 복사
2. 각 실행*.bat 파일 상단의 경로 3개(SOURCE/TARGET/REPORT)를 내 환경에 맞게 수정
3. 순서대로 실행:

   실행1_분석만.bat            <- 반드시 이것부터. 원본/TO-BE 어떤 것도 수정 안 함
   (report\index.html 을 브라우저로 열어 현황 확인)
   실행2_TO_BE_자동수정.bat    <- 안전 자동수정만 TO-BE 폴더에 생성
   실행3_jquery교체시도.bat    <- jquery-3.5.1.min.js / jquery-migrate-3.6.0.min.js 를
                                  WebContent\js 에 넣은 뒤 실행
   실행4_프로브포함.bat        <- 화면용 Runtime Probe 삽입 (Edge IE mode 대응)
   실행5_로컬랩서버.bat        <- http://localhost:18080/_pages (Tomcat 없이 미리보기)
   실행6_운영반영전검증.bat    <- 운영 반영 전 게이트. RESULT=PASS 확인
   실행7_AI리뷰팩.bat          <- (선택) 애매한 코드만 골라 외부 AI와 반복 학습 (README_KO.md 7절)

- 원본 소스는 절대 수정되지 않습니다. 모든 변경은 TO-BE 폴더에만 생성됩니다.
- 외부 AI에 전달할 파일: report\assistant_packet.txt (코드 내용 없이 경로/통계만)
  또는 report\ai_review_pack.txt (애매한 지점만, 문자열은 마스킹, 반복 학습용)
- 상세 설명: README_KO.md / 명령 예시: RUN_EXAMPLES_KO.txt
- 도구 자체 검증: node run-jquery35-v5.js --mode self-test
