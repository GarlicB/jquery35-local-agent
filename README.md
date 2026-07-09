# jquery35-local-agent

**폐쇄망에서 Node.js 하나로 돌아가는 jQuery CVE-2020-11023 조치 자동화 도구**
(레거시 Java/Spring/JSP 프로젝트용 · npm install 불필요 · 인터넷 불필요 · 외부 의존성 0)

오래된 레거시 웹(Spring/JSP 계열 + jQuery 1.x)에서 jQuery를 3.5+로 올려야 할 때 필요한 전 과정을 로컬에서 처리합니다:
**전수 정적분석 → 안전 자동수정(TO-BE 생성) → jQuery 3.5.1 + Migrate 교체 → 화면용 Runtime Probe → mock Lab 서버 → 운영 반영 전 게이트 검사 → 보고서**.

## 특징

- **원본 무수정 원칙** — 모든 변경은 `--target` TO-BE 폴더에만 생성. 원본과 diff로 비교 후 반영.
- **오탐을 줄인 스캐너** — 단순 정규식이 아니라 토큰 마스킹(주석/문자열/정규식 제거) + 리시버 체인 역추적 + 괄호균형 인자 파서 + 파일 내 taint 추적(ajax 콜백 파라미터 → DOM sink 승격) + 전 프로젝트 콜사이트 타입 추론(AutoInferred).
- **안전한 것만 자동수정** — `.bind→.on`, `.size()→.length`, boolean `.attr→.prop` 등 jQuery 1.x/3.x 양쪽에서 동작하는 선제 변경만. `.html(response)` 같은 XSS 후보는 절대 자동수정하지 않고 분류만.
- **폐쇄망/구형 환경 대응** — Edge IE mode(개발자도구 제한)용 ES5 Runtime Probe, EUC-KR 파일 바이트 보존(latin1 round-trip), CSV/XLS 보고서를 npm 없이 직접 생성.
- **AI 리뷰팩(review-pack)** — 애매한 코드 지점(함수명 + 앞뒤 몇 줄, 문자열/주석/정규식은 마스킹)만 골라 외부 AI와 스무고개처럼 반복 학습하는 루프. 회사 전용 공통 함수(AJAX 래퍼 등) 하나의 역할만 알아내면 그 지식이 호출부 전체에 전파됨. 학습된 지식은 절대 자동수정을 트리거하지 않고 분류에만 영향.
- **Hermes 로컬 검수팩(hermes-pack)** — 외부 AI 질문과 별개로 각 CASE의 정적 확인 포인트, 로컬 Probe/Lab 테스트, 통과/실패 기준, project-profile 반영 템플릿, CASE별 모킹 시험장 웹페이지를 생성. 폐쇄망 안에서 반복 검수 지식을 쌓기 위한 부품팩.
- **공개 배포용 rulepack** — 웹루트 후보, Probe 삽입 힌트, 벤더 권고, mock 기본 응답을 `rules/*.json`으로 분리. 배포처마다 JS 코드를 고치지 않고 룰팩만 바꿔 튜닝합니다.
- **Java/Spring 정적 증거** — Spring을 띄우지 않고 `@RequestMapping` 계열과 XML 설정을 읽어 `ajaxToServerMap.csv`, `serverEndpoints.csv`, `hermes_server_evidence.json`을 생성하고 mock route에 컨트롤러 힌트를 붙입니다.
- **IE mode 수동 검증 시나리오** — JSP/HTML의 `id`/`class`/`name`/버튼 텍스트를 인벤토리화하고 JS selector와 매칭해, `runtime_scenarios.html`에 “어느 화면에서 무엇을 눌러볼지”를 생성합니다.
- **Runtime Parity 분석** — Local Lab/mock 결과를 어디까지 믿을 수 있는지 분리해 `LOCAL_LAB_OK`, `SPRING_TOMCAT_REQUIRED`, `IE_MODE_REQUIRED`로 분류하고 `runtime_parity.html`, `runtimeParity.csv`, `ieModeRisk.csv`를 생성합니다.
- **선택형 Runtime Lab 템플릿** — public ZIP에는 Docker/JDK/Tomcat/WAR를 넣지 않고, Codex/로컬 PC에서 WAR를 얹어 실험할 수 있는 `runtime-lab/` 스캐폴드만 제공합니다.
- **Voyager 복붙 패킷** — CSV 파일을 전달할 수 없는 폐쇄망 상황을 위해 `voyager_packet.txt` 하나에 요약/시나리오/selector/AJAX/다음 액션을 줄 단위로 압축합니다.
- **폐쇄망 배포 산출물** — `airgap_manifest.json/txt`로 무의존/무통신 증빙을 남기고, `--mode release-zip`으로 공개 배포용 ZIP을 생성합니다.
- **로컬 웹 콘솔** — `실행0_웹대시보드.bat` 또는 `--mode ui`로 브라우저에서 경로 Browse, 자동 경로 산정, plan/autofix/patch/Hermes/report 파이프라인, Local Lab, 기존 보고서 HTML 열기를 처리합니다.
- **집계/검수 대시보드** — `index.html`에서 유형별 그래프(`event-shortcut-load` 등)와 디렉토리 depth별 분포를 먼저 보고, 파일 클릭 시 AS-IS/TO-BE 주변 코드를 모달로 비교합니다.
- **자체 검증 내장** — `--mode self-test`가 임시 샘플 프로젝트를 만들어 전체 사이클(123개 체크)을 검증. v5.6.5는 source-only 자동 세팅, S1~S10 웹 콘솔 단계명, 경로/유형 집계, AS-IS/TO-BE 줄바꿈 보존 자동수정, UI 요소 기반 런타임 시나리오, Runtime Parity 분석, Voyager 복붙 패킷 생성을 포함합니다.

## 빠른 시작

```bat
node run-jquery35-v5.js --mode self-test

node run-jquery35-v5.js --mode ui --port 18088

node run-jquery35-v5.js --source "C:\work\legacy-app" --target "C:\work\legacy-app_jquery35_tobe" --report "C:\work\jquery35_report_v5" --mode plan
```

브라우저 콘솔은 `http://127.0.0.1:18088/` 에서 열립니다. 여기서 source만 Browse 또는 입력하면 TO-BE/report/profile/server-source/verify-source 기본 경로가 자동 산정되고, 개별 `S1~S10` 단계 또는 `Pipeline`으로 실행하면 됩니다.
명령어 방식이 편하면 `report\index.html` 대시보드를 열어 현황을 확인하고, `README_FIRST.txt`의 순서(분석 → 자동수정 → jQuery 교체 → Probe → Lab → verify-clean)를 따라가면 됩니다.
Windows 사용자는 동봉된 `실행0_웹대시보드.bat` ~ `실행9_배포ZIP생성.bat`의 상단 경로만 수정해 실행하세요.

공개 배포/다른 현장 적용 시에는 `project-profile.public.sample.json`을 복사해 `project-profile.json`으로 만들고, 필요하면 `rules/public-defaults.json`, `rules/vendor-compat.json`, `rules/mock-defaults.json`만 수정하세요.

```bat
node run-jquery35-v5.js --report ".\release" --mode release-zip
```

## 문서

- [README_KO.md](README_KO.md) — 전체 매뉴얼 (판정 기준, 모드 설명, Git/CI 플로우, FAQ)
- [VENDOR_COMPAT_KO.md](VENDOR_COMPAT_KO.md) — 벤더 호환성 브리프: jqGrid/jQuery UI/select2/autoNumeric의 jQuery 3.x 호환 버전, jQuery UI 자체 CVE, Migrate가 복원 못 하는 동작 변화(자기닫힘 태그 등)
- [RUN_EXAMPLES_KO.txt](RUN_EXAMPLES_KO.txt) — 명령 예시 모음
- [README_FIRST.txt](README_FIRST.txt) — 빠른 시작

문서의 모든 경로(`C:\work\legacy-app` 등)는 예시입니다. 실제 프로젝트 경로로 바꿔 사용하세요.

## 요구사항

Node.js 16+ minimum, Node.js 18+ recommended. 그게 전부입니다.

## 라이선스

MIT
