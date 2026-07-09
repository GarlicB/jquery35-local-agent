# jquery35-local-agent v5 — jQuery CVE-2020-11023 조치 자동화 킷

폐쇄망 로컬 PC에서 **Node.js 하나만으로** 동작하는 레거시 Java/Spring/JSP 프론트엔드 취약점 조치 도구입니다.
npm install 불필요, 인터넷 불필요, 외부 모듈 0개(Node 내장 모듈만 사용).

---

## 1. 이 도구가 하는 일

- `WebContent`/`src/main/webapp` 등 웹루트 자동 감지 및 전체 구조 분석 (JSP/JS/CSS/리소스 인벤토리)
- `WEB-INF/views` + `WEB-INF/layouts` JSP의 script/css/include 호출관계 분석
- JSP include를 따라가며 **페이지별 실제 로드되는(effective) 스크립트 목록** 재구성
- jQuery 1.10.2 등 **3.5.0 미만 core 호출부 전수 탐지 (Critical, CVE-2020-11023 핵심)**
- jQuery Migrate 누락 / core 중복 로드 / migrate 로드 순서 리스크 탐지
- 제거·변경된 jQuery API 위험 구문 정적분석 (`.bind` `.live` `.size` `.attr(bool)` `.success` 등)
- **안전한 것만** 자동수정하여 원본은 그대로 두고 **TO-BE 폴더에 동일 구조로 생성**
- DOM XSS 후보(`.html(response)` 등) 위험도 분류 (XssHigh / Review / StaticHtmlLow)
- CSV/Excel(.xls) + index.html 대시보드 + assistant_packet.txt 보고서 생성
- JSP/HTML의 `id`/`class`/`name`/버튼 텍스트와 JS selector를 매칭해 **Edge IE mode 수동 검증 시나리오** 생성
- Local Lab/mock 결과를 어디까지 믿을지 나누는 **Runtime Parity Analyzer** 생성 (`LOCAL_LAB_OK` / `SPRING_TOMCAT_REQUIRED` / `IE_MODE_REQUIRED`)
- CSV 파일 전달이 불가능한 상황을 위한 **Voyager 복붙 패킷**(`voyager_packet.txt`) 생성
- Edge IE mode용 **Runtime Probe** (개발자도구 없이 화면에서 JQMIGRATE 경고/JS 에러 수집)
- Tomcat 없이 프론트 JS를 미리 확인하는 **Local Lab mock 서버**
- 운영 반영 전 게이트 **verify-clean** (구버전 jQuery/Probe 잔존 시 FAIL)
- **AI 리뷰팩(review-pack)** — 애매한 코드 지점만 골라 함수명/앞뒤 몇 줄(문자열은 마스킹)만 담은 질문지를 생성해 외부 AI와 반복 학습하는 스무고개 루프 (7절 참고)
- **Hermes 로컬 검수팩(hermes-pack)** — 외부 AI에게 묻기 전/후에 로컬에서 확인할 테스트 설계, 검수 기준, project-profile 반영 템플릿, CASE별 모킹 시험장 웹페이지를 생성하는 폐쇄망용 부품팩
- **Java/Spring 정적 증거** — Spring을 띄우지 않고 `@RequestMapping`/XML 설정만 읽어 AJAX와 Controller 후보를 연결
- **선택형 Runtime Lab 스캐폴드** — Codex/로컬 PC에서 WAR를 얹어 Tomcat 7 계열 실험을 할 수 있는 `runtime-lab/` 템플릿 제공. Docker/JDK/Tomcat/WAR는 포함하지 않음
- **공개 배포용 rulepack/airgap/release** — 웹루트/벤더/mock 기본값은 `rules/*.json`, 폐쇄망 증빙은 `airgap_manifest.*`, 배포 ZIP은 `release-zip`
- **로컬 웹 콘솔(ui)** — PowerShell 명령을 매번 치지 않고 브라우저에서 source만 지정하면 TO-BE/report/profile/server-source/verify-source를 자동 세팅하고, `S1~S10` 단계 실행, Pipeline, Local Lab 시작/중지, 기존 HTML 보고서 열기를 처리

## 2. 이 도구가 하지 않는 일

- **원본 소스를 절대 직접 수정하지 않습니다.** 모든 변경은 `--target` TO-BE 폴더에만 기록됩니다.
- Critical(구버전 jQuery core 호출부)은 plan/autofix에서 탐지만 하고 **patch-jquery 모드에서만 교체**합니다.
- XssHigh(동적 DOM 삽입)는 **자동수정하지 않습니다.** 사람이 `.text()`/escapeHtml/신뢰경계 검토를 해야 합니다.
- 벤더 라이브러리(jqGrid/jquery-ui/select2/autoNumeric/*.min.js)는 **수정 대상에서 제외**하고 VendorReview로만 분류합니다.
- Local Lab은 Spring Controller/DB/세션/Tiles를 실행하지 않습니다. **최종 검증은 반드시 Eclipse/Tomcat 실 기동으로** 해야 합니다.
- Java/Spring 스캔은 정적 증거만 제공합니다. Controller 매핑 후보가 잡혀도 런타임 권한/세션/DB 결과가 확정되는 것은 아닙니다.
- `runtime-lab/`은 선택형 실험 템플릿입니다. Docker image, JDK, Tomcat, Maven, 업무 WAR를 배포본에 넣지 않고, Edge IE mode 렌더링도 재현하지 않습니다.

## 3. 설치

1. Node.js만 설치돼 있으면 됩니다 (Node.js 16+ 최소, 18+ 권장, npm install 불필요).
2. 이 폴더를 아무 경로에나 복사합니다 (예: `C:\tools\jquery35-local-agent-v5`).
3. 배치파일 상단의 경로 3개를 내 환경에 맞게 수정합니다.
4. 다른 현장/공개 배포용으로 쓸 때는 `project-profile.public.sample.json`을 복사해 `project-profile.json`으로 만들고, 필요하면 `rules/*.json`만 수정합니다.

기본 예시 경로:

| 용도 | 경로 |
|---|---|
| 원본(source) | `C:\work\legacy-app` |
| TO-BE(target) | `C:\work\legacy-app_jquery35_tobe` |
| 보고서(report) | `C:\work\jquery35_report_v5` |

`--source`에는 프로젝트 루트(`C:\work\legacy-app`)를 줘도 되고 `C:\work\legacy-app\WebContent`를 직접 줘도 됩니다. WebContent는 자동 감지됩니다.

### 3-1. 웹 콘솔로 실행하기

명령어를 매번 치기 싫으면 먼저 아래 중 하나로 로컬 웹 콘솔을 띄우세요.

```bat
실행0_웹대시보드.bat

node run-jquery35-v5.js --mode ui --port 18088
```

접속 주소는 `http://127.0.0.1:18088/` 입니다.

- `source`, `target`, `report`, `profile`, `rulepack`, `server-source`를 Browse로 지정하거나 직접 입력한 뒤 버튼으로 `plan`, `autofix`, `patch-jquery`, `probe`, `review-pack`, `hermes-pack`, `verify-clean`, `pr-report`, `airgap-manifest`, `release-zip`을 실행합니다.
- source를 지정하면 TO-BE/report/profile/server-source/verify-source가 자동 산정됩니다. `Auto setup`은 같은 자동 산정을 다시 강제 적용합니다. 웹 콘솔 단계명은 `S1 분석`부터 `S10 배포 ZIP`까지 고정합니다. `Run Pipeline`은 `S1→S2→S3→S6→S7→S8→S9→Lab` 순서로 실행하며, S3 이후의 검수팩/검증/보고서/Local Lab은 `verify-source`(기본값 TO-BE target)를 기준으로 실행합니다.
- `autofix`, `patch-jquery`, `probe`는 여전히 `target`이 필요합니다. 콘솔은 명령을 대신 만들어 실행해주는 껍데기이고, 안전 규칙은 CLI와 동일합니다.
- `기존 산출물` 영역에서 `index.html`, `hermes_testbench.html`, `airgap_manifest.txt`, `pr_description.md`, `verify_clean_result.txt` 등 report 폴더의 결과물을 바로 엽니다.
- Local Lab도 콘솔에서 시작/중지할 수 있고, Lab 보고서는 `http://127.0.0.1:<lab-port>/_report/index.html` 로 연결됩니다.
- 콘솔 서버는 `127.0.0.1`에만 바인딩하고 외부 통신을 하지 않습니다. 실행 명령은 shell 문자열이 아니라 Node 인자 배열로 호출합니다.

### 3-2. 공개 배포/다른 현장 튜닝 포인트

v5.4부터 코드에 박혀 있던 현장 지식을 `rules/`와 profile로 분리했습니다.

- `rules/public-defaults.json` — 웹루트 후보(`WebContent`, `src/main/webapp` 등), Probe 삽입 후보, 경로 변수, 벤더 패턴.
- `rules/vendor-compat.json` — jqGrid, jQuery UI, select2 등 벤더별 권고 문구. 새 플러그인은 여기만 늘리면 됩니다.
- `rules/mock-defaults.json` — Local Lab/mock route의 기본 JSON/HTML/TEXT 응답.
- `project-profile.public.sample.json` — 배포받은 사용자가 자기 프로젝트에 맞춰 복사해 쓰는 일반형 profile.

특정 현장용 rulepack을 따로 둘 때:

```bat
node run-jquery35-v5.js --source "C:\work\legacy-app" --report "C:\work\jquery35_report_v5" --mode plan --rulepack "C:\work\my-rulepack"
```

폐쇄망 반입용 증빙/배포 ZIP:

```bat
node run-jquery35-v5.js --source "C:\work\legacy-app" --report "C:\work\jquery35_report_v5" --mode airgap-manifest
node run-jquery35-v5.js --report ".\release" --mode release-zip
```

## 4. 모드 설명

| 모드 | 하는 일 | 원본 수정 | TO-BE 생성 |
|---|---|---|---|
| `plan` | 분석만. **처음엔 반드시 이것부터** | X | X |
| `autofix` | 안전 자동수정만 TO-BE에 적용 | X | O |
| `patch-jquery` | autofix + 구버전 jQuery script 태그를 3.5.1 + Migrate로 교체 | X | O |
| `probe` | autofix + Runtime Probe 생성/삽입 | X | O |
| `lab` | 로컬 mock 서버 기동 (기본 포트 18080) | X | X |
| `verify-clean` | 운영 반영 전 게이트 검사 (FAIL 시 exit 2) | X | X |
| `pr-report` | PR 설명/CI 체크리스트/커밋 그룹 생성 | X | X |
| `packet` | assistant_packet.txt / voyager_packet.txt / chat_summary.txt 생성 | X | X |
| `review-pack` | plan + ai_review_pack.txt/json + Hermes 로컬 검수팩 생성 (7절 참고) | X | X |
| `hermes-pack` | review-pack과 동일하지만 로컬 검수팩 의도를 명확히 한 별칭 | X | X |
| `airgap-manifest` | 폐쇄망 반입 증빙(`airgap_manifest.json/txt`)만 생성 | X | X |
| `release-zip` | 공개 배포용 ZIP + release manifest 생성 (`--source` 불필요) | X | X |
| `ui` | 브라우저 웹 콘솔 기동. 경로 Browse/자동 산정, 모드 실행, Pipeline, Local Lab 제어, 기존 HTML 산출물 열기 | X | X |
| `self-test` | 회사 코드 없이 도구 자체 정상동작 검증 (123개 체크) | X | X |

## 5. 판정 기준 (실무 기준)

- **Critical** — jQuery core 자체가 3.5 미만. CVE-2020-11023 조치의 핵심. patch-jquery 전까지 자동 교체하지 않음.
- **AutoFixed** — jQuery 1.10.2에서도 동작하고 3.5+에서도 맞는 **선제 변경**. `.bind→.on`, `.unbind→.off`, `.delegate→.on`, `.size()→.length`, `$(window).load→.on("load")`, boolean `.attr→.prop`, `.andSelf→.addBack`, 그리고 정적 HTML 문자열 안의 자기닫힘 태그 확장(`"<div/>..."` → `"<div></div>..."`, jQuery 3.5 보안픽스로 동작이 바뀌는 지점 — 상세는 VENDOR_COMPAT_KO.md). 즉 jQuery 교체 전에 먼저 반영해도 안전합니다. `$.trim`처럼 jQuery 3.x에서 계속 동작하고 jQuery 4에서 제거될 항목은 5.3부터 FocusQueue가 아니라 저위험/후순위로 분리합니다.
- **AutoInferred** — 기존 `AutoFixed2`의 명칭을 바꾼 것입니다. `.attr("disabled", sts)` 같은 변수 인자를 **프로젝트 전체 호출부를 추적해 타입을 추론**한 뒤에만 자동수정합니다. 예: 모든 호출부가 `"Y"/"N"`이면 `.prop("disabled", sts === "Y")`. 함수명 중복/호출부 타입 혼재 시 자동수정하지 않고 근거를 남깁니다.
- **Manual / Review** — `.success/.error/.complete`(AJAX냐 DOM이냐에 따라 권고 다름), `.live/.die`, 타입 불명 변수 등. 사람이 컨텍스트 확인 필요.
- **XssHigh** — `.html(response)`, `.append("<option>"+data[i]+...)` 등 동적 DOM 삽입. **jQuery 업그레이드와 별개로** DOM XSS 검토 필요. 자동수정 금지.
- **VendorReview** — jqGrid/jquery-ui/select2/autoNumeric 내부 코드. **직접 수정 금지.** Migrate 상태에서 화면 테스트하거나 호환 버전 교체를 검토하세요. 라이브러리별 호환 버전과 자체 CVE 정리는 **VENDOR_COMPAT_KO.md** 참고 (특히 jQuery UI ≤1.12.1은 자체 CVE 때문에 core 업그레이드만으로 스캐너를 통과하지 못할 수 있음).
- **StaticHtmlLow** — `.append("<option value=''>선택</option>")` 같은 정적 문자열. 저위험, 보통 조치 불필요.

특이 케이스: `.attr("disabled","false")`는 구버전 jQuery에서 **오히려 비활성화**시키는 코드였기 때문에 `.prop(...,false)`로 기계 변환하면 동작이 뒤집힙니다. 이런 건 Manual로 분류하고 이유를 적어둡니다.

## 6. 권장 작업 플로우 (Git/CI)

```
0.  실행0_웹대시보드.bat 을 열어도 됨. 아래 2~13번을 버튼으로 실행 가능
1.  git checkout -b fix/jquery-cve-2020-11023
2.  실행1_분석만.bat  (mode plan)
3.  report\index.html 열어서 현황 파악, 외부 공유가 필요하면 voyager_packet.txt만 복사
4.  실행2_TO_BE_자동수정.bat  (mode autofix)
5.  TO-BE와 원본을 WinMerge / IDE Compare / git diff 로 비교
6.  안전 자동수정만 브랜치에 반영 (커밋 그룹: AUTO_SAFE)
7.  jquery-3.5.1.min.js / jquery-migrate-3.6.0.min.js 를 WebContent\js 에 배치
    -> 실행3_jquery교체시도.bat  (mode patch-jquery, 커밋 그룹: JQUERY_CORE)
    - Probe/테스트 단계에서 JQMIGRATE 경고를 자세히 보고 싶으면 `project-profile.json`의 `jquery.newMigrateSrc`를 `/js/jquery-migrate-3.6.0.js` 같은 개발 빌드 경로로 지정하고, 운영 후보에서는 `.min.js`로 되돌리세요.
    - 사내 가이드처럼 stack trace까지 봐야 하면 `--migrate-trace`를 추가하세요. 이 옵션은 Migrate script 바로 아래에 `jQuery.migrateTrace = true; jQuery.migrateMute = false;`를 삽입합니다.
8.  로컬 WAS/Tomcat 기동
9.  실행4_프로브포함.bat 결과물로 화면에서 JQMIGRATE 경고/JS 에러 수집
    (Tomcat 없이 급하게 볼 때는 실행5_로컬랩서버.bat)
10. manualQueue.csv / focusQueue.csv 의 Manual/XssHigh 조치
11. 실행6_운영반영전검증.bat  (mode verify-clean) -> RESULT=PASS 확인
12. CI branch build
13. PR 생성 (report\pr_description.md 활용)
```

## 7. AI 리뷰팩 — 스무고개 방식 반복 학습 루프 (review-pack)

폐쇄망이라 원본 코드를 외부 AI에게 통째로 보여줄 수 없지만, **애매하게 분류된 코드 지점만 골라 함수명/앞뒤 몇 줄만** 반복적으로 물어보면 전체 코드를 몰라도 조치 정확도를 라운드마다 끌어올릴 수 있습니다. 특히 레거시 코드에는 `fnAjaxWrap`, `gridBind`, `commonEscape` 같은 "한 번 정의되고 수백 곳에서 호출되는 공통 함수"가 있는데, 이런 함수 하나의 역할만 알아내면 그 지식이 호출부 전체에 한번에 퍼집니다.

**동작 원리**

1. `review-pack` 또는 `hermes-pack` 모드를 실행하면 애매한 코드 그룹(Review/Manual/저신뢰 XssHigh 등) 중 **호출부 수(FanOut) × 우선순위**로 가중치를 매겨 상위 N개(기본 20개)만 골라 `report\ai_review_pack.txt`와 `.json`을 생성합니다.
2. 각 CASE는 파일 전체가 아니라 **함수명/패턴명 + 앞뒤 몇 줄(기본 1줄)** 만 담고, 문자열 리터럴 내용은 `<STR:short/med/long>`으로 대체되어 실제 값이 노출되지 않습니다.
3. 동시에 `hermes_test_plan.md`, `hermes_review_matrix.csv`, `hermes_testbench.html`, `hermes_profile_patch.sample.json`이 생성됩니다. 이 파일들은 폐쇄망 내부에서 각 CASE의 정적 확인 포인트, Probe/Lab 테스트, 통과/실패 기준을 검수하는 용도입니다.
4. `ai_review_pack.txt`를 외부 AI(ChatGPT/Claude 등)에게 그대로 붙여넣습니다. 파일 맨 아래 **ANSWER_JSON** 형식에 맞춰 AI가 JSON으로 답을 만들어 줍니다.
5. 외부 AI 답변을 그대로 믿지 말고 `hermes_review_matrix.csv`의 StaticEvidence/RuntimeTest 기준으로 한 번 검수합니다.
6. 검수된 JSON만 `project-profile.json`의 `learnedWrappers`/`learnedFindings` 배열에 병합합니다.
7. 같은 `--report` 폴더로 `review-pack`/`hermes-pack`(또는 `plan`)을 다시 실행하면, 학습된 지식이 반영되어 애매한 큐가 줄어들고 `review_loop_progress.csv`에 라운드별 진행 상황이 누적됩니다. 이 2~7단계를 몇 차례 반복합니다.

**Hermes 로컬 검수팩 산출물**

- `hermes_test_plan.md` — CASE별 가설, 정적 확인, 로컬 실행 테스트, 통과/실패 기준.
- `hermes_review_matrix.csv` — Excel/WinMerge에서 보기 쉬운 검수 매트릭스.
- `hermes_testbench.html` — report 폴더에서 바로 여는 모킹 시험장 웹페이지. DOM sink, attr/prop, jqXHR, 이벤트 바인딩 유형을 CASE별로 재현합니다.
- `hermes_testbench_data.json` — 시험장 HTML과 같은 데이터를 기계가 다시 읽기 쉬운 JSON으로 보존.
- `hermes_profile_patch.sample.json` — 검수 완료 후 `project-profile.json`에 옮길 수 있는 템플릿. 그대로 병합하지 말고 확인된 CASE만 복사합니다.
- `hermes_local_report.json` — 위 내용을 기계가 다시 읽기 쉬운 JSON으로 보존.

**learnedWrappers 스키마** (함수 하나의 지식을 모든 호출부에 전파)

```json
{
  "learnedWrappers": [
    { "name": "fnAjaxWrap", "role": "ajaxSuccessJson", "calleeParamIndex": 1, "notes": "AJAX 성공 콜백, 서버 JSON을 받음" },
    { "name": "renderCell", "role": "domSinkArg", "sinkParamIndex": 0, "notes": "내부적으로 .html() 사용하는 그리드 셀 렌더러" },
    { "name": "esc", "role": "safeWrapper", "notes": "HTML 이스케이프 헬퍼, 이 함수로 감싸면 안전" }
  ]
}
```

- `ajaxSuccessJson` — 이 함수의 콜백 인자(함수 표현식)의 첫 파라미터를 "서버에서 온 데이터"로 등록합니다. 이후 그 변수가 `.html()`/`.append()` 등에 들어가면 XssHigh로 재분류됩니다.
- `domSinkArg` — 이 함수 자체가 내부적으로 `.html()`을 쓰는 래퍼라고 등록합니다. 이후 이 함수의 모든 호출부가 `.html()` 호출처럼 스캔됩니다(정적 인자면 저위험, 동적/서버데이터면 XssHigh).
- `safeWrapper` — 이 함수로 감싼 값은 안전하다고 등록합니다. `.append(esc(response))`처럼 변수명 때문에 오탐(XssHigh)이 나던 코드가 정적/저위험으로 내려갑니다.

**learnedFindings 스키마** (특정 CASE 그룹 하나의 분류만 덮어씀)

```json
{
  "learnedFindings": [
    { "caseId": "PT-9f8e7d", "decision": "static-safe", "notes": "이 변수는 항상 고정 문자열만 옴" }
  ]
}
```

decision은 `xss-high` / `manual` / `review` / `static-safe` / `vendor-review` / `ignored` 중 하나입니다.

**안전 원칙 (중요)**: `learnedWrappers`/`learnedFindings`는 외부 AI의 "추정"을 반영하는 것이므로, **절대 자동수정(코드 변경)을 트리거하지 않습니다.** 오직 보고서의 분류(Priority/Reason)에만 영향을 줍니다. AI가 잘못 답해도 최악의 경우가 "사람이 한 번 더 확인해야 함"이지, "잘못된 코드가 자동 반영됨"이 아닙니다.

`--max-review-cases <n>`(기본 20), `--context-lines <n>`(기본 1), `--max-review-lines <n>`(기본 300)로 분량을 조절합니다.

## 8. Runtime Probe 사용법 (Edge IE mode 대응)

개발자도구가 막힌 환경을 위해 화면 안에서 로그를 봅니다.

1. `probe` 모드 실행 → TO-BE의 `js/jquery35-test-probe.js` 생성 + 레이아웃 JSP에 script 태그 삽입 (`probe_injection_map.csv`에 기록).
2. TO-BE를 배포/기동 후 화면 접속 → 우측 하단 **JQ35 배지** 클릭.
3. 패널에 jQuery/Migrate/UI 버전, jqGrid·select2·autoNumeric 감지 여부, JQMIGRATE 경고, JS 에러, AJAX 에러, 로드된 script 목록이 표시됩니다.
4. **Copy** 버튼으로 전체 로그 복사(`JQUERY35_RUNTIME_PROBE`로 시작) → 그대로 기록/공유.
5. Local Lab이 떠 있으면 **Send** 버튼이 `/__probe/log`로 전송해 `report\probeLogs\`에 저장됩니다.
6. **운영 반영 전 반드시 제거** — verify-clean이 잔존 시 FAIL을 냅니다.

Probe는 ES5 문법만 사용(화살표 함수/const/fetch 없음)해 IE mode에서도 동작합니다.

## 9. Local Lab 사용법과 한계

```
실행5_로컬랩서버.bat  →  http://localhost:18080/_pages
```

- TO-BE(없으면 원본) WebContent를 정적 서빙하고, JSP를 mock HTML로 변환해 보여줍니다 (include 인라인, `${js}` 등 경로 치환, JSTL 태그 제거).
- 모든 페이지에 Probe 자동 삽입, `.do` 요청에는 mock JSON/HTML 응답.
- 보고서도 `http://localhost:18080/_report/index.html` 로 볼 수 있습니다.

**한계 (중요):** Spring Controller 미실행, DB 조회 없음, 세션/권한 미재현, JSTL/Tiles 불완전 해석, 파일 업로드/RD viewer/ActiveX성 기능 불가.
목적은 오직 **jQuery 3.5+ 호환성 / script 로딩 / plugin 등록 / JQMIGRATE 경고 / JS 에러의 사전 확인**입니다. 최종 검증은 Eclipse/Tomcat.

### 9-1. Java/Spring 정적 증거와 mock route 보강

v5.4부터 `--source` 아래의 Java/XML을 가볍게 스캔합니다. Spring을 실행하지 않고 다음만 정적으로 읽습니다.

- `@RequestMapping`, `@GetMapping`, `@PostMapping` 등 Controller endpoint 후보
- `@ResponseBody`, `@RestController` 여부
- `@RequestParam`, `@PathVariable` 이름
- `context:component-scan`, `mvc:annotation-driven`, view resolver prefix/suffix 같은 XML 힌트

생성 파일:

- `serverEndpoints.csv` — Controller 후보 목록
- `serverEvidence.csv` — XML/Controller 클래스 증거
- `ajaxToServerMap.csv` — 프론트 AJAX URL과 Controller 후보 매핑
- `hermes_server_evidence.json` — 위 내용을 로컬 Hermes/검수팩에서 다시 읽기 쉬운 JSON

이 정보는 취약점 개수를 늘리거나 자동수정을 만들지 않습니다. 대신 `mock_routes.json`에 `handler`, `serverPath`, `evidence`, `confidence`를 붙여 Local Lab/mock 시험장의 신뢰도를 높입니다.

Java 소스 위치가 표준 구조가 아니면:

```bat
node run-jquery35-v5.js --source "C:\work\legacy-app" --report "C:\work\jquery35_report_v5" --mode plan --server-source "D:\src\legacy-server"
```

불필요하면 `--no-server-scan`을 붙이면 됩니다.

### 9-2. Runtime Parity Analyzer와 선택형 Runtime Lab

v5.6.5부터 정적 스캔/Local Lab/mock 결과를 그대로 “최종 검증 완료”로 보지 않고, 항목별로 필요한 검증 환경을 분리합니다.

- `LOCAL_LAB_OK` — 정적 변환 또는 단순 이벤트/API 치환처럼 mock/정적 검토만으로 비교적 신뢰 가능한 항목
- `SPRING_TOMCAT_REQUIRED` — AJAX, 서버 응답 DOM 삽입, 세션/권한/DB 결과, 실제 JSP include/Tiles 조합처럼 Spring/Tomcat 실 기동이 필요한 항목
- `IE_MODE_REQUIRED` — jqGrid/구형 벤더, ActiveX/RD viewer, iframe/window.open, file input, `attachEvent` 계열처럼 Windows Edge IE mode에서 최종 확인해야 하는 항목

생성 파일:

- `runtime_parity.html` — 검증 환경별 요약과 항목별 판정표
- `runtimeParity.csv` — finding 단위 판정 데이터
- `ieModeRisk.csv` — 페이지 단위 IE mode 위험 후보
- `runtime_lab_guide.md` — Codex/로컬 PC에서 WAR 실험을 할 때의 절차와 한계

`runtime-lab/` 폴더는 이 목적의 선택 템플릿입니다. TO-BE를 WAR로 export해 `runtime-lab/inbox/app.war`에 두고 Docker 또는 직접 Tomcat 7로 띄우는 방식입니다. 단, public ZIP은 계속 작게 유지하기 위해 템플릿만 포함하고, Docker 이미지/JDK/Tomcat/업무 WAR는 포함하지 않습니다.

Codex/로컬 PC에서 Spring 3.2.5 + Tomcat 7 자체가 뜨는지 먼저 확인하려면:

```sh
cd runtime-lab
./run-spring325-tomcat7-local.sh start
```

성공 기준은 `http://127.0.0.1:18089/health.do`가 `Spring 3.2.5.RELEASE`와 `Apache Tomcat/7.0.109`를 표시하는 것입니다. 다운로드/빌드 산출물은 `runtime-lab/.work/`와 `runtime-lab/inbox/app.war`에만 생성되며 Git에는 들어가지 않습니다.

Codex/macOS처럼 터미널 명령이 끝난 뒤에도 백그라운드로 유지해야 하면 `./run-spring325-tomcat7-local.sh screen-start`를 사용합니다.

## 10. 외부 AI에게 전달할 때 (코드 유출 없이)

CSV/Excel 파일을 외부로 넘길 수 없는 폐쇄망 상황에서는 `report\voyager_packet.txt` 하나만 통째로 복사/붙여넣기 하세요.
이 파일은 요약, 단계별 범위, 상위 Focus Queue, 런타임 수동 검증 시나리오, Runtime Parity 판정, selector/page 매칭, AJAX/서버 매핑, 다음 액션을 `KEY|field=value` 형식으로 압축합니다.

`report\assistant_packet.txt`는 기존 호환용 요약입니다. 기본값(`--safe-packet true`)에서는 소스코드 내용 없이 **파일경로:줄번호:유형:우선순위**와 통계만 들어갑니다.
짧은 코드 조각까지 허용하려면 `--include-snippets`를 붙이세요. 복붙 분량은 `--max-packet-lines 600` 식으로 조절합니다. 이 옵션은 `assistant_packet.txt`와 `voyager_packet.txt` 모두에 적용됩니다.
애매한 지점을 질문지로 학습시키고 싶으면 `ai_review_pack.txt`(7절)를 추가로 붙여넣습니다.

## 11. 자주 묻는 질문

**Q. autofix가 jQuery를 1.10.2에서 3.5.1로 바꿔주나요?**
아니요. AutoFixed는 1.10.2에서도 그대로 동작하는 선제 변경만 합니다. core 교체는 `patch-jquery` 모드에서 파일 존재 확인 후에만 수행합니다.

**Q. patch-jquery가 SKIP을 내요.**
TO-BE의 `WebContent\js\jquery-3.5.1.min.js` / `jquery-migrate-3.6.0.min.js`가 없기 때문입니다. 원본 `WebContent\js`에 두 파일을 넣고 다시 실행하세요(복사 시 TO-BE에도 들어갑니다). CDN 태그는 자동 교체하지 않고 MANUAL로 남깁니다.

**Q. 한글(EUC-KR) JSP가 깨지지 않나요?**
파일을 바이트 보존 방식(latin1 round-trip)으로 읽고 써서 비ASCII 바이트를 그대로 유지합니다. 새로 삽입되는 문자열은 ASCII로만 구성됩니다. (자체 테스트로 EUC-KR 바이트 보존을 검증했습니다.)

**Q. vendor 파일 안의 .bind는 왜 안 고치나요?**
라이브러리 내부 수정은 업그레이드 시 유실되고 회귀 위험이 큽니다. VendorReview로 분리해 호환성 테스트/버전 교체로 대응하세요.

**Q. jsSyntax FAIL이 떠요.**
Node 파서 기준 실패일 뿐 구형 IE 전용 문법일 수 있습니다. Manual로만 기록되며 실행이 중단되지 않습니다.

**Q. XSS는 어떻게 고치나요?**
단순 텍스트면 `.text(value)`, 구조 유지가 필요하면 아래 공통 함수를 만들어 `escapeHtml(value)`:
```js
function escapeHtml(v){ return String(v == null ? "" : v).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"); }
```
서버가 HTML 자체를 내려주는 구조면 신뢰 경계 확인 또는 서버측 sanitizer가 필요합니다.

**Q. review-pack에서 배운 지식(learnedWrappers)이 잘못되면 코드가 잘못 고쳐지나요?**
아닙니다. learnedWrappers/learnedFindings는 **분류(Priority/Reason)에만** 영향을 주고, 절대 `action:"Changed"`(자동수정)를 트리거하지 않습니다. AI 답변이 틀려도 최악의 경우는 "사람이 한 번 더 확인"이지 "잘못된 자동수정"이 아닙니다.

**Q. review_loop_progress.csv의 Round이 이상하게 늘어나요.**
같은 `--report` 폴더로 `review-pack`을 실행할 때마다 1씩 증가합니다. 새로 처음부터 시작하려면 `--report`에 새 폴더를 지정하거나 기존 `review_loop_progress.csv`를 지우세요. 소스가 이전 라운드와 달라지면(파일 크기/개수 변화) 경고가 뜹니다 — caseId가 편집된 파일에서 더 이상 같은 위치를 가리키지 않을 수 있다는 뜻이니, 그 라운드의 learnedFindings 답변은 다시 확인하세요.

**Q. Docker나 Tomcat을 폐쇄망에 같이 반입해야 하나요?**
아니요. 기본 배포본은 Node.js 단일 파일 중심입니다. `runtime-lab/`은 Codex/로컬 개발 PC에서 WAR 실험을 해보는 선택 스캐폴드이고, 사내망에 Docker 이미지/JDK/Tomcat을 새로 들여오라는 뜻이 아닙니다. 사내망에 이미 Spring/Tomcat이 있으면 그 실 기동 결과와 `runtime_parity.html`을 같이 보면 됩니다.

**Q. ai_review_pack.txt의 마스킹, 정말 안전한가요?**
v5.3 이후 실제 공개 전 다중 에이전트 적대적 검토 결과를 유지하면서, 기본 안착 버전을 jQuery 3.5.1로 맞추고 `$.trim` 같은 jQuery 4 대비 항목은 FocusQueue에서 제외했습니다. 문자열 리터럴(여러 줄에 걸친 템플릿 리터럴 포함), 줄/블록 주석, JSP `<%-- --%>` 주석, 정규식 리터럴 내용까지 전부 `<STR:...>`/`<COMMENT>`/`<REGEX>` placeholder로 치환됩니다. 그래도 100% 무결점을 보장하진 않으니, 처음 몇 번은 `ai_review_pack.txt`를 외부로 보내기 전에 직접 한 번 훑어보는 것을 권장합니다.

## 12. 산출물 목록 (report 폴더)

`index.html`(대시보드), `summary.csv`, `apiFindings.csv`, `findingCategorySummary.csv`, `directoryRiskSummary.csv`, `critical.csv`, `focusQueue.csv`, `manualQueue.csv`, `autoFixed.csv`, `vendorReview.csv`, `staticHtmlLow.csv`, `jqueryLoads.csv`, `scriptInventory.csv`, `pluginInventory.csv`, `directoryInventory.csv`, `jspPages.csv`, `jspIncludes.csv`, `pageScriptMap.csv`, `pageScriptEffective.csv`, `pageCssMap.csv`, `unresolvedRefs.csv`, `ajaxEndpoints.csv`, `serverEndpoints.csv`, `serverEvidence.csv`, `ajaxToServerMap.csv`, `uiElementInventory.csv`, `selectorElementMap.csv`, `runtimeScenarios.csv`, `runtime_scenarios.json`, `runtime_scenarios.html`, `runtimeParity.csv`, `ieModeRisk.csv`, `runtime_parity.html`, `runtime_lab_guide.md`, `hermes_server_evidence.json`, `jsSyntax.csv`, `completeByAutoFix.csv`, `needsWorkByFile.csv`, `changedFiles.csv`, `jquery35_report.xls`(Excel XML, npm 없이 생성), `assistant_packet.txt`, `voyager_packet.txt`, `chat_summary.txt`, `recommended_commits.txt`, `runtime_test_checklist.txt`, `mock_routes.json`, `mock_data_default.json`, `project-profile.sample.json`, `airgap_manifest.json`, `airgap_manifest.txt`, (pr-report 시) `pr_description.md`, `ci_checklist.md`, `bamboo_checklist.md`(하위호환), (probe 시) `probe_injection_map.csv`, (patch 시) `patch_jquery_result.txt`, (verify 시) `verify_clean_result.txt`, (review-pack/hermes-pack 시) `ai_review_pack.txt`, `ai_review_pack.json`, `hermes_test_plan.md`, `hermes_review_matrix.csv`, `hermes_testbench.html`, `hermes_testbench_data.json`, `hermes_profile_patch.sample.json`, `hermes_local_report.json`, `review_loop_progress.csv`

CSV는 전부 UTF-8 BOM이라 Excel에서 바로 열립니다.

## 13. 스캔 정확도에 대해 (v5의 개선점)

v5는 단순 정규식 스캔이 아니라 다음을 사용합니다.

1. **토큰 마스킹 스캐너** — 주석/문자열/정규식 리터럴을 길이 보존 방식으로 제거한 그림자 텍스트에서 탐지 → 주석 속 `.bind(`, 문자열 속 `$(window).load` 같은 오탐 제거 (라인 번호는 원본 그대로 유지).
2. **리시버 체인 역추적** — `$("#a").find("b").bind(...)`의 체인 루트가 `$`/`jQuery`인지 걸어 올라가 판단 → `fn.bind(this)` 같은 `Function.prototype.bind`는 건드리지 않음.
3. **괄호 균형 인자 파서** — DOM sink 인자를 정확히 잘라 정적 리터럴/객체/동적 조합을 구분.
4. **파일 내 taint-lite 추적** — `success: function(data)`의 콜백 파라미터를 오염원으로 등록하고, 그 변수가 `.html()`에 들어가면 이름과 무관하게 XssHigh로 승격.
5. **콜사이트 타입 추론(AutoInferred)** — 함수 파라미터로 넘어온 boolean attr 값을 전 프로젝트 호출부에서 역추적.
6. **콘텐츠 지문** — `jquery.js`처럼 버전이 파일명에 없으면 파일 배너에서 버전을 읽어 판별.
7. **학습형 래퍼 인식(v5.3, review-pack)** — 회사 전용 공통 함수(AJAX 래퍼/DOM 렌더러/이스케이프 헬퍼)는 정적분석만으로는 정체를 알 수 없는데, 외부 AI와의 스무고개 라운드를 거쳐 `learnedWrappers`로 등록하면 그 함수의 모든 호출부에 지식이 전파됩니다. 자세한 내용은 7절.
8. **서버 정적 증거(v5.4)** — Spring Controller/XML을 실행 없이 읽어 AJAX와 endpoint 후보를 연결하고, mock route와 Hermes 검수팩의 근거로 사용합니다.
9. **Runtime Parity Analyzer(v5.6.5)** — Local Lab/mock으로 충분한 항목과 Spring/Tomcat 실 기동 또는 Edge IE mode 확인이 필요한 항목을 나눠, 검증 병목을 줄이는 쪽으로 보고서를 재구성합니다.
