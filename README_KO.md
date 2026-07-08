# jquery35-local-agent v5 — jQuery CVE-2020-11023 조치 자동화 킷

폐쇄망 로컬 PC에서 **Node.js 하나만으로** 동작하는 레거시 Java/Spring/JSP 프론트엔드 취약점 조치 도구입니다.
npm install 불필요, 인터넷 불필요, 외부 모듈 0개(Node 내장 모듈만 사용).

---

## 1. 이 도구가 하는 일

- `WebContent` 전체 구조 분석 (JSP/JS/CSS/리소스 인벤토리)
- `WEB-INF/views` + `WEB-INF/layouts` JSP의 script/css/include 호출관계 분석
- JSP include를 따라가며 **페이지별 실제 로드되는(effective) 스크립트 목록** 재구성
- jQuery 1.10.2 등 **3.5.0 미만 core 호출부 전수 탐지 (Critical, CVE-2020-11023 핵심)**
- jQuery Migrate 누락 / core 중복 로드 / migrate 로드 순서 리스크 탐지
- 제거·변경된 jQuery API 위험 구문 정적분석 (`.bind` `.live` `.size` `.attr(bool)` `.success` 등)
- **안전한 것만** 자동수정하여 원본은 그대로 두고 **TO-BE 폴더에 동일 구조로 생성**
- DOM XSS 후보(`.html(response)` 등) 위험도 분류 (XssHigh / Review / StaticHtmlLow)
- CSV 21종 + Excel(.xls) + index.html 대시보드 + assistant_packet.txt 보고서 생성
- Edge IE mode용 **Runtime Probe** (개발자도구 없이 화면에서 JQMIGRATE 경고/JS 에러 수집)
- Tomcat 없이 프론트 JS를 미리 확인하는 **Local Lab mock 서버**
- 운영 반영 전 게이트 **verify-clean** (구버전 jQuery/Probe 잔존 시 FAIL)
- **AI 리뷰팩(review-pack)** — 애매한 코드 지점만 골라 함수명/앞뒤 몇 줄(문자열은 마스킹)만 담은 질문지를 생성해 외부 AI와 반복 학습하는 스무고개 루프 (7절 참고)

## 2. 이 도구가 하지 않는 일

- **원본 소스를 절대 직접 수정하지 않습니다.** 모든 변경은 `--target` TO-BE 폴더에만 기록됩니다.
- Critical(구버전 jQuery core 호출부)은 plan/autofix에서 탐지만 하고 **patch-jquery 모드에서만 교체**합니다.
- XssHigh(동적 DOM 삽입)는 **자동수정하지 않습니다.** 사람이 `.text()`/escapeHtml/신뢰경계 검토를 해야 합니다.
- 벤더 라이브러리(jqGrid/jquery-ui/select2/autoNumeric/*.min.js)는 **수정 대상에서 제외**하고 VendorReview로만 분류합니다.
- Local Lab은 Spring Controller/DB/세션/Tiles를 실행하지 않습니다. **최종 검증은 반드시 Eclipse/Tomcat 실 기동으로** 해야 합니다.

## 3. 설치

1. Node.js만 설치돼 있으면 됩니다 (Node.js 16+ 최소, 18+ 권장, npm install 불필요).
2. 이 폴더를 아무 경로에나 복사합니다 (예: `C:\tools\jquery35-local-agent-v5`).
3. 배치파일 상단의 경로 3개를 내 환경에 맞게 수정합니다.

기본 예시 경로:

| 용도 | 경로 |
|---|---|
| 원본(source) | `C:\work\legacy-app` |
| TO-BE(target) | `C:\work\legacy-app_jquery35_tobe` |
| 보고서(report) | `C:\work\jquery35_report_v5` |

`--source`에는 프로젝트 루트(`C:\work\legacy-app`)를 줘도 되고 `C:\work\legacy-app\WebContent`를 직접 줘도 됩니다. WebContent는 자동 감지됩니다.

## 4. 모드 설명

| 모드 | 하는 일 | 원본 수정 | TO-BE 생성 |
|---|---|---|---|
| `plan` | 분석만. **처음엔 반드시 이것부터** | X | X |
| `autofix` | 안전 자동수정만 TO-BE에 적용 | X | O |
| `patch-jquery` | autofix + 구버전 jQuery script 태그를 3.5.1 + Migrate로 교체 | X | O |
| `probe` | autofix + Runtime Probe 생성/삽입 | X | O |
| `lab` | 로컬 mock 서버 기동 (기본 포트 18080) | X | X |
| `verify-clean` | 운영 반영 전 게이트 검사 (FAIL 시 exit 2) | X | X |
| `pr-report` | PR 설명/Bamboo 체크리스트/커밋 그룹 생성 | X | X |
| `packet` | assistant_packet.txt / chat_summary.txt만 생성 | X | X |
| `review-pack` | plan + ai_review_pack.txt/json 생성 (7절 AI 리뷰팩 참고) | X | X |
| `self-test` | 회사 코드 없이 도구 자체 정상동작 검증 (70개 체크) | X | X |

## 5. 판정 기준 (실무 기준)

- **Critical** — jQuery core 자체가 3.5 미만. CVE-2020-11023 조치의 핵심. patch-jquery 전까지 자동 교체하지 않음.
- **AutoFixed** — jQuery 1.10.2에서도 동작하고 3.5+에서도 맞는 **선제 변경**. `.bind→.on`, `.unbind→.off`, `.delegate→.on`, `.size()→.length`, `$(window).load→.on("load")`, boolean `.attr→.prop`, `.andSelf→.addBack`, 그리고 정적 HTML 문자열 안의 자기닫힘 태그 확장(`"<div/>..."` → `"<div></div>..."`, jQuery 3.5 보안픽스로 동작이 바뀌는 지점 — 상세는 VENDOR_COMPAT_KO.md). 즉 jQuery 교체 전에 먼저 반영해도 안전합니다. `$.trim`처럼 jQuery 3.x에서 계속 동작하고 jQuery 4에서 제거될 항목은 5.3부터 FocusQueue가 아니라 저위험/후순위로 분리합니다.
- **AutoInferred** — 기존 `AutoFixed2`의 명칭을 바꾼 것입니다. `.attr("disabled", sts)` 같은 변수 인자를 **프로젝트 전체 호출부를 추적해 타입을 추론**한 뒤에만 자동수정합니다. 예: 모든 호출부가 `"Y"/"N"`이면 `.prop("disabled", sts === "Y")`. 함수명 중복/호출부 타입 혼재 시 자동수정하지 않고 근거를 남깁니다.
- **Manual / Review** — `.success/.error/.complete`(AJAX냐 DOM이냐에 따라 권고 다름), `.live/.die`, 타입 불명 변수 등. 사람이 컨텍스트 확인 필요.
- **XssHigh** — `.html(response)`, `.append("<option>"+data[i]+...)` 등 동적 DOM 삽입. **jQuery 업그레이드와 별개로** DOM XSS 검토 필요. 자동수정 금지.
- **VendorReview** — jqGrid/jquery-ui/select2/autoNumeric 내부 코드. **직접 수정 금지.** Migrate 상태에서 화면 테스트하거나 호환 버전 교체를 검토하세요. 라이브러리별 호환 버전과 자체 CVE 정리는 **VENDOR_COMPAT_KO.md** 참고 (특히 jQuery UI ≤1.12.1은 자체 CVE 때문에 core 업그레이드만으로 스캐너를 통과하지 못할 수 있음).
- **StaticHtmlLow** — `.append("<option value=''>선택</option>")` 같은 정적 문자열. 저위험, 보통 조치 불필요.

특이 케이스: `.attr("disabled","false")`는 구버전 jQuery에서 **오히려 비활성화**시키는 코드였기 때문에 `.prop(...,false)`로 기계 변환하면 동작이 뒤집힙니다. 이런 건 Manual로 분류하고 이유를 적어둡니다.

## 6. 권장 작업 플로우 (Bitbucket/Bamboo)

```
1.  git checkout -b fix/jquery-cve-2020-11023
2.  실행1_분석만.bat  (mode plan)
3.  report\index.html 열어서 현황 파악, assistant_packet.txt 확인
4.  실행2_TO_BE_자동수정.bat  (mode autofix)
5.  TO-BE와 원본을 WinMerge / Eclipse Compare / git diff 로 비교
6.  안전 자동수정만 브랜치에 반영 (커밋 그룹: AUTO_SAFE)
7.  jquery-3.5.1.min.js / jquery-migrate-3.6.0.min.js 를 WebContent\js 에 배치
    -> 실행3_jquery교체시도.bat  (mode patch-jquery, 커밋 그룹: JQUERY_CORE)
    - Probe/테스트 단계에서 JQMIGRATE 경고를 자세히 보고 싶으면 `project-profile.json`의 `jquery.newMigrateSrc`를 `/js/jquery-migrate-3.6.0.js` 같은 개발 빌드 경로로 지정하고, 운영 후보에서는 `.min.js`로 되돌리세요.
    - 사내 가이드처럼 stack trace까지 봐야 하면 `--migrate-trace`를 추가하세요. 이 옵션은 Migrate script 바로 아래에 `jQuery.migrateTrace = true; jQuery.migrateMute = false;`를 삽입합니다.
8.  로컬 Eclipse/Tomcat 기동
9.  실행4_프로브포함.bat 결과물로 화면에서 JQMIGRATE 경고/JS 에러 수집
    (Tomcat 없이 급하게 볼 때는 실행5_로컬랩서버.bat)
10. manualQueue.csv / focusQueue.csv 의 Manual/XssHigh 조치
11. 실행6_운영반영전검증.bat  (mode verify-clean) -> RESULT=PASS 확인
12. Bamboo branch build
13. PR 생성 (report\pr_description.md 활용)
```

## 7. AI 리뷰팩 — 스무고개 방식 반복 학습 루프 (review-pack)

폐쇄망이라 원본 코드를 외부 AI에게 통째로 보여줄 수 없지만, **애매하게 분류된 코드 지점만 골라 함수명/앞뒤 몇 줄만** 반복적으로 물어보면 전체 코드를 몰라도 조치 정확도를 라운드마다 끌어올릴 수 있습니다. 특히 레거시 코드에는 `fnAjaxWrap`, `gridBind`, `commonEscape` 같은 "한 번 정의되고 수백 곳에서 호출되는 공통 함수"가 있는데, 이런 함수 하나의 역할만 알아내면 그 지식이 호출부 전체에 한번에 퍼집니다.

**동작 원리**

1. `review-pack` 모드를 실행하면 애매한 코드 그룹(Review/Manual/저신뢰 XssHigh 등) 중 **호출부 수(FanOut) × 우선순위**로 가중치를 매겨 상위 N개(기본 20개)만 골라 `report\ai_review_pack.txt`와 `.json`을 생성합니다.
2. 각 CASE는 파일 전체가 아니라 **함수명/패턴명 + 앞뒤 몇 줄(기본 1줄)** 만 담고, 문자열 리터럴 내용은 `<STR:short/med/long>`으로 대체되어 실제 값이 노출되지 않습니다.
3. `ai_review_pack.txt`를 외부 AI(ChatGPT/Claude 등)에게 그대로 붙여넣습니다. 파일 맨 아래 **ANSWER_JSON** 형식에 맞춰 AI가 JSON으로 답을 만들어 줍니다.
4. 그 JSON을 `project-profile.json`의 `learnedWrappers`/`learnedFindings` 배열에 병합합니다.
5. 같은 `--report` 폴더로 `review-pack`(또는 `plan`)을 다시 실행하면, 학습된 지식이 반영되어 애매한 큐가 줄어들고 `review_loop_progress.csv`에 라운드별 진행 상황이 누적됩니다. 이 2~5단계를 몇 차례 반복합니다.

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

## 10. 외부 AI에게 전달할 때 (코드 유출 없이)

전체 현황 요약만 필요하면 `report\assistant_packet.txt`, 애매한 지점을 짚어 학습시키고 싶으면 `ai_review_pack.txt`(7절)를 전달하세요.
assistant_packet은 기본값(`--safe-packet true`)에서 소스코드 내용 없이 **파일경로:줄번호:유형:우선순위**와 통계만 들어갑니다.
짧은 코드 조각까지 허용하려면 `--include-snippets`를 붙이세요. 분량은 `--max-packet-lines 600` 식으로 조절합니다.

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

**Q. ai_review_pack.txt의 마스킹, 정말 안전한가요?**
v5.3에서 실제 공개 전 다중 에이전트 적대적 검토 결과를 유지하면서, 기본 안착 버전을 jQuery 3.5.1로 맞추고 `$.trim` 같은 jQuery 4 대비 항목은 FocusQueue에서 제외했습니다. 문자열 리터럴(여러 줄에 걸친 템플릿 리터럴 포함), 줄/블록 주석, JSP `<%-- --%>` 주석, 정규식 리터럴 내용까지 전부 `<STR:...>`/`<COMMENT>`/`<REGEX>` placeholder로 치환됩니다. 그래도 100% 무결점을 보장하진 않으니, 처음 몇 번은 `ai_review_pack.txt`를 외부로 보내기 전에 직접 한 번 훑어보는 것을 권장합니다.

## 12. 산출물 목록 (report 폴더)

`index.html`(대시보드), `summary.csv`, `apiFindings.csv`, `critical.csv`, `focusQueue.csv`, `manualQueue.csv`, `autoFixed.csv`, `vendorReview.csv`, `staticHtmlLow.csv`, `jqueryLoads.csv`, `scriptInventory.csv`, `pluginInventory.csv`, `directoryInventory.csv`, `jspPages.csv`, `jspIncludes.csv`, `pageScriptMap.csv`, `pageScriptEffective.csv`, `pageCssMap.csv`, `unresolvedRefs.csv`, `ajaxEndpoints.csv`, `jsSyntax.csv`, `completeByAutoFix.csv`, `needsWorkByFile.csv`, `changedFiles.csv`, `jquery35_report.xls`(Excel XML, npm 없이 생성), `assistant_packet.txt`, `chat_summary.txt`, `recommended_commits.txt`, `runtime_test_checklist.txt`, `mock_routes.json`, `mock_data_default.json`, `project-profile.sample.json`, (pr-report 시) `pr_description.md`, `bamboo_checklist.md`, (probe 시) `probe_injection_map.csv`, (patch 시) `patch_jquery_result.txt`, (verify 시) `verify_clean_result.txt`, (review-pack 시) `ai_review_pack.txt`, `ai_review_pack.json`, `review_loop_progress.csv`

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
