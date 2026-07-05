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

## 2. 이 도구가 하지 않는 일

- **원본 소스를 절대 직접 수정하지 않습니다.** 모든 변경은 `--target` TO-BE 폴더에만 기록됩니다.
- Critical(구버전 jQuery core 호출부)은 plan/autofix에서 탐지만 하고 **patch-jquery 모드에서만 교체**합니다.
- XssHigh(동적 DOM 삽입)는 **자동수정하지 않습니다.** 사람이 `.text()`/escapeHtml/신뢰경계 검토를 해야 합니다.
- 벤더 라이브러리(jqGrid/jquery-ui/select2/autoNumeric/*.min.js)는 **수정 대상에서 제외**하고 VendorReview로만 분류합니다.
- Local Lab은 Spring Controller/DB/세션/Tiles를 실행하지 않습니다. **최종 검증은 반드시 Eclipse/Tomcat 실 기동으로** 해야 합니다.

## 3. 설치

1. Node.js만 설치돼 있으면 됩니다 (LTS 아무 버전, npm install 불필요).
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
| `patch-jquery` | autofix + 구버전 jQuery script 태그를 3.7.1 + Migrate로 교체 | X | O |
| `probe` | autofix + Runtime Probe 생성/삽입 | X | O |
| `lab` | 로컬 mock 서버 기동 (기본 포트 18080) | X | X |
| `verify-clean` | 운영 반영 전 게이트 검사 (FAIL 시 exit 2) | X | X |
| `pr-report` | PR 설명/Bamboo 체크리스트/커밋 그룹 생성 | X | X |
| `packet` | assistant_packet.txt / chat_summary.txt만 생성 | X | X |
| `self-test` | 회사 코드 없이 도구 자체 정상동작 검증 (44개 체크) | X | X |

## 5. 판정 기준 (실무 기준)

- **Critical** — jQuery core 자체가 3.5 미만. CVE-2020-11023 조치의 핵심. patch-jquery 전까지 자동 교체하지 않음.
- **AutoFixed** — jQuery 1.10.2에서도 동작하고 3.5+에서도 맞는 **선제 변경**. `.bind→.on`, `.unbind→.off`, `.delegate→.on`, `.size()→.length`, `$(window).load→.on("load")`, boolean `.attr→.prop`, `.andSelf→.addBack`. 즉 jQuery 교체 전에 먼저 반영해도 안전합니다.
- **AutoFixed2** — `.attr("disabled", sts)` 같은 변수 인자를 **프로젝트 전체 호출부를 추적해 타입을 추론**한 뒤에만 자동수정. 예: 모든 호출부가 `"Y"/"N"`이면 `.prop("disabled", sts === "Y")`. 함수명 중복/호출부 타입 혼재 시 자동수정하지 않고 근거를 남깁니다.
- **Manual / Review** — `.success/.error/.complete`(AJAX냐 DOM이냐에 따라 권고 다름), `.live/.die`, 타입 불명 변수 등. 사람이 컨텍스트 확인 필요.
- **XssHigh** — `.html(response)`, `.append("<option>"+data[i]+...)` 등 동적 DOM 삽입. **jQuery 업그레이드와 별개로** DOM XSS 검토 필요. 자동수정 금지.
- **VendorReview** — jqGrid/jquery-ui/select2/autoNumeric 내부 코드. **직접 수정 금지.** Migrate 상태에서 화면 테스트하거나 호환 버전 교체를 검토하세요.
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
7.  jquery-3.7.1.min.js / jquery-migrate-3.6.0.min.js 를 WebContent\js 에 배치
    -> 실행3_jquery교체시도.bat  (mode patch-jquery, 커밋 그룹: JQUERY_CORE)
8.  로컬 Eclipse/Tomcat 기동
9.  실행4_프로브포함.bat 결과물로 화면에서 JQMIGRATE 경고/JS 에러 수집
    (Tomcat 없이 급하게 볼 때는 실행5_로컬랩서버.bat)
10. manualQueue.csv / focusQueue.csv 의 Manual/XssHigh 조치
11. 실행6_운영반영전검증.bat  (mode verify-clean) -> RESULT=PASS 확인
12. Bamboo branch build
13. PR 생성 (report\pr_description.md 활용)
```

## 7. Runtime Probe 사용법 (Edge IE mode 대응)

개발자도구가 막힌 환경을 위해 화면 안에서 로그를 봅니다.

1. `probe` 모드 실행 → TO-BE의 `js/jquery35-test-probe.js` 생성 + 레이아웃 JSP에 script 태그 삽입 (`probe_injection_map.csv`에 기록).
2. TO-BE를 배포/기동 후 화면 접속 → 우측 하단 **JQ35 배지** 클릭.
3. 패널에 jQuery/Migrate/UI 버전, jqGrid·select2·autoNumeric 감지 여부, JQMIGRATE 경고, JS 에러, AJAX 에러, 로드된 script 목록이 표시됩니다.
4. **Copy** 버튼으로 전체 로그 복사(`JQUERY35_RUNTIME_PROBE`로 시작) → 그대로 기록/공유.
5. Local Lab이 떠 있으면 **Send** 버튼이 `/__probe/log`로 전송해 `report\probeLogs\`에 저장됩니다.
6. **운영 반영 전 반드시 제거** — verify-clean이 잔존 시 FAIL을 냅니다.

Probe는 ES5 문법만 사용(화살표 함수/const/fetch 없음)해 IE mode에서도 동작합니다.

## 8. Local Lab 사용법과 한계

```
실행5_로컬랩서버.bat  →  http://localhost:18080/_pages
```

- TO-BE(없으면 원본) WebContent를 정적 서빙하고, JSP를 mock HTML로 변환해 보여줍니다 (include 인라인, `${js}` 등 경로 치환, JSTL 태그 제거).
- 모든 페이지에 Probe 자동 삽입, `.do` 요청에는 mock JSON/HTML 응답.
- 보고서도 `http://localhost:18080/_report/index.html` 로 볼 수 있습니다.

**한계 (중요):** Spring Controller 미실행, DB 조회 없음, 세션/권한 미재현, JSTL/Tiles 불완전 해석, 파일 업로드/RD viewer/ActiveX성 기능 불가.
목적은 오직 **jQuery 3.5+ 호환성 / script 로딩 / plugin 등록 / JQMIGRATE 경고 / JS 에러의 사전 확인**입니다. 최종 검증은 Eclipse/Tomcat.

## 9. 외부 AI에게 전달할 때 (코드 유출 없이)

`report\assistant_packet.txt` 만 복사해서 전달하면 됩니다.
기본값(`--safe-packet true`)에서는 소스코드 내용 없이 **파일경로:줄번호:유형:우선순위**와 통계만 들어갑니다.
짧은 코드 조각까지 허용하려면 `--include-snippets`를 붙이세요. 분량은 `--max-packet-lines 600` 식으로 조절합니다.

## 10. 자주 묻는 질문

**Q. autofix가 jQuery를 1.10.2에서 3.7.1로 바꿔주나요?**
아니요. AutoFixed는 1.10.2에서도 그대로 동작하는 선제 변경만 합니다. core 교체는 `patch-jquery` 모드에서 파일 존재 확인 후에만 수행합니다.

**Q. patch-jquery가 SKIP을 내요.**
TO-BE의 `WebContent\js\jquery-3.7.1.min.js` / `jquery-migrate-3.6.0.min.js`가 없기 때문입니다. 원본 `WebContent\js`에 두 파일을 넣고 다시 실행하세요(복사 시 TO-BE에도 들어갑니다). CDN 태그는 자동 교체하지 않고 MANUAL로 남깁니다.

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

## 11. 산출물 목록 (report 폴더)

`index.html`(대시보드), `summary.csv`, `apiFindings.csv`, `critical.csv`, `focusQueue.csv`, `manualQueue.csv`, `autoFixed.csv`, `vendorReview.csv`, `staticHtmlLow.csv`, `jqueryLoads.csv`, `scriptInventory.csv`, `pluginInventory.csv`, `directoryInventory.csv`, `jspPages.csv`, `jspIncludes.csv`, `pageScriptMap.csv`, `pageScriptEffective.csv`, `pageCssMap.csv`, `unresolvedRefs.csv`, `ajaxEndpoints.csv`, `jsSyntax.csv`, `completeByAutoFix.csv`, `needsWorkByFile.csv`, `changedFiles.csv`, `jquery35_report.xls`(Excel XML, npm 없이 생성), `assistant_packet.txt`, `chat_summary.txt`, `recommended_commits.txt`, `runtime_test_checklist.txt`, `mock_routes.json`, `mock_data_default.json`, `project-profile.sample.json`, (pr-report 시) `pr_description.md`, `bamboo_checklist.md`, (probe 시) `probe_injection_map.csv`, (patch 시) `patch_jquery_result.txt`, (verify 시) `verify_clean_result.txt`

CSV는 전부 UTF-8 BOM이라 Excel에서 바로 열립니다.

## 12. 스캔 정확도에 대해 (v5의 개선점)

v5는 단순 정규식 스캔이 아니라 다음을 사용합니다.

1. **토큰 마스킹 스캐너** — 주석/문자열/정규식 리터럴을 길이 보존 방식으로 제거한 그림자 텍스트에서 탐지 → 주석 속 `.bind(`, 문자열 속 `$(window).load` 같은 오탐 제거 (라인 번호는 원본 그대로 유지).
2. **리시버 체인 역추적** — `$("#a").find("b").bind(...)`의 체인 루트가 `$`/`jQuery`인지 걸어 올라가 판단 → `fn.bind(this)` 같은 `Function.prototype.bind`는 건드리지 않음.
3. **괄호 균형 인자 파서** — DOM sink 인자를 정확히 잘라 정적 리터럴/객체/동적 조합을 구분.
4. **파일 내 taint-lite 추적** — `success: function(data)`의 콜백 파라미터를 오염원으로 등록하고, 그 변수가 `.html()`에 들어가면 이름과 무관하게 XssHigh로 승격.
5. **콜사이트 타입 추론(AutoFixed2)** — 함수 파라미터로 넘어온 boolean attr 값을 전 프로젝트 호출부에서 역추적.
6. **콘텐츠 지문** — `jquery.js`처럼 버전이 파일명에 없으면 파일 배너에서 버전을 읽어 판별.
