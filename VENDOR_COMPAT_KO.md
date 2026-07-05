# jQuery 3.5+ 업그레이드 — 벤더 라이브러리 호환성 브리프

이 문서는 웹 조사(2026-07 기준) 결과를 정리한 것입니다. 도구의 `pluginInventory.csv` 권고문과 같은 근거를 공유합니다.
결론부터: **jQuery core만 3.7.1로 올려도 벤더 쪽에서 두 가지가 남습니다 — ① jQuery UI 자체 CVE, ② jqGrid 세대 교체.**

## 요약 표

| 라이브러리 | jQuery 3.x에서 상태 | 권장 조치 |
|---|---|---|
| jQuery UI ≤ 1.12.1 | 동작 여부와 무관하게 **자체 CVE 보유** (CVE-2021-41182/41183/41184 datepicker XSS, CVE-2022-31160) → 보안 스캐너가 별도로 잡음 | **1.13.2+ 로 교체** (jQuery 3.x 공식 지원). 1.10.x는 jQuery 3 미지원 세대 |
| jqGrid (trirand 4.x 클래식) | jQuery 3 이전 세대. `.bind/.andSelf/.size` 등 의존 → Migrate로 연명 가능하나 미보증 | **free-jqGrid 4.15.x 또는 유지보수 포크(jQuery 3.x 지원)**, 상용이면 **Guriddo jqGrid 5.5.4+**(jQuery 3.5 공식 지원). 교체 전까지는 Migrate 상태로 전 기능 테스트 |
| select2 | 4.0.5는 jQuery 3에서 focus/멀티선택 버그 보고, **4.0.8+에서 수정** | 4.x면 4.0.8+(권장 4.0.13) 확인. 3.5.x 라인이면 교체 검토 |
| autoNumeric | 구 1.x도 jQuery 3.1에서 동작 보고됨. v4+는 jQuery 무관 스탠드얼론 | 낮은 리스크. 금액입력/콤마/blur/저장값/readonly 테스트로 확인 |

## 반드시 알아야 할 동작 변화 2가지 (Migrate가 못 덮는 것)

**1) 자기닫힘 태그 (jQuery 3.5의 보안픽스 그 자체)**
CVE-2020-11023 픽스로 `htmlPrefilter`가 더 이상 `<div/>`를 `<div></div>`로 확장하지 않습니다.
`$("#x").append("<div/><span>a</span>")` 같은 코드는 3.5부터 **span이 div의 형제가 아니라 자식이 되어** 레이아웃이 조용히 틀어집니다.
Migrate는 이걸 기본 복원하지 않습니다(복원 = 취약점 재도입이므로 `migrateEnablePatches("self-closed-tags")` 명시 호출 필요 — 사용 금지 권장).
→ **본 도구 v5.1이 `self-closed-tag` 카테고리로 탐지하며, 정적 문자열은 `<div></div>` 형태로 자동수정(AutoFixed)합니다.** 이 수정은 구/신 jQuery 양쪽에서 동일하게 동작합니다.

**2) `$(document).ready()` 비동기화 (jQuery 3.0)**
3.0부터 ready 핸들러가 비동기로 실행되어, 인라인 스크립트와 ready 콜백의 실행 순서에 기대던 코드는 순서가 바뀔 수 있습니다. 정적분석으로 못 잡는 항목이라 **화면 테스트에서 "초기값이 안 채워짐" 류 증상이 나오면 이걸 의심**하세요.

## Migrate 3.x가 복원해주는 것 (경고 내면서)

`.size()`, `.andSelf()`, jqXHR의 `.success/.error/.complete`, `$.trim` 등 3.0에서 제거된 API 다수 — 그래서 구형 jqGrid도 Migrate 아래에서 "일단 도는" 경우가 많습니다. 단 이는 연명이지 완치가 아니며, JQMIGRATE 경고 목록이 곧 기술부채 목록입니다.
주의: 1.9에서 제거된 API(`.live()`, `$.browser`)는 Migrate 3.x가 복원하지 **않습니다**. 현재 1.10.2에서 돌고 있다면 그 절벽은 이미 지난 상태라 걱정 대상이 아닙니다.

## 참고 자료

- jQuery Core 3.5 Upgrade Guide (htmlPrefilter 변경): https://jquery.com/upgrade-guide/3.5/
- jQuery Core 3.0 Upgrade Guide (제거 API, ready 비동기): https://jquery.com/upgrade-guide/3.0/
- jQuery Migrate (복원/경고 목록): https://github.com/jquery/jquery-migrate
- jQuery UI 1.13 Upgrade Guide: https://jqueryui.com/upgrade-guide/1.13/
- jQuery UI 1.12.1 CVE 정리 (Broadcom KB): https://knowledge.broadcom.com/external/article/280539/
- free-jqGrid (MIT/GPL 포크): https://github.com/free-jqgrid/jqGrid / 유지보수 포크: https://github.com/rany2/jqGrid
- Guriddo jqGrid 5.5.4 (jQuery 3.5 지원 릴리스): https://guriddo.net/?cat=21
- select2 릴리스 노트 (4.0.8 jQuery 3 호환 수정): https://github.com/select2/select2/releases
- autoNumeric jQuery 3 이슈 리포트: https://github.com/autoNumeric/autoNumeric/issues/240
