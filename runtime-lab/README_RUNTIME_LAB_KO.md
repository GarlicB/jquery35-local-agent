# Runtime Lab 선택팩

이 폴더는 사내망 반입용 본체가 아니라, Codex/로컬 개발 PC에서 Spring 3.2.x + Tomcat 7 계열 실험을 해보기 위한 선택형 템플릿입니다.

## 원칙

- Docker image, JDK, Tomcat, Maven, 업무 WAR는 포함하지 않습니다.
- 본체 도구는 계속 Node.js 단일 파일 중심의 작은 배포를 유지합니다.
- 여기서 얻은 결과는 `runtime_parity.html`, `runtimeParity.csv`, `ieModeRisk.csv`, `voyager_packet.txt` 판단을 보강하는 용도입니다.
- Edge IE mode 렌더링은 Windows Edge에서만 최종 확인 가능합니다.

## Docker 방식

준비:

1. TO-BE 소스를 Eclipse/빌드 도구로 WAR로 export합니다.
2. WAR 파일을 `runtime-lab/inbox/app.war`로 둡니다.
3. Docker Desktop이 실행 중인지 확인합니다.

실행:

```sh
cd runtime-lab
docker compose -f docker-compose.tomcat7.yml up
```

접속:

```text
http://127.0.0.1:18089/
```

종료:

```sh
docker compose -f docker-compose.tomcat7.yml down
```

## JDK/Tomcat 직접 방식

Docker가 없으면 JDK 8과 Tomcat 7을 직접 설치한 뒤 WAR를 Tomcat `webapps/ROOT.war`에 배치해도 됩니다.

이 방식이 더 정확한 경우:

- 회사 PC에 이미 JDK 8/Tomcat 7/Eclipse가 있음
- Docker 보안승인이 어려움
- 운영과 같은 JVM 옵션, 인코딩, system property를 맞춰야 함

## 결과 회수

1. Runtime Probe가 들어간 TO-BE를 띄웁니다.
2. 화면 우측 하단 `JQ35` 배지 클릭
3. `Copy`로 로그 복사
4. `voyager_packet.txt`와 함께 Codex에 붙여넣기

## 한계

- JEUS/WebtoB, 세션/SSO, DB, 파일스토리지, WebtoB SSL termination은 Tomcat Docker로 완전 재현되지 않습니다.
- Mac arm64에서는 `tomcat:7.0.109-jdk8-openjdk`가 `linux/amd64` 에뮬레이션으로 실행될 수 있어 느릴 수 있습니다.
- IE mode 브라우저 차이는 이 폴더에서 재현하지 않습니다. `ieModeRisk.csv`의 IE 대상은 Windows Edge IE mode에서 확인하세요.
