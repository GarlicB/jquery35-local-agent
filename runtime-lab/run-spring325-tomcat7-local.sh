#!/usr/bin/env sh
set -eu

BASE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORK_DIR="$BASE_DIR/.work"
TOOLS_DIR="$WORK_DIR/tools"
TOMCAT_VERSION="7.0.109"
SPRING_VERSION="3.2.5.RELEASE"
PORT="${PORT:-18089}"
TOMCAT_NAME="apache-tomcat-$TOMCAT_VERSION"
TOMCAT_HOME="$TOOLS_DIR/$TOMCAT_NAME"
TOMCAT_TGZ="$TOOLS_DIR/$TOMCAT_NAME.tar.gz"
CATALINA_BASE_DIR="$WORK_DIR/tomcat-base"
WAR_DIR="$WORK_DIR/spring325-demo-war"
WAR_FILE="$BASE_DIR/inbox/app.war"
PID_FILE="$WORK_DIR/tomcat.pid"

log() {
  printf '[runtime-lab] %s\n' "$*"
}

choose_java_home() {
  if [ -n "${JAVA_HOME:-}" ] && [ -x "$JAVA_HOME/bin/java" ]; then
    printf '%s\n' "$JAVA_HOME"
    return
  fi
  if command -v /usr/libexec/java_home >/dev/null 2>&1; then
    /usr/libexec/java_home -v 17 2>/dev/null && return
    /usr/libexec/java_home 2>/dev/null && return
  fi
  return 1
}

download() {
  url="$1"
  out="$2"
  if [ -f "$out" ]; then
    return
  fi
  log "download $(basename "$out")"
  curl -fL --retry 3 --connect-timeout 20 -o "$out" "$url"
}

download_jar() {
  group="$1"
  artifact="$2"
  version="$3"
  dest_dir="$4"
  group_path=$(printf '%s' "$group" | tr '.' '/')
  dest="$dest_dir/$artifact-$version.jar"
  download "https://repo.maven.apache.org/maven2/$group_path/$artifact/$version/$artifact-$version.jar" "$dest"
}

prepare_tomcat() {
  mkdir -p "$TOOLS_DIR"
  download "https://archive.apache.org/dist/tomcat/tomcat-7/v$TOMCAT_VERSION/bin/$TOMCAT_NAME.tar.gz" "$TOMCAT_TGZ"
  if [ ! -x "$TOMCAT_HOME/bin/catalina.sh" ]; then
    log "extract $TOMCAT_NAME"
    tar -xzf "$TOMCAT_TGZ" -C "$TOOLS_DIR"
    chmod +x "$TOMCAT_HOME/bin/"*.sh
  fi
}

build_demo_war() {
  rm -rf "$WAR_DIR"
  mkdir -p "$WAR_DIR/WEB-INF/lib" "$WAR_DIR/WEB-INF/classes" "$WAR_DIR/WEB-INF/src/lab"
  download_jar org.springframework spring-core "$SPRING_VERSION" "$WAR_DIR/WEB-INF/lib"
  download_jar org.springframework spring-beans "$SPRING_VERSION" "$WAR_DIR/WEB-INF/lib"
  download_jar org.springframework spring-context "$SPRING_VERSION" "$WAR_DIR/WEB-INF/lib"
  download_jar org.springframework spring-expression "$SPRING_VERSION" "$WAR_DIR/WEB-INF/lib"
  download_jar org.springframework spring-aop "$SPRING_VERSION" "$WAR_DIR/WEB-INF/lib"
  download_jar org.springframework spring-web "$SPRING_VERSION" "$WAR_DIR/WEB-INF/lib"
  download_jar org.springframework spring-webmvc "$SPRING_VERSION" "$WAR_DIR/WEB-INF/lib"
  download_jar commons-logging commons-logging 1.1.3 "$WAR_DIR/WEB-INF/lib"
  download_jar aopalliance aopalliance 1.0 "$WAR_DIR/WEB-INF/lib"

  cat > "$WAR_DIR/lab.css" <<'EOF'
:root {
  color-scheme: light;
  --bg: #f5f7fb;
  --panel: #ffffff;
  --ink: #172033;
  --muted: #657386;
  --line: #d9e0eb;
  --accent: #146c94;
  --ok: #0f7a5f;
  --warn-bg: #fff8e8;
  --warn-line: #d49b2f;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  min-height: 100vh;
  background: var(--bg);
  color: var(--ink);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
}

.shell {
  width: min(960px, calc(100% - 40px));
  margin: 0 auto;
  padding: 44px 0;
}

.hero {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 24px;
  padding-bottom: 24px;
  margin-bottom: 24px;
  border-bottom: 1px solid var(--line);
}

.eyebrow {
  margin: 0 0 8px;
  color: var(--accent);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0;
  text-transform: uppercase;
}

h1 {
  margin: 0;
  font-size: 34px;
  line-height: 1.16;
  letter-spacing: 0;
}

h2 {
  margin: 0 0 16px;
  font-size: 19px;
  letter-spacing: 0;
}

.lede {
  max-width: 720px;
  margin: 14px 0 0;
  color: var(--muted);
  font-size: 15px;
  line-height: 1.6;
}

.status {
  display: inline-flex;
  align-items: center;
  min-height: 32px;
  padding: 0 12px;
  border: 1px solid rgba(15, 122, 95, 0.24);
  border-radius: 999px;
  background: rgba(15, 122, 95, 0.1);
  color: var(--ok);
  font-size: 12px;
  font-weight: 700;
  white-space: nowrap;
}

.panel {
  padding: 22px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel);
  box-shadow: 0 12px 34px rgba(31, 44, 65, 0.08);
}

.panel + .panel {
  margin-top: 16px;
}

.fact-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}

.fact {
  min-width: 0;
  padding-top: 10px;
  border-top: 2px solid #e6ebf3;
}

.fact span {
  display: block;
  color: var(--muted);
  font-size: 12px;
  line-height: 1.4;
}

.fact strong {
  display: block;
  margin-top: 5px;
  font-size: 16px;
  line-height: 1.35;
  overflow-wrap: anywhere;
}

.action-row {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 38px;
  padding: 0 14px;
  border: 1px solid var(--accent);
  border-radius: 7px;
  background: var(--accent);
  color: #fff;
  font-size: 14px;
  font-weight: 700;
  text-decoration: none;
}

.button.secondary {
  background: #fff;
  color: var(--accent);
}

.check-list {
  display: grid;
  gap: 9px;
  margin: 16px 0 0;
  padding-left: 20px;
  color: var(--muted);
  line-height: 1.5;
}

.note {
  margin: 18px 0 0;
  padding: 13px 14px;
  border-left: 4px solid var(--warn-line);
  border-radius: 6px;
  background: var(--warn-bg);
  color: #5c471e;
  font-size: 14px;
  line-height: 1.5;
}

@media (max-width: 640px) {
  .shell {
    width: calc(100% - 24px);
    padding: 28px 0;
  }

  .hero {
    display: block;
  }

  .status {
    margin-top: 16px;
  }

  h1 {
    font-size: 28px;
  }

  .fact-grid {
    grid-template-columns: 1fr;
  }
}
EOF

  cat > "$WAR_DIR/index.html" <<'EOF'
<!doctype html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Spring 3.2.5 Tomcat 7 Lab</title>
  <link rel="stylesheet" href="lab.css">
</head>
<body>
  <main class="shell">
    <section class="hero">
      <div>
        <p class="eyebrow">Runtime parity smoke</p>
        <h1>Spring 3.2.5 + Tomcat 7 Local Lab</h1>
        <p class="lede">Project-local WAR is deployed on Tomcat 7. Use this page to prove that the servlet container and Spring MVC route are alive before testing real TO-BE pages.</p>
      </div>
      <span class="status">READY</span>
    </section>

    <section class="panel">
      <h2>Checks</h2>
      <div class="action-row">
        <a class="button" href="health.do">Open Spring MVC health</a>
      </div>
      <ul class="check-list">
        <li>Tomcat and Spring jars are loaded from runtime-lab/.work.</li>
        <li>No JSP compiler is required for this smoke check.</li>
        <li>Business WAR/JSP compatibility still needs the target JDK/WAS run.</li>
      </ul>
    </section>
  </main>
</body>
</html>
EOF

  cat > "$WAR_DIR/WEB-INF/src/lab/HealthController.java" <<'EOF'
package lab;

import java.io.PrintWriter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;

public class HealthController implements Controller {
  public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
    response.setCharacterEncoding("UTF-8");
    response.setContentType("text/html; charset=UTF-8");
    PrintWriter out = response.getWriter();
    out.println("<!doctype html>");
    out.println("<html><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Spring 3.2.5 Health</title><link rel=\"stylesheet\" href=\"/lab.css\"></head><body>");
    out.println("<main class=\"shell\">");
    out.println("<section class=\"hero\"><div><p class=\"eyebrow\">Runtime parity smoke</p><h1>Spring MVC is running</h1><p class=\"lede\">This response is produced by a Spring MVC Controller inside the Tomcat 7 WAR.</p></div><span class=\"status\">RUNNING</span></section>");
    out.println("<section class=\"panel\"><h2>Runtime facts</h2><div class=\"fact-grid\">");
    writeFact(out, "Spring", "3.2.5.RELEASE");
    writeFact(out, "Servlet container", request.getServletContext().getServerInfo());
    writeFact(out, "Java", System.getProperty("java.version"));
    writeFact(out, "Request URI", request.getRequestURI());
    out.println("</div><p class=\"note\">JSP compilation is intentionally bypassed in this smoke because Tomcat 7's old JSP compiler can fail under newer JDK class formats. Test business JSPs on the company JDK/WAS path.</p></section>");
    out.println("<section class=\"panel\"><h2>Navigation</h2><div class=\"action-row\"><a class=\"button\" href=\"/\">Open lab index</a><a class=\"button secondary\" href=\"/health.do\">Reload health</a></div></section>");
    out.println("</main>");
    out.println("</body></html>");
    return null;
  }

  private void writeFact(PrintWriter out, String label, String value) {
    out.println("<div class=\"fact\"><span>" + escape(label) + "</span><strong>" + escape(value) + "</strong></div>");
  }

  private String escape(String value) {
    if (value == null) {
      return "";
    }
    return value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;");
  }
}
EOF

  cat > "$WAR_DIR/WEB-INF/web.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://java.sun.com/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd"
         version="3.0">
  <display-name>spring325-demo</display-name>

  <context-param>
    <param-name>contextConfigLocation</param-name>
    <param-value>/WEB-INF/root-context.xml</param-value>
  </context-param>

  <listener>
    <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
  </listener>

  <servlet>
    <servlet-name>spring</servlet-name>
    <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
    <init-param>
      <param-name>contextConfigLocation</param-name>
      <param-value>/WEB-INF/spring-servlet.xml</param-value>
    </init-param>
    <load-on-startup>1</load-on-startup>
  </servlet>

  <servlet-mapping>
    <servlet-name>spring</servlet-name>
    <url-pattern>*.do</url-pattern>
  </servlet-mapping>
</web-app>
EOF

  cat > "$WAR_DIR/WEB-INF/root-context.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-3.2.xsd">
</beans>
EOF

  cat > "$WAR_DIR/WEB-INF/spring-servlet.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans-3.2.xsd">

  <bean class="org.springframework.web.servlet.handler.SimpleUrlHandlerMapping">
    <property name="urlMap">
      <map>
        <entry key="/health.do" value-ref="healthController"/>
      </map>
    </property>
  </bean>

  <bean id="healthController" class="lab.HealthController"/>
</beans>
EOF

  build_java_home=$(choose_java_home)
  "$build_java_home/bin/javac" --release 8 -encoding UTF-8 \
    -cp "$WAR_DIR/WEB-INF/lib/*:$TOMCAT_HOME/lib/servlet-api.jar" \
    -d "$WAR_DIR/WEB-INF/classes" \
    "$WAR_DIR/WEB-INF/src/lab/HealthController.java"

  mkdir -p "$BASE_DIR/inbox"
  (cd "$WAR_DIR" && jar cf "$WAR_FILE" .)
  log "WAR built: $WAR_FILE"
}

write_tomcat_base() {
  rm -rf "$CATALINA_BASE_DIR"
  mkdir -p "$CATALINA_BASE_DIR"
  cp -R "$TOMCAT_HOME/conf" "$CATALINA_BASE_DIR/conf"
  mkdir -p "$CATALINA_BASE_DIR/bin" "$CATALINA_BASE_DIR/logs" "$CATALINA_BASE_DIR/temp" "$CATALINA_BASE_DIR/webapps" "$CATALINA_BASE_DIR/work"
  cp "$WAR_FILE" "$CATALINA_BASE_DIR/webapps/ROOT.war"
  python3 - "$CATALINA_BASE_DIR/conf/server.xml" "$PORT" <<'PY'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
port = sys.argv[2]
s = p.read_text()
s = s.replace('port="8005"', 'port="-1"', 1)
s = s.replace('port="8080"', f'port="{port}"', 1)
p.write_text(s)
PY
  cat > "$CATALINA_BASE_DIR/bin/setenv.sh" <<'EOF'
JAVA_OPTS="$JAVA_OPTS -Dfile.encoding=UTF-8 -Djava.awt.headless=true"
JAVA_OPTS="$JAVA_OPTS --add-opens=java.base/java.lang=ALL-UNNAMED"
JAVA_OPTS="$JAVA_OPTS --add-opens=java.base/java.io=ALL-UNNAMED"
JAVA_OPTS="$JAVA_OPTS --add-opens=java.base/java.util=ALL-UNNAMED"
EOF
  chmod +x "$CATALINA_BASE_DIR/bin/setenv.sh"
}

stop_tomcat() {
  pids=""
  if [ -f "$PID_FILE" ]; then
    pids="$pids $(cat "$PID_FILE" 2>/dev/null || true)"
  fi
  found_pids=$(ps -axo pid=,command= 2>/dev/null | awk -v base="$CATALINA_BASE_DIR" 'index($0, base) && index($0, "org.apache.catalina.startup.Bootstrap") { print $1 }' || true)
  pids=$(printf '%s\n%s\n' "$pids" "$found_pids" | tr ' ' '\n' | awk 'NF && !seen[$1]++ { print $1 }')
  if [ -n "$pids" ]; then
    for old_pid in $pids; do
      if kill -0 "$old_pid" 2>/dev/null; then
        log "stop existing Tomcat pid=$old_pid"
        kill "$old_pid" 2>/dev/null || true
      fi
    done
    sleep 1
    for old_pid in $pids; do
      if kill -0 "$old_pid" 2>/dev/null; then
        log "force stop Tomcat pid=$old_pid"
        kill -9 "$old_pid" 2>/dev/null || true
      fi
    done
  fi
  rm -f "$PID_FILE"
}

start_tomcat() {
  JAVA_HOME=$(choose_java_home)
  export JAVA_HOME
  export CATALINA_HOME="$TOMCAT_HOME"
  export CATALINA_BASE="$CATALINA_BASE_DIR"
  export CATALINA_PID="$PID_FILE"
  log "JAVA_HOME=$JAVA_HOME"
  log "CATALINA_HOME=$CATALINA_HOME"
  log "CATALINA_BASE=$CATALINA_BASE"
  "$TOMCAT_HOME/bin/catalina.sh" start
}

run_tomcat() {
  JAVA_HOME=$(choose_java_home)
  export JAVA_HOME
  export CATALINA_HOME="$TOMCAT_HOME"
  export CATALINA_BASE="$CATALINA_BASE_DIR"
  export CATALINA_PID="$PID_FILE"
  log "JAVA_HOME=$JAVA_HOME"
  log "CATALINA_HOME=$CATALINA_HOME"
  log "CATALINA_BASE=$CATALINA_BASE"
  exec "$TOMCAT_HOME/bin/catalina.sh" run
}

stop_screen_session() {
  if command -v screen >/dev/null 2>&1; then
    session="${SCREEN_NAME:-jq35spring325}"
    screen -S "$session" -X quit >/dev/null 2>&1 || true
  fi
}

start_screen_session() {
  if ! command -v screen >/dev/null 2>&1; then
    log "screen command not found"
    return 1
  fi
  session="${SCREEN_NAME:-jq35spring325}"
  screen -S "$session" -X quit >/dev/null 2>&1 || true
  log "screen session=$session"
  screen -dmS "$session" env PORT="$PORT" "$BASE_DIR/run-spring325-tomcat7-local.sh" run
}

wait_for_health() {
  url="http://127.0.0.1:$PORT/health.do"
  i=0
  while [ "$i" -lt 40 ]; do
    if curl -fsS "$url" >/tmp/jq35-spring325-health.html 2>/dev/null; then
      log "PASS $url"
      sed -n '1,80p' /tmp/jq35-spring325-health.html
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  log "FAIL $url"
  log "tail catalina log:"
  tail -120 "$CATALINA_BASE_DIR/logs/catalina.out" 2>/dev/null || true
  return 1
}

case "${1:-start}" in
  stop)
    prepare_tomcat
    stop_tomcat
    stop_screen_session
    ;;
  clean)
    stop_tomcat || true
    stop_screen_session
    rm -rf "$WORK_DIR"
    ;;
  run)
    prepare_tomcat
    build_demo_war
    write_tomcat_base
    stop_tomcat || true
    run_tomcat
    ;;
  screen-start)
    prepare_tomcat
    stop_tomcat || true
    stop_screen_session
    start_screen_session
    wait_for_health
    ;;
  start|"")
    prepare_tomcat
    build_demo_war
    write_tomcat_base
    stop_tomcat || true
    start_tomcat
    wait_for_health
    ;;
  *)
    echo "usage: $0 [start|stop|clean|run|screen-start]" >&2
    exit 2
    ;;
esac
