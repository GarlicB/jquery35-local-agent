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

  cat > "$WAR_DIR/index.html" <<'EOF'
<!doctype html>
<html>
<head><meta charset="UTF-8"><title>Spring 3.2.5 Tomcat 7 Lab</title></head>
<body>
  <h1>Spring 3.2.5 + Tomcat 7 Local Lab</h1>
  <ul>
    <li><a href="health.do">Spring MVC health.do</a></li>
  </ul>
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
    out.println("<html><head><meta charset=\"UTF-8\"><title>Spring 3.2.5 Health</title></head><body>");
    out.println("<h1>Spring MVC is running</h1>");
    out.println("<dl>");
    out.println("<dt>Spring</dt><dd>3.2.5.RELEASE</dd>");
    out.println("<dt>Servlet container</dt><dd>" + request.getServletContext().getServerInfo() + "</dd>");
    out.println("<dt>Java</dt><dd>" + System.getProperty("java.version") + "</dd>");
    out.println("<dt>Request URI</dt><dd>" + request.getRequestURI() + "</dd>");
    out.println("</dl>");
    out.println("</body></html>");
    return null;
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
  if [ -f "$PID_FILE" ]; then
    old_pid=$(cat "$PID_FILE" 2>/dev/null || true)
    if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
      log "stop existing Tomcat pid=$old_pid"
      JAVA_HOME=$(choose_java_home)
      export JAVA_HOME CATALINA_HOME="$TOMCAT_HOME" CATALINA_BASE="$CATALINA_BASE_DIR" CATALINA_PID="$PID_FILE"
      "$TOMCAT_HOME/bin/catalina.sh" stop 10 -force >/dev/null 2>&1 || true
    fi
    rm -f "$PID_FILE"
  fi
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
    ;;
  clean)
    stop_tomcat || true
    rm -rf "$WORK_DIR"
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
    echo "usage: $0 [start|stop|clean]" >&2
    exit 2
    ;;
esac
