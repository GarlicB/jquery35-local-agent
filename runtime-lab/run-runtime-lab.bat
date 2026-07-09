@echo off
setlocal
cd /d "%~dp0"

if not exist "inbox\app.war" (
  echo missing runtime-lab\inbox\app.war
  echo export the TO-BE application WAR and place it at runtime-lab\inbox\app.war
  exit /b 2
)

docker compose -f docker-compose.tomcat7.yml up
