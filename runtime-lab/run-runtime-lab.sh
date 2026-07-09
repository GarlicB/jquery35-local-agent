#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"

if [ ! -f "inbox/app.war" ]; then
  echo "missing runtime-lab/inbox/app.war"
  echo "export the TO-BE application WAR and place it at runtime-lab/inbox/app.war"
  exit 2
fi

docker compose -f docker-compose.tomcat7.yml up
