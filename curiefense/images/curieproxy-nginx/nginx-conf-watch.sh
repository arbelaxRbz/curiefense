#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
  set -o xtrace
fi

echo "watch-customconf: Blindly calling reload script at start"
/usr/local/bin/nginx-conf-reload.sh &

confarchive=/cf-config/current/config/customconf.tar.gz

while true
do
  if [ -f "$confarchive" ]; then
    file_age=$(($(date +%s) - $(date +%s -r "$confarchive")))
    echo "watch-customconf: File age in sec: $file_age"
    if (( file_age < 20 ));
    then
      echo "watch-customconf: New copy of $confarchive found. calling reload script."
      /usr/local/bin/nginx-conf-reload.sh &
    fi
  else
      echo "watch-customconf: ${confarchive} missing" >&2
  fi
  sleep 20;
done
