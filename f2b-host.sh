#!/bin/sh
# Ruft fail2ban-client im Host-Namespace auf (Komodo/Docker).
set -eu
if command -v nsenter >/dev/null 2>&1; then
  exec nsenter --target 1 --mount --uts --ipc --net -- /usr/bin/fail2ban-client "$@"
fi
echo "nsenter fehlt – fail2ban nicht erreichbar" >&2
exit 1
