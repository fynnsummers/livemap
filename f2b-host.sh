#!/bin/sh
# Spricht den Fail2ban-Socket im Container an. Kein nsenter, kein Host-Namespace.
set -eu
exec /usr/bin/fail2ban-client "$@"
