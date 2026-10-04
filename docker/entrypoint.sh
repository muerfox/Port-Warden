#!/bin/sh
# Fix the data volume for the non-root app user, then drop privileges.
set -eu
mkdir -p /var/lib/port-warden/logs /var/lib/port-warden/snapshots /var/lib/port-warden/honeypot
chown -R portwarden:portwarden /var/lib/port-warden
exec runuser -u portwarden -- "$@"
