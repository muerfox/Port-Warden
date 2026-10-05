#!/bin/sh
# Fix the data volume for the non-root app user, then drop privileges.
# When CAP_NET_ADMIN is present, keep it as an ambient capability so the
# local nft backend can install table inet port_warden on the host.
set -eu
mkdir -p /var/lib/port-warden/logs /var/lib/port-warden/snapshots /var/lib/port-warden/honeypot
chown -R portwarden:portwarden /var/lib/port-warden

if command -v setpriv >/dev/null 2>&1; then
  exec setpriv --reuid=10001 --regid=10001 --init-groups \
    --inh-caps=-all,+net_admin \
    --ambient-caps=+net_admin \
    -- "$@"
fi
exec runuser -u portwarden -- "$@"
