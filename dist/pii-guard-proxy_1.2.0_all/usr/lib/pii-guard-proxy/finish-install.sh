#!/bin/sh
# Deferred-install helper. Run as a transient systemd service from postinst
# (via `systemd-run --no-block`) so it has no parent-process relationship
# with dpkg — that's the only way dpkg can return immediately while we
# still wait for its lock to release.
#
# Args:
#   $1 — space-separated list of apt packages to install (may be empty)
#   $2 — optional user whose Chrome NSS DB should receive the CA
#   $3 — set to "hybrid" to also fetch the GLiNER PII Small ONNX model
#        + transformers.js dependency for the hybrid detection mode
#
# This script is "best-effort" everywhere — it never aborts. If something
# fails, it logs and continues so downstream steps still run.

cd /

LOG=/var/log/pii-guard-finish-install.log
echo "" >>"$LOG"
echo "[$(date '+%F %T')] finish-install starting (apt: $1, user: ${2:-none}, ml: ${3:-none})" >>"$LOG"
exec >>"$LOG" 2>&1

# 1. Wait for dpkg / apt locks to release.
i=0
while [ "$i" -lt 300 ]; do
  if ! fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
    && ! fuser /var/lib/dpkg/lock >/dev/null 2>&1 \
    && ! fuser /var/lib/apt/lists/lock >/dev/null 2>&1; then
    break
  fi
  i=$((i + 1))
  sleep 2
done
echo "[$(date '+%F %T')] Lock released after ~$((i*2))s, proceeding."

# 2. Install missing apt packages (best-effort).
if [ -n "$1" ]; then
  DEBIAN_FRONTEND=noninteractive apt-get update -q \
    || echo "[$(date '+%F %T')] apt-get update failed (continuing)"
  if DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends $1; then
    echo "[$(date '+%F %T')] Installed: $1"
  else
    echo "[$(date '+%F %T')] WARNING: failed to install: $1 (continuing)"
  fi
fi

# 3. Generate CA if it wasn't created in postinst (e.g. node wasn't there).
if [ ! -f /etc/pii-guard/ca-cert.pem ] && command -v node >/dev/null 2>&1; then
  echo "[$(date '+%F %T')] Generating CA..."
  PII_GUARD_CA_DIR=/etc/pii-guard /usr/bin/node -e \
    "require('/usr/lib/pii-guard-proxy/lib/cert-manager').ensureCa()" \
    || echo "[$(date '+%F %T')] CA generation failed"
  if [ -f /etc/pii-guard/ca-cert.pem ]; then
    chown pii-guard:pii-guard /etc/pii-guard/ca-cert.pem /etc/pii-guard/ca-key.pem 2>/dev/null
    chmod 0644 /etc/pii-guard/ca-cert.pem 2>/dev/null
    chmod 0600 /etc/pii-guard/ca-key.pem 2>/dev/null
  fi
fi

# 4. Make sure the system trust store has it.
if [ -f /etc/pii-guard/ca-cert.pem ] \
   && [ ! -f /usr/local/share/ca-certificates/pii-guard.crt ]; then
  install -m 0644 /etc/pii-guard/ca-cert.pem \
    /usr/local/share/ca-certificates/pii-guard.crt \
    && update-ca-certificates >/dev/null 2>&1
fi

# 5. If hybrid detection was selected, fetch transformers.js + the
#    GLiNER PII Small ONNX weights into /var/lib/pii-guard/models/.
#    Done BEFORE the service restart so the proxy picks up the model
#    on its first start. install-ml.sh is itself best-effort — if
#    download fails, the proxy falls back to regex-only and the user
#    can re-run via `sudo pii-guard ml-enable`.
if [ "$3" = "hybrid" ] && [ -x /usr/lib/pii-guard-proxy/install-ml.sh ]; then
  echo "[$(date '+%F %T')] Hybrid detection requested — installing ML stack..."
  /usr/lib/pii-guard-proxy/install-ml.sh \
    || echo "[$(date '+%F %T')] ML install reported failure (proxy will run regex-only)"
fi

# 6. Restart the service.
systemctl daemon-reload >/dev/null 2>&1
systemctl restart pii-guard-proxy.service \
  || echo "[$(date '+%F %T')] Service restart failed — see journalctl -u pii-guard-proxy"

# 7. Add CA to every real user's Chrome NSS DB.
#    We iterate /home/* instead of relying on a single user argument because
#    SUDO_USER is unreliable (can be empty, or 'root' if the install was run
#    from a root login shell). Browsers run as the desktop user(s), so we
#    trust the CA for each of them.
if command -v certutil >/dev/null 2>&1; then
  # Briefly close any running Chromium-family browser so the NSS DB isn't
  # locked while certutil writes. The user will reopen them after.
  pkill -TERM -f '/opt/google/chrome'  >/dev/null 2>&1 || true
  pkill -TERM -f '/usr/lib/chromium'   >/dev/null 2>&1 || true
  pkill -TERM -f '/opt/brave.com'      >/dev/null 2>&1 || true
  pkill -TERM -f '/opt/microsoft/msedge' >/dev/null 2>&1 || true
  sleep 1

  HANDLED=""
  add_for_user() {
    case " $HANDLED " in *" $1 "*) return ;; esac
    HANDLED="$HANDLED $1"
    echo "[$(date '+%F %T')] Adding CA to $1's Chrome NSS DB..."
    if su - "$1" -c /usr/bin/pii-guard-trust-chrome >/dev/null 2>&1; then
      echo "  done."
    else
      echo "  failed (rerun 'pii-guard-trust-chrome' as $1 with Chrome closed)"
    fi
  }

  # Try the explicit user argument first (if a useful one was passed).
  if [ -n "$2" ] && [ "$2" != "root" ] && id "$2" >/dev/null 2>&1; then
    add_for_user "$2"
  fi

  # Then sweep /home/* for any other user that has a desktop session.
  for home in /home/*; do
    [ -d "$home" ] || continue
    user=$(basename "$home")
    id "$user" >/dev/null 2>&1 || continue
    add_for_user "$user"
  done

  if [ -z "$HANDLED" ]; then
    echo "[$(date '+%F %T')] No suitable user found — run 'pii-guard-trust-chrome' as your desktop user."
  fi
else
  echo "[$(date '+%F %T')] certutil not available — Chrome NSS trust skipped."
  echo "  install libnss3-tools then run 'pii-guard-trust-chrome' as your desktop user."
fi

echo "[$(date '+%F %T')] finish-install complete."
