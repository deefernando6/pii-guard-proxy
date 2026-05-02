#!/bin/bash
# Wipes every trace of pii-guard-proxy. Safe to run repeatedly.
set -u

echo "→ stopping any deferred-install or service still running..."
pkill -f /usr/lib/pii-guard-proxy/finish-install.sh 2>/dev/null
systemctl stop pii-guard-finish-install.service 2>/dev/null
systemctl reset-failed pii-guard-finish-install.service 2>/dev/null
systemctl stop pii-guard-proxy.service 2>/dev/null

echo "→ purging dpkg state..."
dpkg --purge --force-all pii-guard-proxy 2>/dev/null
dpkg --configure -a 2>/dev/null

echo "→ removing files..."
rm -rf /etc/pii-guard
rm -f  /etc/profile.d/pii-guard-claude-code.sh
rm -f  /etc/profile.d/pii-guard-https-proxy.sh
rm -f  /etc/opt/chrome/policies/managed/pii-guard.json
rm -f  /etc/chromium/policies/managed/pii-guard.json
rm -f  /etc/brave/policies/managed/pii-guard.json
rm -f  /etc/opt/edge/policies/managed/pii-guard.json
rm -f  /usr/local/share/ca-certificates/pii-guard.crt
rm -rf /usr/lib/pii-guard-proxy
rm -f  /var/log/pii-guard-finish-install.log
rm -f  /lib/systemd/system/pii-guard-proxy.service
rm -f  /etc/systemd/system/pii-guard-proxy.service
rm -f  /etc/default/pii-guard-proxy
rm -f  /usr/bin/pii-guard-proxy /usr/bin/pii-guard-trust-chrome

echo "→ refreshing system trust store..."
update-ca-certificates --fresh >/dev/null 2>&1

echo "→ dropping service user..."
deluser pii-guard 2>/dev/null

echo "→ reloading systemd..."
systemctl daemon-reload 2>/dev/null

echo
echo "Done. Verification:"
dpkg -l pii-guard-proxy 2>&1 | tail -1
echo -n "  port 8765: " ; ss -ltn 2>/dev/null | grep -q ':8765 ' && echo "STILL UP" || echo "free"
echo -n "  /etc/pii-guard: " ; [ -e /etc/pii-guard ] && echo "STILL EXISTS" || echo "gone"
echo -n "  pii-guard user: " ; getent passwd pii-guard >/dev/null && echo "STILL EXISTS" || echo "gone"
echo -n "  Chrome policy: " ; [ -e /etc/opt/chrome/policies/managed/pii-guard.json ] && echo "STILL EXISTS" || echo "gone"
