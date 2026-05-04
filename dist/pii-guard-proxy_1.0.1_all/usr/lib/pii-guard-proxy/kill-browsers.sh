#!/bin/sh
# SIGTERM running Chromium-family browsers so they pick up a freshly-
# applied (or freshly-removed) managed policy on next launch. Only
# invoked from postinst / postrm — install and remove/purge — so the
# user's Chrome windows aren't yanked closed every time the proxy
# service cycles or the CLI changes a runtime setting.
#
# Honours PII_GUARD_KILL_BROWSERS_ON_POLICY_CHANGE in /etc/default/
# pii-guard-proxy: set it to false to suppress the kill on install
# and remove/purge as well.

set -eu
cd /

[ -r /etc/default/pii-guard-proxy ] && . /etc/default/pii-guard-proxy
KILL_BROWSERS="${PII_GUARD_KILL_BROWSERS_ON_POLICY_CHANGE:-true}"

case "$KILL_BROWSERS" in
  false|0|no|off|FALSE|False) exit 0 ;;
esac

pkill -TERM -f '/opt/google/chrome'    >/dev/null 2>&1 || true
pkill -TERM -f '/usr/lib/chromium'     >/dev/null 2>&1 || true
pkill -TERM -f '/opt/brave.com'        >/dev/null 2>&1 || true
pkill -TERM -f '/opt/microsoft/msedge' >/dev/null 2>&1 || true

exit 0
