#!/bin/sh
# Toggle every pii-guard-proxy config artifact in lock-step with the
# systemd service. Called from ExecStartPost / ExecStopPost so the
# user's environment never points at a dead proxy.
#
#   apply   — for each *-mode-enabled marker that exists, materialise
#             the corresponding config (profile.d env-var file for
#             claude-code / https-proxy, JSON policy file for browser).
#   revert  — remove every config artifact, regardless of marker state.
#             After this the system behaves as if pii-guard-proxy was
#             never installed (until apply runs again on next start).
#
# This script intentionally NEVER kills browsers. Earlier versions did,
# which meant `systemctl stop pii-guard-proxy`,
# `pii-guard placeholder-replace enable`, and `pii-guard reconfigure`
# all closed the user's Chrome windows (because each one triggers a
# service restart that fires apply/revert). Browser termination now
# only runs from postinst/postrm — install and remove/purge — via
# /usr/lib/pii-guard-proxy/kill-browsers.sh.
#
# Trade-off: when the service is stopped without restarting Chrome,
# Chrome keeps its cached managed-policy until a manual restart, so
# routing through the dead proxy will fail until then. That's a much
# better UX than losing tabs every time the service cycles.

set -eu
cd /

CONFIG_DIR=/etc/pii-guard

# Markers: existence indicates "user wants this mode active"
MARKER_CLAUDE_CODE="$CONFIG_DIR/claude-code-mode-enabled"
MARKER_HTTPS_PROXY="$CONFIG_DIR/https-proxy-mode-enabled"
MARKER_BROWSER="$CONFIG_DIR/browser-mode-enabled"

# Artifacts: created on apply, removed on revert
PROFILE_CLAUDE_CODE=/etc/profile.d/pii-guard-claude-code.sh
PROFILE_HTTPS_PROXY=/etc/profile.d/pii-guard-https-proxy.sh
ZSH_HOOK_FILE=/etc/pii-guard/pii-guard-hook.zsh
ZSH_RC=/etc/zsh/zshrc
POLICY_DIRS="
/etc/chromium/policies/managed
/etc/opt/chrome/policies/managed
/etc/brave/policies/managed
/etc/opt/edge/policies/managed
"

write_profile_claude_code() {
  cat > "$1" <<'PROFILE'
# Installed by pii-guard-proxy. Dynamically sets/unsets ANTHROPIC_BASE_URL
# before every shell prompt so the env var stays in sync with the proxy
# service state — no need to open a new terminal when the service starts
# or stops.
_pii_guard_cc_check() {
  if systemctl is-active --quiet pii-guard-proxy 2>/dev/null; then
    export ANTHROPIC_BASE_URL="http://127.0.0.1:8765"
  else
    unset ANTHROPIC_BASE_URL
  fi
}
_pii_guard_cc_check
if [ -n "${BASH_VERSION:-}" ]; then
  PROMPT_COMMAND="${PROMPT_COMMAND:+${PROMPT_COMMAND%;}; }_pii_guard_cc_check"
elif [ -n "${ZSH_VERSION:-}" ]; then
  autoload -Uz add-zsh-hook 2>/dev/null || true
  add-zsh-hook precmd _pii_guard_cc_check 2>/dev/null || true
fi
PROFILE
  chmod 0644 "$1"
}

write_profile_https_proxy() {
  cat > "$1" <<'PROFILE'
# Installed by pii-guard-proxy. Dynamically sets/unsets HTTPS_PROXY etc.
# before every shell prompt so the env vars stay in sync with the proxy
# service state — no need to open a new terminal when the service starts
# or stops.
_pii_guard_hp_check() {
  if systemctl is-active --quiet pii-guard-proxy 2>/dev/null; then
    export HTTPS_PROXY="http://127.0.0.1:8765"
    export HTTP_PROXY="http://127.0.0.1:8765"
    export NO_PROXY="localhost,127.0.0.1,::1"
    export NODE_EXTRA_CA_CERTS="/usr/local/share/ca-certificates/pii-guard.crt"
  else
    unset HTTPS_PROXY HTTP_PROXY NO_PROXY NODE_EXTRA_CA_CERTS
  fi
}
_pii_guard_hp_check
if [ -n "${BASH_VERSION:-}" ]; then
  PROMPT_COMMAND="${PROMPT_COMMAND:+${PROMPT_COMMAND%;}; }_pii_guard_hp_check"
elif [ -n "${ZSH_VERSION:-}" ]; then
  autoload -Uz add-zsh-hook 2>/dev/null || true
  add-zsh-hook precmd _pii_guard_hp_check 2>/dev/null || true
fi
PROFILE
  chmod 0644 "$1"
}

POLICY_JSON='{
  "ProxyMode": "fixed_servers",
  "ProxyServer": "127.0.0.1:8765",
  "ProxyBypassList": "<-loopback>;localhost",
  "QuicAllowed": false
}'

# Write /etc/pii-guard/pii-guard-hook.zsh with native-zsh precmd hooks
# for all active modes, then ensure /etc/zsh/zshrc sources it.
# profile.d covers bash (and zsh login shells), but most terminals open
# non-login interactive zsh shells that never source /etc/profile.d —
# the zshrc mechanism covers those.
write_zsh_hooks() {
  # Build the hook file from active modes
  {
    printf '# Managed by pii-guard-proxy. Do not edit.\n'
    if [ -f "$MARKER_CLAUDE_CODE" ]; then
      cat <<'ZSH_CC'
_pii_guard_cc_check() {
  if systemctl is-active --quiet pii-guard-proxy 2>/dev/null; then
    export ANTHROPIC_BASE_URL="http://127.0.0.1:8765"
  else
    unset ANTHROPIC_BASE_URL
  fi
}
_pii_guard_cc_check
typeset -gaU precmd_functions
precmd_functions+=(_pii_guard_cc_check)
ZSH_CC
    fi
    if [ -f "$MARKER_HTTPS_PROXY" ]; then
      cat <<'ZSH_HP'
_pii_guard_hp_check() {
  if systemctl is-active --quiet pii-guard-proxy 2>/dev/null; then
    export HTTPS_PROXY="http://127.0.0.1:8765"
    export HTTP_PROXY="http://127.0.0.1:8765"
    export NO_PROXY="localhost,127.0.0.1,::1"
    export NODE_EXTRA_CA_CERTS="/usr/local/share/ca-certificates/pii-guard.crt"
  else
    unset HTTPS_PROXY HTTP_PROXY NO_PROXY NODE_EXTRA_CA_CERTS
  fi
}
_pii_guard_hp_check
typeset -gaU precmd_functions
precmd_functions+=(_pii_guard_hp_check)
ZSH_HP
    fi
  } > "$ZSH_HOOK_FILE"
  chmod 0644 "$ZSH_HOOK_FILE"

  # Inject a sourcing line into /etc/zsh/zshrc if not already present.
  # The marker comment is the anchor used for removal on uninstall.
  if [ -f "$ZSH_RC" ] && ! grep -q "pii-guard-proxy" "$ZSH_RC" 2>/dev/null; then
    printf '\n# pii-guard-proxy: dynamic ANTHROPIC_BASE_URL / HTTPS_PROXY per-prompt\n[[ -f %s ]] && source %s # pii-guard-proxy\n' \
      "$ZSH_HOOK_FILE" "$ZSH_HOOK_FILE" >> "$ZSH_RC"
  fi
}

remove_zsh_hooks() {
  # Remove our injected lines from /etc/zsh/zshrc
  if [ -f "$ZSH_RC" ]; then
    grep -v "pii-guard-proxy" "$ZSH_RC" > "${ZSH_RC}.pii-guard-tmp" \
      && mv "${ZSH_RC}.pii-guard-tmp" "$ZSH_RC" || rm -f "${ZSH_RC}.pii-guard-tmp"
  fi
  rm -f "$ZSH_HOOK_FILE"
}

apply() {
  changed=0

  # claude-code: ANTHROPIC_BASE_URL (always rewrite so hook is up-to-date)
  if [ -f "$MARKER_CLAUDE_CODE" ]; then
    write_profile_claude_code "$PROFILE_CLAUDE_CODE"
    changed=1
  fi

  # https-proxy: HTTPS_PROXY etc. (always rewrite so hook is up-to-date)
  if [ -f "$MARKER_HTTPS_PROXY" ]; then
    write_profile_https_proxy "$PROFILE_HTTPS_PROXY"
    changed=1
  fi

  # zsh non-login shells: write hook file + inject into /etc/zsh/zshrc
  if [ -f "$MARKER_CLAUDE_CODE" ] || [ -f "$MARKER_HTTPS_PROXY" ]; then
    write_zsh_hooks
  fi

  # browser: Chromium-family managed policy
  browser_changed=0
  if [ -f "$MARKER_BROWSER" ]; then
    for d in $POLICY_DIRS; do
      mkdir -p "$d"
      f="$d/pii-guard.json"
      if [ -f "$f" ]; then
        cur=$(cat "$f")
      else
        cur=""
      fi
      if [ "$cur" != "$POLICY_JSON" ]; then
        printf '%s\n' "$POLICY_JSON" > "$f"
        chmod 0644 "$f"
        browser_changed=1
      fi
    done
  fi

  if [ "$changed" = "1" ] || [ "$browser_changed" = "1" ]; then
    echo "[pii-guard-config] config applied (claude-code:$([ -f "$MARKER_CLAUDE_CODE" ] && echo yes || echo no) https-proxy:$([ -f "$MARKER_HTTPS_PROXY" ] && echo yes || echo no) browser:$([ -f "$MARKER_BROWSER" ] && echo yes || echo no))"
  fi
}

revert() {
  browser_changed=0

  # profile.d files are kept on stop — the PROMPT_COMMAND/precmd hook
  # inside them will automatically unset the env vars the next time the
  # user runs a command in any open shell. Removing the files here would
  # mean new shells opened after the stop would never get the hook and
  # therefore wouldn't auto-reconnect when the service starts again.
  # Files are only deleted on package remove/purge (postrm).

  for d in $POLICY_DIRS; do
    f="$d/pii-guard.json"
    if [ -f "$f" ]; then
      rm -f "$f"
      browser_changed=1
    fi
  done

  if [ "$browser_changed" = "1" ]; then
    echo "[pii-guard-config] browser proxy policy removed (proxy is no longer running)"
    echo "[pii-guard-config]   note: running Chromium-family browsers keep their cached policy until restarted"
  fi
  echo "[pii-guard-config] proxy stopped — shell env vars will be auto-cleared on next prompt"
}

case "${1:-}" in
  apply)  apply  ;;
  revert) revert ;;
  *) echo "usage: $0 apply|revert" >&2; exit 1 ;;
esac
exit 0
