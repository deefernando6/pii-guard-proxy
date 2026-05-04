#!/bin/sh
# Fetch the GLiNER PII Small INT8 ONNX model + tokenizer files for the
# proxy's ML detection pipeline. Idempotent — safe to re-run.
#
# Files end up at /var/lib/pii-guard/models/gliner-pii-small/. The
# proxy's lib/ml-detector.js looks there by default.
#
# Called from:
#   - finish-install.sh after `apt install` completes (deferred so
#     dpkg's lock has been released).
#   - `pii-guard ml-enable` if the user opted out at install time.
set -e

MODEL_DIR="${PII_GUARD_ML_MODEL_DIR:-/var/lib/pii-guard/models/gliner-pii-small}"
HF_REPO="knowledgator/gliner-pii-small-v1.0"
HF_BASE="https://huggingface.co/${HF_REPO}/resolve/main"

LOG=/var/log/pii-guard-ml-install.log
echo "[$(date '+%F %T')] install-ml: starting (model_dir=$MODEL_DIR)" >>"$LOG"
exec >>"$LOG" 2>&1

mkdir -p "$MODEL_DIR/onnx"

fetch() {
  rel="$1"
  out="$MODEL_DIR/$rel"
  if [ -f "$out" ] && [ -s "$out" ]; then
    echo "  ✓ $rel (cached, $(stat -c%s "$out") bytes)"
    return 0
  fi
  echo "  → fetching $rel..."
  if curl -fsSL -o "$out.tmp" "$HF_BASE/$rel"; then
    mv "$out.tmp" "$out"
    echo "  ✓ $rel ($(stat -c%s "$out") bytes)"
  else
    echo "  ✗ $rel (download failed)"
    rm -f "$out.tmp"
    return 1
  fi
}

fetch gliner_config.json
fetch tokenizer.json
fetch tokenizer_config.json
fetch special_tokens_map.json
fetch onnx/model_quint8.onnx

# Set ownership so the pii-guard service user can read them.
if getent passwd pii-guard >/dev/null; then
  chown -R pii-guard:pii-guard "$MODEL_DIR" 2>/dev/null || true
fi
chmod -R a+r "$MODEL_DIR" 2>/dev/null || true

echo "[$(date '+%F %T')] install-ml: done"

# Drop the marker so ml-detector.js knows ML is available. The proxy
# stats this on every detect call, so toggling on/off is effectively
# instant after a service reload.
mkdir -p /etc/pii-guard
touch /etc/pii-guard/ml-detection-enabled
chmod 0644 /etc/pii-guard/ml-detection-enabled
exit 0
