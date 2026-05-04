#!/bin/sh
# Fetch the GLiNER PII Small INT8 + Base INT8 ONNX models for the
# proxy's ML detection pipeline. Idempotent — safe to re-run.
#
# Files end up at:
#   /var/lib/pii-guard/models/gliner-pii-small/
#   /var/lib/pii-guard/models/gliner-pii-base/
#
# The proxy's lib/ml-helper.py loads both in parallel; lib/ml-detector.js
# applies per-(model, label) cutoffs to merge their predictions.
# Combining small + base is what lifts measured recall on
# ai4privacy/pii-masking-300k from ~84% (either model alone) to ~91%.
set -e

SMALL_DIR="${PII_GUARD_ML_SMALL_DIR:-/var/lib/pii-guard/models/gliner-pii-small}"
BASE_DIR="${PII_GUARD_ML_BASE_DIR:-/var/lib/pii-guard/models/gliner-pii-base}"
HF_BASE_URL="https://huggingface.co"

LOG=/var/log/pii-guard-ml-install.log
echo "[$(date '+%F %T')] install-ml: starting" >>"$LOG"
exec >>"$LOG" 2>&1

fetch() {
  repo="$1"; rel="$2"; dest_dir="$3"
  out="$dest_dir/$rel"
  mkdir -p "$(dirname "$out")"
  if [ -f "$out" ] && [ -s "$out" ]; then
    echo "  ✓ $repo/$rel (cached, $(stat -c%s "$out") bytes)"
    return 0
  fi
  echo "  → fetching $repo/$rel..."
  url="$HF_BASE_URL/$repo/resolve/main/$rel"
  if curl -fsSL -o "$out.tmp" "$url"; then
    mv "$out.tmp" "$out"
    echo "  ✓ $repo/$rel ($(stat -c%s "$out") bytes)"
  else
    echo "  ✗ $repo/$rel (download failed)"
    rm -f "$out.tmp"
    return 1
  fi
}

mkdir -p "$SMALL_DIR/onnx" "$BASE_DIR/onnx"

echo "[$(date '+%F %T')] Fetching gliner-pii-small..."
fetch knowledgator/gliner-pii-small-v1.0 gliner_config.json       "$SMALL_DIR"
fetch knowledgator/gliner-pii-small-v1.0 tokenizer.json           "$SMALL_DIR"
fetch knowledgator/gliner-pii-small-v1.0 tokenizer_config.json    "$SMALL_DIR"
fetch knowledgator/gliner-pii-small-v1.0 special_tokens_map.json  "$SMALL_DIR"
fetch knowledgator/gliner-pii-small-v1.0 onnx/model_quint8.onnx   "$SMALL_DIR"

echo "[$(date '+%F %T')] Fetching gliner-pii-base..."
fetch knowledgator/gliner-pii-base-v1.0  gliner_config.json       "$BASE_DIR"
fetch knowledgator/gliner-pii-base-v1.0  tokenizer.json           "$BASE_DIR"
fetch knowledgator/gliner-pii-base-v1.0  tokenizer_config.json    "$BASE_DIR"
fetch knowledgator/gliner-pii-base-v1.0  special_tokens_map.json  "$BASE_DIR"
fetch knowledgator/gliner-pii-base-v1.0  added_tokens.json        "$BASE_DIR" || true
fetch knowledgator/gliner-pii-base-v1.0  spm.model                "$BASE_DIR" || true
fetch knowledgator/gliner-pii-base-v1.0  onnx/model_quint8.onnx   "$BASE_DIR"

# Set ownership so the pii-guard service user can read them.
if getent passwd pii-guard >/dev/null; then
  chown -R pii-guard:pii-guard "$SMALL_DIR" "$BASE_DIR" 2>/dev/null || true
fi
chmod -R a+r "$SMALL_DIR" "$BASE_DIR" 2>/dev/null || true

echo "[$(date '+%F %T')] install-ml: done"

mkdir -p /etc/pii-guard
touch /etc/pii-guard/ml-detection-enabled
chmod 0644 /etc/pii-guard/ml-detection-enabled
exit 0
