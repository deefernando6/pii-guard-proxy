#!/bin/sh
# Installs the hybrid-detection-mode dependencies:
#
#   1. The transformers.js npm dep into the proxy's bundled
#      /usr/lib/pii-guard-proxy/node_modules/. We don't ship it in the
#      base deb because regex-only users don't need ~30 MB of dead code.
#   2. The GLiNER PII Small ONNX weights into
#      /var/lib/pii-guard/models/gliner-pii-small/. ~50 MB.
#
# Called from finish-install.sh (deferred postinst) and from
# `sudo pii-guard ml-enable` (runtime CLI).  Best-effort everywhere —
# if anything fails the proxy falls back to regex-only and surfaces
# the situation through `pii-guard ml-status`.
#
# Honours $PII_GUARD_ML_HOST_OVERRIDE for offline mirrors:
#   sudo PII_GUARD_ML_HOST_OVERRIDE=https://my-mirror.example.com/ \
#     /usr/lib/pii-guard-proxy/install-ml.sh

set -eu
cd /

LIB_DIR=/usr/lib/pii-guard-proxy
MODEL_DIR=/var/lib/pii-guard/models/gliner-pii-small
HF_REPO="knowledgator/gliner-pii-small-v1.0"
HF_HOST="${PII_GUARD_ML_HOST_OVERRIDE:-https://huggingface.co}"

log() { printf '[pii-guard-ml] %s\n' "$*"; }

# 1. Sanity: need node + curl.
if ! command -v node >/dev/null 2>&1; then
  log "FATAL: node is not installed yet — re-run after nodejs is on PATH."
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  log "FATAL: curl is required for the model download."
  exit 1
fi

# 2. Install transformers.js into the bundled node_modules. We pin the
#    version so we don't get a surprise breaking change six months from
#    now. The version below was the latest stable at deb-build time.
TRANSFORMERS_VER="3.5.0"
log "Installing @huggingface/transformers@${TRANSFORMERS_VER} into ${LIB_DIR}/node_modules ..."
if [ ! -d "$LIB_DIR/node_modules/@huggingface/transformers" ] \
  || ! grep -q "\"version\": \"${TRANSFORMERS_VER}\"" \
       "$LIB_DIR/node_modules/@huggingface/transformers/package.json" 2>/dev/null; then
  if command -v npm >/dev/null 2>&1; then
    ( cd "$LIB_DIR" && npm install --omit=dev --no-audit --no-fund \
        "@huggingface/transformers@${TRANSFORMERS_VER}" ) \
      || { log "WARNING: npm install failed; hybrid mode unavailable until retry."; exit 1; }
  else
    log "WARNING: npm not found — install nodejs first, then retry: sudo pii-guard ml-enable"
    exit 1
  fi
else
  log "transformers.js already present, skipping npm install."
fi

# 3. Download the GLiNER PII Small ONNX weights + tokenizer from HF.
#    transformers.js expects a specific layout under <model_dir>/onnx/
#    and the tokenizer.json + config files at the root.
install -d -m 0755 -o pii-guard -g pii-guard /var/lib/pii-guard/models
install -d -m 0755 -o pii-guard -g pii-guard "$MODEL_DIR"
install -d -m 0755 -o pii-guard -g pii-guard "$MODEL_DIR/onnx"

# Files we need.  GLiNER ships an INT8-quantized variant
# (model_quint8.onnx) which is the ~50 MB target referenced in the
# debconf warning. We grab that plus the metadata.
FILES_ROOT="config.json tokenizer.json tokenizer_config.json special_tokens_map.json gliner_config.json"
FILES_ONNX="onnx/model_quint8.onnx"

fetch() {
  rel="$1"
  url="${HF_HOST}/${HF_REPO}/resolve/main/${rel}"
  out="${MODEL_DIR}/${rel}"
  if [ -f "$out" ] && [ "$(stat -c%s "$out" 2>/dev/null || echo 0)" -gt 0 ]; then
    log "  already have ${rel}"
    return 0
  fi
  log "  fetching ${rel} ..."
  if curl -fSL --retry 3 --retry-delay 4 -o "$out.part" "$url"; then
    mv "$out.part" "$out"
    chown pii-guard:pii-guard "$out"
    chmod 0644 "$out"
  else
    rm -f "$out.part"
    log "  WARNING: failed to fetch ${rel}"
    return 1
  fi
}

failed=0
for f in $FILES_ROOT $FILES_ONNX; do
  fetch "$f" || failed=$((failed + 1))
done

if [ "$failed" -gt 0 ]; then
  log "WARNING: ${failed} file(s) failed to download. Retry with: sudo pii-guard ml-enable"
  exit 1
fi

log "Model + transformers.js installed at ${MODEL_DIR} (~$(du -sh "$MODEL_DIR" 2>/dev/null | cut -f1))"
log "Restart the proxy to load it:  sudo systemctl restart pii-guard-proxy"
exit 0
