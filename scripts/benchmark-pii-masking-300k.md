# PII Guard Proxy — accuracy benchmark on `ai4privacy/pii-masking-300k`

This directory holds the harness we use to measure detection accuracy on
public ground truth. Two scripts:

| Script | What it measures |
|---|---|
| `benchmark-pii-masking-300k.js` | regex-only detection (the proxy's `lib/detector.js`) |
| `benchmark-pii-masking-300k-ml.py` | three ML models (GLiNER PII Small INT8, GLiNER PII Small FP32, DeBERTa-v3-base ai4privacy FT) |

The Python script writes per-entry predictions to JSONL files. A
companion Node script (`score-all.js`) loads regex predictions plus the
ML JSONLs and reports span-level F1 for every combination
(regex-only, regex+gliner_int8, regex+gliner_fp32, regex+deberta_base)
under the same matching framework: STRICT/LENIENT × TYPE-AWARE/ANY-TYPE.

## Reproducing

```sh
# 1. Download the English validation split (~27 MB).
mkdir -p scripts/data
curl -L -o scripts/data/english_validation.jsonl \
  'https://huggingface.co/datasets/ai4privacy/pii-masking-300k/resolve/main/data/validation/1english_openpii_8k.jsonl'

# 2. Regex-only F1 (no extra deps, ~0.3 s).
node scripts/benchmark-pii-masking-300k.js

# 3. ML F1 (needs python3 + pip; ~50 min on a CPU).
python3 -m venv scripts/venv
scripts/venv/bin/pip install gliner transformers torch onnxruntime
scripts/venv/bin/python scripts/benchmark-pii-masking-300k-ml.py \
  scripts/data/english_validation.jsonl

# 4. Combined F1 across all 4 detection scenarios.
node scripts/score-all.js
```

## What gets reported

For each scenario we report four span-level F1 numbers:

* **STRICT** — predicted span exactly matches the gold span (start, end)
* **LENIENT** — predicted span overlaps the gold span by any byte
* **TYPE-AWARE** — additionally requires that the predicted PII type
  maps to the gold label per a fixed acceptance table
* **ANY-TYPE** — counts any span overlap as a hit, ignoring label
  mismatch (most relevant for an anonymisation proxy: did we catch
  the PII at all)

Plus a per-gold-label recall table comparing all four scenarios on
each of the dataset's 28 PII labels.

## Why these models?

* **GLiNER PII Small INT8 ONNX** — the model the deb actually ships in
  hybrid mode. ~50 MB on disk. Same weights `pii-guard-proxy` loads.
* **GLiNER PII Small FP32** — same model as above but with full-precision
  PyTorch weights. Tells us how much accuracy we lose to int8
  quantisation for download-size reasons.
* **DeBERTa-v3-base ai4privacy FT**
  (`Isotonic/deberta-v3-base_finetuned_ai4privacy_v2`) — a 184 M-param
  / ~736 MB model fine-tuned directly on this dataset's training
  split. Reference point for "what's the ceiling if you don't care
  about model size?".
