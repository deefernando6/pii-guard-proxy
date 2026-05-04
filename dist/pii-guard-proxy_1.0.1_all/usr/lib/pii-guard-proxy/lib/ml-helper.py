#!/usr/bin/env python3
"""Long-lived GLiNER PII Small INT8 inference helper.

Spawned by proxy.js on first ML detection request. Reads NDJSON requests
from stdin, writes NDJSON responses to stdout. Each request:
  {"id": <int>, "text": "..."}
Each response:
  {"id": <int>, "spans": [{"start": int, "end": int, "label": str, "score": float}, ...]}

Loads the ONNX model from $PII_GUARD_ML_MODEL_DIR (defaults to
/var/lib/pii-guard/models/gliner-pii-small). Threshold defaults to 0.30
to give the Node side enough candidate spans to apply per-label cutoffs.

The list of labels we ask GLiNER for is intentionally aligned with the
gold scheme of ai4privacy/pii-masking-300k so the deployed proxy is
exposed to the same candidate set the benchmark scored against.
"""
import json
import os
import sys
from pathlib import Path

MODEL_DIR = Path(os.environ.get(
    'PII_GUARD_ML_MODEL_DIR',
    '/var/lib/pii-guard/models/gliner-pii-small',
))
THRESHOLD = float(os.environ.get('PII_GUARD_ML_THRESHOLD', '0.30'))

LABELS = [
    "person name", "first name", "last name", "title",
    "email address", "phone number", "date of birth", "date", "time",
    "address", "city", "state", "country", "postal code", "street",
    "building", "secondary address", "geographic coordinates",
    "id card", "social security number", "passport number",
    "driver license", "username", "ip address",
    "password", "sex", "card issuer",
]


def emit(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def main():
    try:
        from gliner import GLiNER
    except Exception as e:
        emit({"error": f"gliner-import-failed: {e}"})
        return 1

    try:
        model = GLiNER.from_pretrained(
            str(MODEL_DIR),
            load_tokenizer=True,
            load_onnx_model=True,
            onnx_model_file='onnx/model_quint8.onnx',
        )
    except Exception as e:
        emit({"error": f"model-load-failed: {e}"})
        return 1

    emit({"ready": True, "model_dir": str(MODEL_DIR), "threshold": THRESHOLD})

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        rid = req.get('id')
        text = req.get('text') or ''
        if not isinstance(text, str) or not text:
            emit({"id": rid, "spans": []})
            continue
        try:
            ents = model.predict_entities(text, LABELS, threshold=THRESHOLD)
            spans = [
                {"start": e["start"], "end": e["end"],
                 "label": e["label"], "score": float(e.get("score", 0.0))}
                for e in ents
            ]
            emit({"id": rid, "spans": spans})
        except Exception as e:
            emit({"id": rid, "spans": [], "error": str(e)})

    return 0


if __name__ == '__main__':
    sys.exit(main())
