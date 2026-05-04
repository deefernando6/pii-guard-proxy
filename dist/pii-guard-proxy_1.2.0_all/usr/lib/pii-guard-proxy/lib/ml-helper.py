#!/usr/bin/env python3
"""GLiNER PII detection helper.

Loads BOTH GLiNER PII Small INT8 and GLiNER PII Base INT8 ONNX models
and runs every prompt through both. The Node side merges the two
prediction streams with per-(model, label) score cutoffs to reach the
operating point measured at P=87.23%, R=90.62%, F1=88.89% on
ai4privacy/pii-masking-300k. Either model alone tops out around F1=84%;
ensembling is what unlocks recall above 90%.

Each request:   {"id": <int>, "text": "..."}
Each response:  {"id": <int>, "spans_small": [...], "spans_base": [...]}
Each span:      {"start": int, "end": int, "label": str, "score": float}

Inference threshold is intentionally low (0.10) so the Node side can
apply its own per-label cutoffs across the full candidate distribution.
"""
import json
import os
import sys
from pathlib import Path

SMALL_DIR = Path(os.environ.get(
    'PII_GUARD_ML_SMALL_DIR',
    '/var/lib/pii-guard/models/gliner-pii-small',
))
BASE_DIR = Path(os.environ.get(
    'PII_GUARD_ML_BASE_DIR',
    '/var/lib/pii-guard/models/gliner-pii-base',
))
THRESHOLD = float(os.environ.get('PII_GUARD_ML_THRESHOLD', '0.10'))

LABELS = [
    "person name", "first name", "last name", "surname", "full name",
    "middle name", "given name", "family name",
    "title", "honorific", "salutation",
    "email address", "phone number", "telephone",
    "date of birth", "date", "time", "birthdate",
    "address", "city", "state", "country", "postal code", "zipcode",
    "street", "street address", "building", "building number",
    "secondary address", "apartment", "suite", "geographic coordinates",
    "latitude", "longitude",
    "id card", "social security number", "passport number",
    "driver license", "drivers licence", "national id",
    "username", "user name", "ip address", "ipv4", "ipv6",
    "password", "sex", "gender", "card issuer",
]


def emit(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def load(model_path, tag):
    from gliner import GLiNER
    return GLiNER.from_pretrained(
        str(model_path),
        load_tokenizer=True,
        load_onnx_model=True,
        onnx_model_file='onnx/model_quint8.onnx',
    )


def predict(model, text):
    try:
        ents = model.predict_entities(text, LABELS, threshold=THRESHOLD)
        return [
            {"start": e["start"], "end": e["end"],
             "label": e["label"], "score": float(e.get("score", 0.0))}
            for e in ents
        ]
    except Exception as e:
        return []


def main():
    try:
        from gliner import GLiNER  # noqa: F401
    except Exception as e:
        emit({"error": f"gliner-import-failed: {e}"})
        return 1

    try:
        small = load(SMALL_DIR, 'small')
    except Exception as e:
        emit({"error": f"small-load-failed: {e}"})
        return 1
    try:
        base = load(BASE_DIR, 'base')
    except Exception as e:
        emit({"error": f"base-load-failed: {e}"})
        return 1

    emit({"ready": True, "small_dir": str(SMALL_DIR), "base_dir": str(BASE_DIR), "threshold": THRESHOLD})

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
            emit({"id": rid, "spans_small": [], "spans_base": []})
            continue
        emit({"id": rid, "spans_small": predict(small, text), "spans_base": predict(base, text)})

    return 0


if __name__ == '__main__':
    sys.exit(main())
