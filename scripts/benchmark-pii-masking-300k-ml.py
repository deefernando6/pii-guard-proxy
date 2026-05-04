#!/usr/bin/env python3
"""
Multi-model PII detection benchmark on ai4privacy/pii-masking-300k
(English validation split).

Runs three ML models — GLiNER PII Small INT8 ONNX, GLiNER PII Small FP32,
DeBERTa-v3-base finetuned on ai4privacy — over the same prompts and
saves per-entry predictions to JSON files. A separate Node script
combines those predictions with regex output and computes span-level
F1 with the SAME methodology as scripts/benchmark-pii-masking-300k.js
in the proxy repo.
"""
import json
import os
import sys
import time
from pathlib import Path

INPUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('/tmp/pii-bench/english_validation.jsonl')
LIMIT = int(sys.argv[2]) if len(sys.argv) > 2 else 0  # 0 = all
OUT_DIR = Path('/tmp/pii-bench/predictions')
OUT_DIR.mkdir(exist_ok=True)

# Labels we ask GLiNER for. Keeping the list in sync with the dataset's
# 28 labels (mapped to natural-language phrases GLiNER understands).
GLINER_LABELS = [
    # Names — multiple synonyms catch second/third surnames better
    "person name", "first name", "last name", "surname", "full name",
    "middle name", "given name", "family name",
    # Honorifics
    "title", "honorific", "salutation",
    # Contact
    "email address", "phone number", "telephone",
    # Dates
    "date of birth", "date", "time", "birthdate",
    # Addresses — multiple specificities
    "address", "city", "state", "country", "postal code", "zipcode",
    "street", "street address", "building", "building number",
    "secondary address", "apartment", "suite", "geographic coordinates",
    "latitude", "longitude",
    # IDs
    "id card", "social security number", "passport number",
    "driver license", "drivers licence", "national id",
    # Misc
    "username", "user name", "ip address", "ipv4", "ipv6",
    "password", "sex", "gender", "card issuer",
]


def load_entries():
    entries = []
    with INPUT.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except Exception:
                pass
            if LIMIT and len(entries) >= LIMIT:
                break
    return entries


def write_predictions(name, preds):
    path = OUT_DIR / f'{name}.jsonl'
    with path.open('w') as f:
        for p in preds:
            f.write(json.dumps(p, ensure_ascii=False) + '\n')
    print(f'  wrote {len(preds)} predictions to {path}')


def run_gliner(entries, *, name, load_onnx=False):
    """Run GLiNER over every entry and return predictions list."""
    print(f'\n=== {name} ===')
    from gliner import GLiNER

    local_path = '/tmp/pii-bench/models/gliner-pii-small'
    if load_onnx:
        model = GLiNER.from_pretrained(
            local_path,
            load_tokenizer=True,
            load_onnx_model=True,
            onnx_model_file='onnx/model_quint8.onnx',
        )
    else:
        model = GLiNER.from_pretrained(local_path)

    preds = []
    t0 = time.time()
    for i, e in enumerate(entries):
        text = e['source_text']
        try:
            ents = model.predict_entities(text, GLINER_LABELS, threshold=0.10)
        except Exception as exc:
            ents = []
            if i < 5:
                print(f'  warn @{i}: {exc}')
        spans = [{'start': x['start'], 'end': x['end'], 'label': x['label'],
                  'score': float(x.get('score', 0.0))} for x in ents]
        preds.append({'idx': i, 'spans': spans})
        if (i + 1) % 200 == 0:
            elapsed = time.time() - t0
            eta = elapsed / (i + 1) * (len(entries) - i - 1)
            print(f'  {i+1}/{len(entries)}  ({elapsed:.0f}s elapsed, ~{eta:.0f}s remaining)')
    print(f'  total {time.time()-t0:.1f}s')
    write_predictions(name, preds)


def run_deberta(entries, *, name='deberta'):
    """Run DeBERTa-v3-base ai4privacy fine-tune via transformers pipeline."""
    print(f'\n=== {name} ===')
    from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline
    import torch
    model_id = '/tmp/pii-bench/models/deberta'
    print(f'  loading {model_id}...')
    tok = AutoTokenizer.from_pretrained(model_id)
    mdl = AutoModelForTokenClassification.from_pretrained(model_id)
    nlp = pipeline(
        'token-classification',
        model=mdl, tokenizer=tok,
        aggregation_strategy='simple',
        device=-1,
    )

    preds = []
    t0 = time.time()
    for i, e in enumerate(entries):
        text = e['source_text']
        try:
            ents = nlp(text)
        except Exception as exc:
            ents = []
            if i < 5:
                print(f'  warn @{i}: {exc}')
        spans = [{'start': int(x['start']), 'end': int(x['end']),
                  'label': x['entity_group'], 'score': float(x['score'])} for x in ents]
        preds.append({'idx': i, 'spans': spans})
        if (i + 1) % 100 == 0:
            elapsed = time.time() - t0
            eta = elapsed / (i + 1) * (len(entries) - i - 1)
            print(f'  {i+1}/{len(entries)}  ({elapsed:.0f}s elapsed, ~{eta:.0f}s remaining)')
    print(f'  total {time.time()-t0:.1f}s')
    write_predictions(name, preds)


def main():
    print(f'Loading {INPUT}...')
    entries = load_entries()
    print(f'Loaded {len(entries)} entries')

    targets = sys.argv[3:] if len(sys.argv) > 3 else ['gliner_int8', 'gliner_fp32', 'deberta']
    print(f'Running models: {targets}')

    if 'gliner_int8' in targets:
        run_gliner(entries, name='gliner_int8', load_onnx=True)
    if 'gliner_fp32' in targets:
        run_gliner(entries, name='gliner_fp32', load_onnx=False)
    if 'deberta' in targets:
        run_deberta(entries, name='deberta')


if __name__ == '__main__':
    main()
