#!/usr/bin/env python3
"""Run openai/privacy-filter (INT8 ONNX) over the validation split."""
import json
import sys
import time
from pathlib import Path

import numpy as np
import onnxruntime as ort
from transformers import PreTrainedTokenizerFast

MODEL_DIR = Path('/tmp/pii-bench/models/openai-privacy-filter')
INPUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('/tmp/pii-bench/english_validation.jsonl')
LIMIT = int(sys.argv[2]) if len(sys.argv) > 2 else 0
OUT_PATH = Path('/tmp/pii-bench/predictions/openai_pf.jsonl')

# Load id2label from config
with open(MODEL_DIR / 'config.json') as f:
    cfg = json.load(f)
id2label = {int(k): v for k, v in cfg['id2label'].items()}
print(f'Loaded {len(id2label)} BIES tags', flush=True)

# Load tokenizer
print('Loading tokenizer...', flush=True)
tok = PreTrainedTokenizerFast(
    tokenizer_file=str(MODEL_DIR / 'tokenizer.json'),
    pad_token='<|endoftext|>',
    eos_token='<|endoftext|>',
    model_max_length=128000,
)
print(f'Tokenizer model_max_length: {tok.model_max_length}', flush=True)

# Load ONNX model
print('Loading ONNX session (may take a moment for ~1.5GB external data)...', flush=True)
sess_opts = ort.SessionOptions()
sess_opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_BASIC
sess = ort.InferenceSession(
    str(MODEL_DIR / 'onnx' / 'model_quantized.onnx'),
    sess_options=sess_opts,
    providers=['CPUExecutionProvider'],
)
inputs_meta = [i.name for i in sess.get_inputs()]
print(f'Inputs: {inputs_meta}', flush=True)
outputs_meta = [o.name for o in sess.get_outputs()]
print(f'Outputs: {outputs_meta}', flush=True)


def decode_bies(labels, offsets):
    """Decode BIES-tagged tokens to spans."""
    spans = []
    cur_label = None
    cur_start = None
    cur_end = None
    for tag, (s, e) in zip(labels, offsets):
        if s == 0 and e == 0:
            continue   # special tokens
        if tag == 'O':
            if cur_label is not None:
                spans.append({'start': cur_start, 'end': cur_end, 'label': cur_label})
                cur_label = None
            continue
        prefix = tag.split('-', 1)[0]
        ent = tag.split('-', 1)[1] if '-' in tag else tag
        if prefix == 'B':
            if cur_label is not None:
                spans.append({'start': cur_start, 'end': cur_end, 'label': cur_label})
            cur_label = ent
            cur_start = s
            cur_end = e
        elif prefix == 'I':
            if cur_label == ent:
                cur_end = e
            else:
                if cur_label is not None:
                    spans.append({'start': cur_start, 'end': cur_end, 'label': cur_label})
                cur_label = ent
                cur_start = s
                cur_end = e
        elif prefix == 'E':
            if cur_label == ent:
                cur_end = e
            else:
                cur_start = s
                cur_label = ent
                cur_end = e
            spans.append({'start': cur_start, 'end': cur_end, 'label': cur_label})
            cur_label = None
        elif prefix == 'S':
            if cur_label is not None:
                spans.append({'start': cur_start, 'end': cur_end, 'label': cur_label})
            spans.append({'start': s, 'end': e, 'label': ent})
            cur_label = None
        else:
            pass
    if cur_label is not None:
        spans.append({'start': cur_start, 'end': cur_end, 'label': cur_label})
    return spans


def predict(text):
    enc = tok(text, return_offsets_mapping=True, truncation=True, max_length=8192,
              return_tensors='np', return_attention_mask=True)
    feed = {'input_ids': enc['input_ids'].astype(np.int64),
            'attention_mask': enc['attention_mask'].astype(np.int64)}
    if 'position_ids' in inputs_meta:
        seq = enc['input_ids'].shape[1]
        feed['position_ids'] = np.arange(seq).reshape(1, -1).astype(np.int64)
    if 'token_type_ids' in inputs_meta:
        feed['token_type_ids'] = np.zeros_like(enc['input_ids'])
    out = sess.run(None, feed)
    logits = out[0][0]  # (seq, num_labels)
    pred_ids = np.argmax(logits, axis=-1)
    labels = [id2label[i] for i in pred_ids.tolist()]
    offsets = enc['offset_mapping'][0].tolist()
    return decode_bies(labels, offsets)


def main():
    entries = []
    with INPUT.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try: entries.append(json.loads(line))
            except: pass
            if LIMIT and len(entries) >= LIMIT: break
    print(f'Running on {len(entries)} entries...', flush=True)
    OUT_PATH.parent.mkdir(exist_ok=True)
    t0 = time.time()
    with OUT_PATH.open('w') as f:
        for i, e in enumerate(entries):
            try:
                spans = predict(e['source_text'])
            except Exception as exc:
                spans = []
                if i < 5:
                    print(f'  warn @{i}: {exc}', flush=True)
            f.write(json.dumps({'idx': i, 'spans': spans}, ensure_ascii=False) + '\n')
            if (i + 1) % 100 == 0:
                elapsed = time.time() - t0
                eta = elapsed / (i + 1) * (len(entries) - i - 1)
                print(f'  {i+1}/{len(entries)}  ({elapsed:.0f}s elapsed, ~{eta:.0f}s remaining)', flush=True)
    print(f'  total {time.time()-t0:.1f}s', flush=True)
    print(f'  wrote {len(entries)} predictions to {OUT_PATH}', flush=True)


if __name__ == '__main__':
    main()
