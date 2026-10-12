"""One model x one thread count, in its own process (clean RSS). Prints one JSON line.

usage: bench_one.py <model> <threads>
model: gliner2 | pf_torch | pf_onnx_int8 | pf_onnx_q4
Synthetic text only (PPE corpus, seed 20261002).
"""

import json
import os
import statistics
import sys
import time

import psutil

MODEL, THREADS = sys.argv[1], int(sys.argv[2])
os.environ["OMP_NUM_THREADS"] = str(THREADS)
HERE = os.path.dirname(os.path.abspath(__file__))
proc = psutil.Process()

items = [json.loads(line)["text"] for line in open(os.path.join(HERE, "corpus.jsonl"))]


def doc(nbytes: int) -> str:
    out, i = [], 0
    while sum(len(x) + 2 for x in out) < nbytes:
        out.append(items[i % len(items)])
        i += 1
    return "\n\n".join(out)[:nbytes]


SIZES = {"msg_160B": items[7], "1KB": doc(1024), "10KB": doc(10 * 1024), "100KB": doc(100 * 1024)}
rss0 = proc.memory_info().rss
t0 = time.perf_counter()

if MODEL == "gliner2":
    import torch

    torch.set_num_threads(THREADS)
    from gliner2 import GLiNER2

    m = GLiNER2.from_pretrained("/media/administrator/DATA/models/fastino-gliner2-privacy-filter-PII-multi")
    LABELS = ["person", "email", "phone_number", "address", "national_id", "passport_number",
              "credit_card_number", "bank_account_number", "date_of_birth", "ip_address"]
    CHUNK = 1500  # chars; GLiNER encoders are ~512-token windows

    def run(text: str) -> int:
        n = 0
        for i in range(0, len(text), CHUNK):
            r = m.extract_entities(text[i : i + CHUNK], LABELS, threshold=0.5)
            n += sum(len(v) for v in r.get("entities", {}).values())
        return n

elif MODEL == "pf_torch":
    import torch

    torch.set_num_threads(THREADS)
    from transformers import AutoModelForTokenClassification, AutoTokenizer

    tok = AutoTokenizer.from_pretrained("/media/administrator/DATA/models/openai-privacy-filter")
    m = AutoModelForTokenClassification.from_pretrained("/media/administrator/DATA/models/openai-privacy-filter").eval()

    def run(text: str) -> int:
        enc = tok(text, return_tensors="pt")
        with torch.inference_mode():
            logits = m(**enc).logits
        return int((logits.argmax(-1) != 0).sum())

else:
    import onnxruntime as ort
    from huggingface_hub import hf_hub_download
    from transformers import AutoTokenizer

    fname = {"pf_onnx_int8": "model_quantized", "pf_onnx_q4": "model_q4"}[MODEL]
    path = f"/media/administrator/DATA/models/openai-privacy-filter/onnx/{fname}.onnx"
    so = ort.SessionOptions()
    so.intra_op_num_threads = THREADS
    so.inter_op_num_threads = 1
    sess = ort.InferenceSession(path, so, providers=["CPUExecutionProvider"])
    tok = AutoTokenizer.from_pretrained("/media/administrator/DATA/models/openai-privacy-filter")
    names = {i.name for i in sess.get_inputs()}

    def run(text: str) -> int:
        enc = tok(text, return_tensors="np")
        feed = {k: v for k, v in enc.items() if k in names}
        (logits,) = sess.run(None, feed)[:1]
        return int((logits.argmax(-1) != 0).sum())


load_s = time.perf_counter() - t0
rss_loaded = proc.memory_info().rss
run(SIZES["msg_160B"])  # warm-up

res = {"model": MODEL, "threads": THREADS, "load_s": round(load_s, 1),
       "rss_loaded_mb": round(rss_loaded / 2**20), "lat": {}}
peak = rss_loaded
for name, text in SIZES.items():
    reps = 5 if len(text) <= 1024 else (3 if len(text) <= 10240 else 1)
    ts, hits = [], 0
    for _ in range(reps):
        t = time.perf_counter()
        hits = run(text)
        ts.append(time.perf_counter() - t)
        peak = max(peak, proc.memory_info().rss)
    res["lat"][name] = {"ms": round(statistics.median(ts) * 1000), "hits": hits, "bytes": len(text)}
res["rss_peak_mb"] = round(peak / 2**20)
res["rss_base_mb"] = round(rss0 / 2**20)
print(json.dumps(res), flush=True)
