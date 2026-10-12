"""GLiNER2-PII ONNX int8 (okasi export, 7 fixed labels). usage: bench_onnx.py <threads>"""

import json
import os
import statistics
import sys
import time
from pathlib import Path

TH = int(sys.argv[1])
import onnxruntime as ort  # noqa: E402
import psutil  # noqa: E402

import sys
sys.path.insert(0, "/media/administrator/DATA/models/okasi-gliner2-privacy-filter-pii-multi-onnx/examples")
import onnx_runtime as rt  # noqa: E402

HERE = Path("/media/administrator/DATA/models/okasi-gliner2-privacy-filter-pii-multi-onnx")
SCR = Path(__file__).resolve().parent
items = [json.loads(line)["text"] for line in open(SCR.parent / "corpus.jsonl")]


def doc(n: int) -> str:
    out, i = [], 0
    while sum(len(x) + 2 for x in out) < n:
        out.append(items[i % len(items)])
        i += 1
    return "\n\n".join(out)[:n]


t0 = time.perf_counter()
s = rt.Gliner2OnnxSession.__new__(rt.Gliner2OnnxSession)
s.model_dir = HERE
s.labels = rt.load_entity_labels(HERE)
s.onnx_model_file = "model_q8.onnx"
s.processor, s.collator = rt.create_gliner2_collator(HERE)
so = ort.SessionOptions()
so.intra_op_num_threads = TH
so.inter_op_num_threads = 1
s.session = ort.InferenceSession(str(HERE / "model_q8.onnx"), so, providers=["CPUExecutionProvider"])
load_s = time.perf_counter() - t0
CHUNK = 1500


def run(text: str) -> int:
    return sum(len(s.predict_entities(text[i : i + CHUNK])) for i in range(0, len(text), CHUNK))


print("sample:", s.predict_entities(items[7]), file=sys.stderr)
run(items[7])
res = {"model": "gliner2_onnx_q8", "threads": TH, "load_s": round(load_s, 1), "lat": {}}
for name, text in {"msg_160B": items[7], "1KB": doc(1024), "10KB": doc(10240), "100KB": doc(102400)}.items():
    reps = 5 if len(text) <= 1024 else (3 if len(text) <= 10240 else 1)
    ts = []
    for _ in range(reps):
        t = time.perf_counter()
        hits = run(text)
        ts.append(time.perf_counter() - t)
    res["lat"][name] = {"ms": round(statistics.median(ts) * 1000), "hits": hits}
res["rss_mb"] = round(psutil.Process().memory_info().rss / 2**20)
print(json.dumps(res), flush=True)
