"""GLiNER2 variants on one 10 KB doc + one 160 B message: labels count, batched long API, int8.
usage: bench_gliner_variants.py <threads>"""

import json
import os
import statistics
import sys
import time

TH = int(sys.argv[1])
os.environ["OMP_NUM_THREADS"] = str(TH)
import psutil  # noqa: E402
import torch  # noqa: E402

torch.set_num_threads(TH)
from gliner2 import GLiNER2  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
items = [json.loads(line)["text"] for line in open(os.path.join(HERE, "corpus.jsonl"))]
doc10 = "\n\n".join(items[:80])[: 10 * 1024]
msg = items[7]
L10 = ["person", "email", "phone_number", "address", "national_id", "passport_number",
       "credit_card_number", "bank_account_number", "date_of_birth", "ip_address"]
L3 = ["person", "address", "national_id"]


def t(fn, reps=3):
    fn()
    ts = []
    for _ in range(reps):
        s = time.perf_counter()
        fn()
        ts.append(time.perf_counter() - s)
    return round(statistics.median(ts) * 1000)


m = GLiNER2.from_pretrained("/media/administrator/DATA/models/fastino-gliner2-privacy-filter-PII-multi")
out = {"threads": TH}
out["msg_10labels_ms"] = t(lambda: m.extract_entities(msg, L10, threshold=0.5))
out["msg_3labels_ms"] = t(lambda: m.extract_entities(msg, L3, threshold=0.5))
out["msg_1label_ms"] = t(lambda: m.extract_entities(msg, ["person"], threshold=0.5))
for bs in (1, 8):
    out[f"10KB_long_10labels_bs{bs}_ms"] = t(
        lambda: m.batch_extract_entities_long([doc10], L10, batch_size=bs), reps=1)
out["10KB_long_3labels_bs8_ms"] = t(lambda: m.batch_extract_entities_long([doc10], L3, batch_size=8), reps=1)

torch.ao.quantization.quantize_dynamic(m, {torch.nn.Linear}, dtype=torch.qint8, inplace=True)
out["int8_msg_10labels_ms"] = t(lambda: m.extract_entities(msg, L10, threshold=0.5))
out["int8_10KB_long_10labels_bs8_ms"] = t(
    lambda: m.batch_extract_entities_long([doc10], L10, batch_size=8), reps=1)
out["rss_mb"] = round(psutil.Process().memory_info().rss / 2**20)
print(json.dumps(out), flush=True)
