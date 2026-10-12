"""Split one GLiNER2 ONNX call into preprocessing vs model forward."""

import json
import time
from pathlib import Path

import onnxruntime as ort

import sys
sys.path.insert(0, "/media/administrator/DATA/models/okasi-gliner2-privacy-filter-pii-multi-onnx/examples")
import onnx_runtime as rt

H = Path("/media/administrator/DATA/models/okasi-gliner2-privacy-filter-pii-multi-onnx")
items = [json.loads(line)["text"] for line in open(Path(__file__).resolve().parent.parent / "corpus.jsonl")]
labels = rt.load_entity_labels(H)
_, col = rt.create_gliner2_collator(H)
so = ort.SessionOptions()
so.intra_op_num_threads = 3
so.inter_op_num_threads = 1
sess = ort.InferenceSession(str(H / "model_q8.onnx"), so, providers=["CPUExecutionProvider"])
for name, text in [("msg", items[7]), ("1500ch", "\n\n".join(items[:12])[:1500])]:
    for _ in range(3):
        t = time.perf_counter()
        b, wc = rt.preprocess_entity_example(col, text, labels)
        t1 = time.perf_counter()
        feed = {"input_ids": b.input_ids.numpy(), "attention_mask": b.attention_mask.numpy(),
                "text_word_indices": b.text_word_indices.numpy(), "text_word_counts": wc}
        out = sess.run(None, feed)
        t2 = time.perf_counter()
    print(name, "tokens", tuple(b.input_ids.shape), "words", int(wc[0]),
          "preprocess_ms", round((t1 - t) * 1000), "onnx_ms", round((t2 - t1) * 1000),
          "span_scores", out[1].shape, flush=True)
