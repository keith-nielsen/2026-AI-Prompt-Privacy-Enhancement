import time, torch
torch.set_num_threads(3)
from gliner2 import GLiNER2
m = GLiNER2.from_pretrained("/media/administrator/DATA/models/fastino-gliner2-privacy-filter-PII-multi").eval()
enc = m.encoder
print("encoder", type(enc).__name__, "params_M", round(sum(p.numel() for p in enc.parameters())/1e6), "embedding_M", round(enc.embeddings.word_embeddings.weight.numel()/1e6), flush=True)
def t(T, mod):
    x = torch.randint(1000, 30000, (1, T)); a = torch.ones_like(x)
    with torch.inference_mode():
        mod(input_ids=x, attention_mask=a)
        s = time.perf_counter(); mod(input_ids=x, attention_mask=a); return round((time.perf_counter()-s)*1000)
print("fp32 encoder ms  T=140:", t(140, enc), " T=512:", t(512, enc), " T=774:", t(774, enc), flush=True)
q = torch.ao.quantization.quantize_dynamic(enc, {torch.nn.Linear}, dtype=torch.qint8)
print("int8 encoder ms  T=140:", t(140, q), " T=512:", t(512, q), " T=774:", t(774, q), flush=True)
