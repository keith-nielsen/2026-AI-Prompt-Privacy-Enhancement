# External baseline: Microsoft Presidio on NVIDIA Nemotron-PII (2026-10-16)

> **Pre-alpha.** Presidio *as shipped* (default recognisers, no tuning) next to PPE's Stage 1 rules,
> through one harness, one label map and one scorer. Numbers describe this synthetic, US-centred
> dataset, not real-world accuracy. A tuned Presidio (context words, custom recognisers, per-entity
> thresholds) would score differently; so will PPE once span models land (phase 4).

Dataset, pin, licence and protocol: [`2026-10-16-nemotron-pii.md`](2026-10-16-nemotron-pii.md).
Results: `bench/results/2026-10-16-presidio-baseline/` (Presidio) and
`bench/results/2026-10-16-nemotron-pii/` (PPE rules), side by side in `head-to-head.txt`.

## Set-up

| | |
|---|---|
| System | `presidio-analyzer` 2.2.364, `AnalyzerEngine` + `BatchAnalyzerEngine`, language `en`, default registry (17 recognisers: `SpacyRecognizer` and 16 rule-based ones; the list is in the JSON) |
| NLP model | spaCy 3.8.16, `en_core_web_lg` 3.8.0 (MIT), loaded from a local path; the harness refuses a model name, because Presidio downloads a name it cannot find |
| Suffix list | Presidio's email recogniser checks domains with `tldextract`, which by default downloads the Public Suffix List and caches it in `~/.cache`. The harness pins it to the snapshot bundled with `tldextract` 5.4.0: no network, results fixed by the recorded version. |
| Thresholds | `min_score` 0 (Presidio's default analyser threshold) and 0.5, one pass, one report each |
| Not enabled by default | `SG_NRIC_FIN` (and other non-US national recognisers). The dataset has no NRIC or IBAN label, so this costs Presidio nothing here. |
| Host | one process, `nice -n 19 taskset -c 5-7`, `MemoryMax=4G`: 53–55 docs/s (31.6 and 30.2 min for 100,000 docs in two full runs), peak RSS 1.4 GB. PPE rules: 1,341 docs/s on the same cores. |

**Mapping, fixed before Presidio was scored.** Presidio entity → canonical type (`PRESIDIO_TYPES` in
`src/prompt_privacy/evaluation/systems.py`): `EMAIL_ADDRESS`→EMAIL, `PHONE_NUMBER`→PHONE,
`CREDIT_CARD`→CARD, `IBAN_CODE`→IBAN, `SG_NRIC_FIN`→NRIC, `IP_ADDRESS`→IPV4 or IPV6 (by a `:` in
the span), and PERSON, LOCATION, DATE_TIME, URL, US_SSN, ORGANIZATION, AGE, MAC_ADDRESS to
themselves. Entities with no dataset counterpart (US_DRIVER_LICENSE, US_BANK_NUMBER, US_PASSPORT,
UK_NHS, NRP, MEDICAL_LICENSE, US_ITIN, CRYPTO) keep their own names: they count for any-type
coverage and the confusion table, never for typed recall. The dataset label map was extended at the
same time, from the labels' meaning, for every system: `first_name`/`last_name`→PERSON;
`city`/`county`/`state`/`country`/`street_address`→LOCATION; `date`/`date_time`/`date_of_birth`/
`time`→DATE_TIME; `url`→URL; `ssn`→US_SSN; `company_name`→ORGANIZATION; `age`→AGE;
`mac_address`→MAC_ADDRESS.

## Reproduce

```bash
# Presidio venv: bench/harness/README.md ("Presidio baseline venv"); model directory = the one with meta.json
OMP_NUM_THREADS=3 systemd-run --user --scope -q -p MemoryMax=4G -p MemorySwapMax=0 nice -n 19 taskset -c 5-7 \
  bench/harness/pvenv/bin/ppe evaluate run nemotron-pii --system presidio --model-path <spaCy model dir> \
  --data-dir /path/outside/repo --min-score 0,0.5 --json bench/results/2026-10-16-presidio-baseline/presidio.json
.venv/bin/python bench/harness/compare_reports.py bench/results/2026-10-16-presidio-baseline/head-to-head.txt \
  bench/results/2026-10-16-nemotron-pii/ppe-rules-phone-{optional,required}.json \
  bench/results/2026-10-16-presidio-baseline/presidio-min{0,0.5}.json
```

## Head to head on the types both claim

CARD, EMAIL, IPV4, IPV6 and PHONE are claimed by both systems and labelled in the dataset (PPE's
SECRET, IBAN and NRIC, and Presidio's NER types, are claimed by one side only). Same gold spans,
same matching rules:

| type | support | PPE optional R / P / F1 | PPE required R / P / F1 | Presidio ≥0 R / P / F1 | Presidio ≥0.5 R / P / F1 |
|---|---:|---|---|---|---|
| CARD | 12,867 | 0.118 / 0.762 / 0.205 | same | 0.118 / 0.773 / 0.205 | same |
| EMAIL | 53,930 | 0.995 / 0.998 / 0.996 | same | 0.992 / 0.998 / 0.995 | same |
| IPV4 | 6,078 | 1.000 / 0.655 / 0.791 | same | 1.000 / 0.655 / 0.791 | same |
| IPV6 | 3,139 | 0.905 / 0.985 / 0.944 | same | 0.908 / 0.985 / 0.945 | same |
| PHONE | 30,353 | 0.917 / 0.535 / 0.676 | **0.822 / 0.993 / 0.900** | 0.943 / 0.484 / 0.639 | 0.617 / 0.610 / 0.613 |
| **micro, shared types** | 106,367 | 0.864 / 0.766 / 0.812 | **0.837 / 0.957 / 0.893** | 0.870 / 0.729 / 0.794 | 0.777 / 0.840 / 0.807 |

R = typed recall (overlap), P = typed precision. Strict recall is within 0.011 of overlap recall for
every row above (`head-to-head.txt`).

- **Pattern types are at parity.** Recall on email, IP and card agrees to within 0.003, and
  precision too, except card (0.762 vs 0.773). Both card detectors require a valid Luhn check, and
  88% of the dataset's card numbers fail it (see the Nemotron write-up), so both find 0.118. Both
  also match IPv4 addresses inside URLs labelled `url` (3,041 and 3,039 spans).
- **Phone is where they differ.** Presidio's defaults find more phone numbers (recall 0.943), but
  over half of its phone spans fall on other labels' values (typed precision 0.484). Its own score is a
  poor lever here: at ≥0.5, recall falls to 0.617 and precision only rises to 0.610. PPE's
  `detection.phone_context=required` gives 0.822 / 0.993. On this data a context gate separates
  phone numbers from other numbers much better than Presidio's score does.

## Each system's own scope, and everything labelled

| | PPE optional | PPE required | Presidio ≥0 | Presidio ≥0.5 |
|---|---|---|---|---|
| micro over own claimed types (R / P / F1) | 0.794 / 0.771 / 0.782 | 0.769 / 0.958 / 0.853 | 0.820 / 0.559 / 0.664 | 0.802 / 0.576 / 0.670 |
| micro over every mapped type (R / P / F1) | 0.160 / 0.771 / 0.264 | 0.155 / 0.958 / 0.266 | 0.803 / 0.559 / 0.659 | 0.786 / 0.576 / 0.665 |
| any-type coverage, 850,340 gold spans | 0.144 | 0.112 | **0.747** | 0.666 |
| system spans | 122,866 | 95,945 | 949,280 | 748,177 |
| … overlapping no gold span | 546 (0.4%) | 354 (0.4%) | 146,162 (15.4%) | 136,785 (18.3%) |

The all-mapped row has the same denominator (586,978 mapped gold spans) for every system. PPE's
rules claim nothing for names, places, dates, organisations, URLs or SSNs, so most of those spans
count against it. Presidio's spaCy model covers them:

| Presidio ≥0, type | support | R overlap | R strict | P typed | F1 |
|---|---:|---:|---:|---:|---:|
| PERSON | 143,639 | 0.858 | 0.166 | 0.799 | 0.827 |
| DATE_TIME | 129,673 | 0.896 | 0.816 | 0.565 | 0.693 |
| LOCATION | 85,484 | 0.654 | 0.606 | 0.821 | 0.728 |
| ORGANIZATION | 54,837 | 0.702 | 0.611 | 0.280 | 0.400 |
| URL | 37,847 | 0.922 | 0.391 | 0.333 | 0.490 |
| US_SSN | 6,062 | 0.995 | 0.995 | 0.316 (0.809 at ≥0.5) | 0.480 (0.892) |
| MAC_ADDRESS | 4,250 | 1.000 | 0.999 | 0.997 | 0.999 |
| AGE | 7,167 | 0 | 0 | (no spans) | |

## What the numbers mean (counts from the confusion tables)

| Finding | Evidence |
|---|---|
| Most of Presidio's coverage of ID-like labels is incidental and low-confidence. Its weak US pattern recognisers fire on most alphanumeric IDs. | `US_DRIVER_LICENSE` 98,771 spans, on `account_number` 14,764, `customer_id` 13,442, `biometric_identifier` 11,361, `medical_record_number` 9,329, `bank_routing_number` 8,349; `US_BANK_NUMBER` 46,003; `US_PASSPORT` 15,780. At ≥0.5, `US_DRIVER_LICENSE` falls to 1,078, `US_BANK_NUMBER` and `US_PASSPORT` to none, and coverage of `biometric_identifier` from 0.999 to 0.171. A masking proxy still hides those values, but only because of a low-confidence guess of the wrong type. |
| Presidio's NER over-fires on organisations and dates. | ORGANIZATION: 70,140 spans on no gold span. DATE_TIME: 54,199 on no gold span, and 6,439 on card numbers, much of why Presidio "covers" 0.707 of cards while typing only 0.118 of them. |
| Presidio's URL recogniser matches the domain inside an email address. | 64,495 URL spans overlap `email` spans (typed URL precision 0.333). The address is still covered by the EMAIL span; as a URL it is a false positive. |
| Nine-digit routing numbers read as SSNs. | 7,837 US_SSN spans on `bank_routing_number`; the ≥0.5 threshold removes most (precision 0.316 → 0.809). |
| Names: the dataset labels first and last names separately. | Presidio's PERSON span usually covers the full name: overlap recall 0.858, strict 0.166. Strict matching undercounts any full-name detector here. |
| Neither system detects secrets well; Presidio has no secret recogniser. | SECRET recall: PPE 0.151 with the 2026-10-18 secret rules (0.062 before; vendor-prefixed API keys 422/447), Presidio 0. Coverage of `api_key`: PPE 0.323, Presidio 0.061. Of `password`: PPE 0.037, Presidio 0.218; the Presidio spans on passwords are mostly US_DRIVER_LICENSE (687), ORGANIZATION (455) and LOCATION (219). |
| Precision cost of coverage | 15.4% of Presidio's spans overlap no gold span, against 0.4% of PPE's. In a proxy that masks spans, a false positive costs utility (a non-sensitive value hidden from the model), not leakage. |

**For PPE.** On the pattern types the rules match a widely used baseline, and on phone numbers
they do better on precision, given the context setting. The gap is everything that needs a model:
names, places, dates, organisations, and the numeric IDs that Presidio covers only by low-confidence
guessing. That is phase 4 (span models behind the arbiter). The 0.4% vs 15.4% no-gold rate is the
budget a span model must stay within if PPE's precision is to be kept.

## Validation

- **Integration test** `test_presidio_end_to_end` (real Presidio, local model, synthetic sentence):
  email, phone and IPv4 found with the right types; NRIC not claimed; the suffix list is the offline
  snapshot. It runs only where Presidio and `PPE_PRESIDIO_MODEL` are present, under the cap. It first
  failed: Presidio labelled `jane.tan@example.test` NRP, not EMAIL, because its email recogniser
  drops a match whose domain `tldextract` cannot place (`.test` is reserved, not on the suffix list),
  so the test uses `example.com`.
- **Mutation check** (`bench/results/2026-10-16-nemotron-pii/mutation.txt`): the unmutated tree must
  pass first (a control run, added after an earlier attempt reported 18/18 when the test environment
  could not even import its tests). Then 24 faults, each caught by a named test, including Presidio
  IPv6 labelled IPv4, a model name accepted, the suffix list fetched over the network (pointed at a
  refused loopback port, so nothing leaves the host), ratios rounded twice and F1 from rounded ratios.
  Without Presidio, 23/23 with the network fault marked not run.
- **Same PPE numbers as the committed run.** Re-scored after the label map was extended: every
  per-type count for PPE's types, every per-label coverage count and the whole confusion table were
  identical to the 104aa84 results; only the all-mapped micro changed (0.785 → 0.158 recall), as it
  must once names, places and dates are counted. The PPE results were regenerated once more after
  the three detector fixes from the Gretel run (IBAN followed by a word, non-ASCII e-mail, IPv6 inside
  a word; `2026-10-16-gretel-pii-finance.md`); the PPE figures above are from that run.
- **Threshold consistency.** Every count in the ≥0.5 report is at most the ≥0 count; support is
  equal; the system configuration is identical apart from `min_score`.
- **Deterministic.** Two full Presidio runs (100,000 documents each) gave identical counts in every
  table: per type, per slice, per label and confusion; only F1 changed, in the 4th decimal, because
  the scorer's F1 rounding was fixed between them. The committed reports are from the second run. No run that was scored used a downloaded suffix list: the one
  download happened in a speed probe before the pin, and its cache was deleted; it has not
  reappeared after any later run.
- **Console logs equal the JSON.** Each `.txt` result rebuilt from its `.json` with `scoring.table`
  is byte-identical to the run's own output (checked before and after the table fixes). The table
  computes every ratio from the raw counts and rounds once; every ratio quoted above was recomputed
  from the counts, which caught two cells (PPE e-mail recall 0.995 → 0.994, URL F1 0.489 → 0.490)
  printed by the earlier double rounding.
- **No dataset text in the results** (`bench/harness/leak_scan.py nemotron-pii …`, output `leak_scan.txt`): no run
  of 35 or more characters of any document appears in any result file, once the 55 label names (the
  published schema, which some documents use as record keys) are masked. A planted 60-character
  excerpt was caught (exit 1) before and after masking. The 1,077 gold values that occur in the files
  are 4–5 digit numbers that are our own counts, label names, common words (`support`, `value`), Presidio
  recogniser names, `Singapore` (from our note) and the run date. The write-ups themselves were scanned too: two 24-character windows
  matched, both ordinary English from our own prose ("the system configuration", "before and after
  the").

## Comparability

PIIBench (arXiv 2604.15776) reports Presidio F1 0.1385 on its own data, labels and matching rules;
that number does not compare with the tables above. Like-for-like comparison holds only for systems
run through this harness against this pin and label map, and `compare_reports.py` refuses reports
from different pins or limits. The same comparison on Gretel `synthetic_pii_finance_multilingual`:
[`2026-10-16-gretel-pii-finance.md`](2026-10-16-gretel-pii-finance.md). Next, for secrets: Samsung
CredData.
