# External benchmark: PPE rules on NVIDIA Nemotron-PII (2026-10-16)

> **Pre-alpha.** First run of PPE against a public labelled dataset. It measures Stage 1 (the
> deterministic rules) only; span models and the arbiter are not built. Numbers describe this
> dataset, which is synthetic and US-centred, not real-world accuracy.

## Dataset

| | |
|---|---|
| Dataset | [`nvidia/Nemotron-PII`](https://huggingface.co/datasets/nvidia/Nemotron-PII), test split |
| Pin | revision `b70ffaf5ff39e079776134c5bf4381f00a9fd1ed`, file `data/test-00000-of-00001.parquet`, 150,968,398 bytes, SHA-256 `1a4b0512ecb5370f0992d29d0f9c07351e6de13f0d7ea33bb18cecb984780247` (matches the Hub's LFS record) |
| Licence | CC BY 4.0. Attribution: *Nemotron-PII: Synthesized Data for Privacy-Preserving AI*, Steier, Manoel, Haushalter, Van Segbroeck; NVIDIA, 2025. No records are redistributed here; only aggregate counts derived from them. |
| Content | 100,000 rows: 50,000 uids, each once with `locale=us` and once with `locale=intl` (different texts; the card's "50k test" counts uids). 850,340 gold spans, 55 labels. Fully synthetic. |
| Offsets | Authoritative. Every span's stored `text` equals the text at its offsets, except for letter case (6,195) or an integer-typed value (6,747). The scorer uses offsets only. |
| Not in it | Singapore NRIC/FIN, IBAN as a label. PPE's NRIC and IBAN detectors are scored for precision only. |

The data lives outside the repository (`--data-dir`) and is never committed.

## Reproduce

```bash
uv pip install --python .venv/bin/python -e ".[bench]"           # pyarrow
.venv/bin/ppe evaluate fetch nemotron-pii --data-dir /path/outside/repo   # kept only if size + SHA-256 match
.venv/bin/ppe evaluate run nemotron-pii --data-dir /path/outside/repo --phone-context optional \
    --json bench/results/2026-10-16-nemotron-pii/ppe-rules-phone-optional.json
.venv/bin/python bench/harness/miss_shapes.py nemotron-pii /path/outside/repo \
    bench/results/2026-10-16-nemotron-pii/miss_shapes.txt                    # why spans are missed
.venv/bin/python bench/harness/mutate_evaluation.py                          # negative proof of the tests
```

`run` re-checks the file's SHA-256 before scoring. Full split: about 80 s at about 1,250 docs/s on
three cores (`nice -n 19 taskset -c 5-7`). Results: `bench/results/2026-10-16-nemotron-pii/`.

## Protocol (`src/prompt_privacy/evaluation/scoring.py`)

One protocol for every system, so Presidio (done) or a later span-model run is scored identically.

- **Label map.** A dataset label maps to a canonical type only when *every* span with that label is
  that type: `email`→EMAIL, `phone_number`/`fax_number`→PHONE, `credit_debit_card`→CARD,
  `ipv4`→IPV4, `ipv6`→IPV6, `api_key`/`password`→SECRET. For the Presidio baseline the map was
  extended, before Presidio was scored and the same for every system, to types PPE's rules do not
  claim: `first_name`/`last_name`→PERSON, `city`/`county`/`state`/`country`/`street_address`→LOCATION,
  `date`/`date_time`/`date_of_birth`/`time`→DATE_TIME, `url`→URL, `ssn`→US_SSN,
  `company_name`→ORGANIZATION, `age`→AGE, `mac_address`→MAC_ADDRESS. The other 31 labels
  (`account_number`, `customer_id`, `postcode`, …) are scored for any-type coverage only.
- **Two micro averages.** Over the types the system claims (its own scope; for PPE's rules: CARD,
  EMAIL, IPV4, IPV6, PHONE, SECRET, IBAN, NRIC, of which the first six have labels), and over every
  mapped type (the same 586,978 gold spans for every system).
- **Compatible labels** count for precision only (they can hold the type among other things):
  IBAN on `account_number`, NRIC on `national_id`, SECRET on `http_cookie`.
- **Recall, overlap:** a mapped gold span is found when a finding *of the same type* overlaps it.
  **Recall, strict:** same type and identical offsets.
- **Precision, typed:** a finding overlaps a gold span of its type (or a compatible label).
  **Precision, any label:** it overlaps any gold span, because a value swapped under the wrong type
  still did not leave. Unlabelled real identifiers would count as false positives; the dataset is
  synthetic, so few should exist.
- **Any-type coverage:** for every one of the 55 labels, the share of gold spans overlapped by any
  finding: what the rules protect today, including labels they do not claim.

## Results (`ppe-rules` 0.1.0.dev1, after the IPv4 fix below, the three detector fixes from the Gretel run, and the 2026-10-18 secret rules: Gitleaks import, v3)

`phone_context=optional` (the shipped default in all three profiles):

| type | support | R overlap | R strict | findings | P typed | P any | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| CARD | 12,867 | 0.118 | 0.118 | 1,996 | 0.762 | 0.993 | 0.205 |
| EMAIL | 53,930 | 0.995 | 0.994 | 53,770 | 0.998 | 1.000 | 0.996 |
| IPV4 | 6,078 | **1.000** | 1.000 | 9,284 | 0.655 | 0.983 | 0.791 |
| IPV6 | 3,139 | 0.905 | 0.905 | 2,885 | 0.985 | 0.985 | 0.944 |
| PHONE | 30,353 | 0.917 | 0.906 | 52,035 | 0.535 | 0.994 | 0.676 |
| SECRET | 11,652 | 0.151 | 0.128 | 2,834 | 0.981 | 0.992 | 0.262 |
| IBAN | (no label) | | | 59 | 0.373 | 0.932 | |
| NRIC | (no label) | | | 3 | 1.000 | 1.000 | |
| **micro, claimed types** | 118,019 | 0.794 | 0.788 | 122,804 | 0.771 | 0.996 | 0.782 |
| micro, all mapped types | 586,978 | 0.160 | 0.158 | 122,804 | 0.771 | 0.996 | 0.264 |

`phone_context=required` changes PHONE only: recall 0.822, typed precision **0.993**, F1 0.900;
micro over claimed types: recall 0.769, precision 0.958, F1 0.853 (all mapped types: 0.155 / 0.958 /
0.266). The all-mapped micro counts names, places, dates and the other spaCy-style types against
the rules, which claim none of them; Presidio's numbers on the same denominator are in
[`2026-10-16-presidio-baseline.md`](2026-10-16-presidio-baseline.md).

Any-type coverage over all 850,340 gold spans: **0.144** (optional) / 0.112 (required). Names,
addresses, dates, SSNs, account numbers and the like need span models (phase 4) or rules not yet
written; the per-label table is in the `.txt` results.

Ratios in these tables are computed from the raw counts and rounded once. (Until 2026-10-16 the
console table re-rounded the 4-place ratios stored in the JSON, which printed an EMAIL recall of
0.99447 as 0.995, and F1 was computed from rounded ratios; both fixed, the counts were never affected.)

**Detector fixes found on the Gretel finance run** (`2026-10-16-gretel-pii-finance.md`), and their
effect here: an IBAN followed by a word was never reported (the match ran on into the word and failed
mod 97): 16 → 59 IBAN findings, 5 → 22 on `account_number`. E-mail with non-ASCII letters (RFC 6531,
IDNA) was missed: 15 more gold e-mails found (53,632 → 53,647). An IPv6 match may no longer start or
end inside a word: 6 fewer findings, and 5 overlap hits lost, all on gold values that are not valid
IPv6 (`…:abcd:efgh`), where the old pattern matched a valid-looking prefix. Card and phone each lost
1 and 3 findings to IBANs found on the same spans.

## What the numbers mean (from `miss_shapes.txt`, counts only)

| Type | Finding | Kind |
|---|---|---|
| CARD | 11,271 of 12,867 gold card numbers (88%) **fail the Luhn check**. Real card numbers cannot. PPE's strict detector rejects them by design (and G2 surrogates rely on invalid check digits). On the 1,525 Luhn-valid gold cards, recall is **0.995** (1,517). | dataset property |
| SECRET | 4,220 of 4,667 `api_key` spans are generic random strings with no vendor prefix: 1,081 found with the 2026-10-18 secret rules (64 before; Gitleaks' generic rule matches a key word and a random value, and the Bearer rule adds tokens after `Bearer`). Vendor-prefixed keys: 422 of 447 found (0.944; 409 before). `password` values are found in assignment or URL form only: 257 of 6,985 (246 before). v0.1.0.dev2 found 215: its placeholder filter (Gitleaks' 1,448 stop words) dropped 44 real passwords; rules v3 drop only placeholders, values naming a kind of credential (2 real `Password123`-style passwords lost), templates and code. | scope of Stage 1 |
| IPV4 | **Bug, fixed here.** An address that ends a sentence (`… 192.0.2.10.`) was never detected: the regex refused any following dot. That was 1,233 of the 1,234 misses. Now 6,077 of 6,078 (the one left has an octet above 255). Typed precision 0.655 because 3,041 findings sit inside URLs labelled `url`; they count under P any. | PPE bug |
| IPV6 | 287 of the 297 missed gold values are not valid IPv6 addresses (Python's `ipaddress` rejects them). | dataset property |
| PHONE | Misses (2,525): international numbers with a one-digit group (`+353 1 …`, `+33 6 12 …`; 802), other international (50), and national formats outside SG/NANP/UK (1,673; 9-digit and others). With `optional`, nearly half of all phone findings land on other numeric IDs (biometric IDs, customer IDs, MRNs); `required` removes nearly all of them at a 9.5-point recall cost. This is the `detection.phone_context` trade-off, now measured on external data. | scope and knob |
| EMAIL | 273 of the 283 misses are gold "emails" with no `@`. | dataset property |
| IBAN | 59 findings, 22 on account numbers and 4 on no gold span; the rest on other ID labels (customer, employee, health-plan IDs, user names, URLs). `iban_valid` checks mod 97 only (see the stdnum cross-check below). | PPE gap (precision) |

Before the IPv4 fix (same data, same protocol): IPV4 recall 0.797, typed precision 0.602, F1 0.686;
micro recall 0.774, F1 0.770.

## Independent check-digit reference: python-stdnum 2.2

`tests/unit/test_checksums_stdnum.py` compares PPE's check-digit code with
[python-stdnum](https://arthurdejong.org/python-stdnum/) (LGPL-2.1+, a test-only dependency PPE
never imports):

| Check | Result |
|---|---|
| Luhn validity and check digit, hypothesis-generated digit strings | identical |
| IBAN check digits, all 89 countries in stdnum's registry | identical |
| Every stdnum-valid IBAN (680 generated, 85 countries) is accepted by `iban_valid` **and found by `detect`**, compact and printed in groups, at the end of a sentence | yes |
| Corpus generator's cards and IBANs (500 each) | valid for stdnum |
| PPE card and IBAN surrogates (500 each, guarantee G2) | **invalid for stdnum**: the "deliberately invalid" guarantee holds against an outside implementation |
| `iban_valid` rejects what stdnum's registry rejects (unknown country, wrong length or layout) | **no**: in an exploratory run, 19,996 of 20,000 random mod-97-valid strings passed PPE and failed stdnum. Recorded as a strict xfail (`test_iban_rejects_what_the_registry_rejects`); cost is precision, not leakage. |
| Singapore NRIC/FIN | no reference: stdnum 2.2 has `sg.uen` only |

## Validation of the harness itself

- **Unit tests** (`tests/evaluation/`): each scoring view on hand-built documents (strict vs overlap,
  wrong type, many-to-one labels, unmapped labels, compatible labels, false positives, adjacency,
  slices); dataset pins exact; span parser rejects out-of-range spans, wrong types and code
  (`ast.literal_eval` builds literals only); download kept only on exact size and hash, aborted while
  streaming when too long, nothing left behind on mismatch; tampered or missing file refused;
  parquet reading; an end-to-end `ppe evaluate run` whose output must not contain the input's text.
- **Mutation check** (`bench/harness/mutate_evaluation.py`, output `mutation.txt`): a control run
  on the unmutated tree must pass first; then deliberate faults in the scorer, downloader, parser,
  check-digit code, surrogates, detector and Presidio wrapper. First run: 13 faults, 12 caught; the
  survivor (the streaming size cap) got its own test. Now 24 faults, **24/24** caught with Presidio
  installed (23/23 without, the Presidio-gated fault marked not run).
- **No dataset text in the results** (`bench/harness/leak_scan.py nemotron-pii …`; output in
  `bench/results/2026-10-16-presidio-baseline/leak_scan.txt`, covering both result directories):
  every gold value of length ≥ 4 (283,260 distinct) is searched for in the committed result files,
  and every run of 35+ characters of document text, with the 55 label names masked. No document
  text; the value matches are coincidences: our own counts, label names, words from our own notes,
  the date, and the column name `support`. A planted excerpt is caught.
- **Fetch exercised against the Hub:** `ppe evaluate fetch` downloaded the pinned file in 10 s,
  byte-identical to the separately downloaded copy, and a second call did no download.

## Comparability

`nvidia/gliner-PII` reports strict F1 0.87 on Nemotron-PII (threshold 0.3, all 55 labels, trained on
the train split of the same dataset); `docs/sources/detector-models.md`. That is not comparable with
the table above: different label set, different matching rules, in-distribution training. The
comparison becomes like-for-like only when other systems run through this harness with this label
map. Done for Presidio: [`2026-10-16-presidio-baseline.md`](2026-10-16-presidio-baseline.md), and on a
second dataset: [`2026-10-16-gretel-pii-finance.md`](2026-10-16-gretel-pii-finance.md). Next: CredData
for secrets.
