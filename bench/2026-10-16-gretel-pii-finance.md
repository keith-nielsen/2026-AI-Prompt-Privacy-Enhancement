# External benchmark: PPE rules and Presidio on Gretel synthetic PII finance (2026-10-16)

> **Pre-alpha.** The second public dataset through `ppe evaluate`, with the same protocol, scorer and
> Presidio set-up as the Nemotron run ([`2026-10-16-nemotron-pii.md`](2026-10-16-nemotron-pii.md),
> [`2026-10-16-presidio-baseline.md`](2026-10-16-presidio-baseline.md)). It adds what Nemotron lacks:
> IBANs, SWIFT codes, financial document formats (EDIFACT, FpML, SWIFT MT, XML) and six languages besides
> English. Synthetic data; the gold labels are partly machine-made (see below), so precision here is a
> floor, not a measurement.

Results: `bench/results/2026-10-16-gretel-pii-finance/` (head-to-head in `head-to-head.txt`).

## Dataset

| | |
|---|---|
| Dataset | [`gretelai/synthetic_pii_finance_multilingual`](https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual), default `test` split |
| Pin | revision `7b844d16738527a04264f50214cb426a4cea0897`, file `data/test-00000-of-00001.parquet`, 5,422,540 bytes, SHA-256 `014e1057978f030fce4f4cad7c93b9e3377fd0ded713d2bf4c7de00e3e3c8c72` (the Hub's LFS record); fetched with `ppe evaluate fetch`, kept only on an exact match |
| Licence | Apache-2.0. Attribution: *Synthetic-PII-Financial-Documents-North-America*, Watson, Meyer, Van Segbroeck, Grossman, Torbey, Mlocek, Greco; Gretel, 2024. No records are redistributed here; only aggregate counts. |
| Content | 5,594 documents (the card's prose says 5,164; its metadata and the file say 5,594), mean 1,303 characters, 37,017 gold spans, 29 labels. Languages: English 2,962, German 476, Dutch 447, Spanish 444, Italian 441, Swedish 430, French 394 (the file's value is `France`). |
| Gold quality | The card: spans were labelled with the help of an NER library (GLiNER), filtered by an LLM judge and spot-checked by people; "some errors may still be present". Measured on the text at each span (counts only): 27 spans in 8 documents end past their text (dropped and counted, `gold_dropped_out_of_range`); 409 pairs of gold spans overlap; 66 of 120 card numbers fail Luhn; 44 of 203 IBANs fail mod 97; 41 of 1,422 e-mails have no `@` and 111 include a bracket around them (`[a@b.c]`); 19 phone numbers contain no digit; 25 IPv6 spans touch a further colon (cut out of a longer colon-separated run, or `label:address`). |

The data lives outside the repository and is never committed.

**Label map, fixed before either system was scored on this dataset** (`GRETEL_PII_FINANCE` in
`src/prompt_privacy/evaluation/datasets.py`), with Nemotron's choices where the labels agree:
`email`→EMAIL, `phone_number`→PHONE, `credit_card_number`→CARD, `iban`→IBAN, `ipv4`/`ipv6`,
`api_key`/`password`→SECRET, `name`/`first_name`/`last_name`→PERSON, `street_address`→LOCATION,
`date`/`date_of_birth`/`date_time`/`time`→DATE_TIME, `company`→ORGANIZATION. `ssn` is left unmapped:
the tag names follow Python Faker, whose `ssn()` is locale-specific (a Swedish personnummer, a Dutch
BSN), so it is not one type across the seven languages. The other 12 labels (`bban`, `swift_bic_code`,
`customer_id`, …) count for any-type coverage only.

## Reproduce

```bash
.venv/bin/ppe evaluate fetch gretel-pii-finance --data-dir /path/outside/repo
.venv/bin/ppe evaluate run gretel-pii-finance --data-dir /path/outside/repo --phone-context optional \
    --json bench/results/2026-10-16-gretel-pii-finance/ppe-rules-phone-optional.json      # and required
# Presidio (bench/harness/README.md), under the usual cap: 2.5 min, 1.05 GB peak, 39 docs/s
bench/harness/pvenv/bin/ppe evaluate run gretel-pii-finance --system presidio --model-path <spaCy model dir> \
    --data-dir /path/outside/repo --min-score 0,0.5 --json bench/results/2026-10-16-gretel-pii-finance/presidio.json
.venv/bin/python bench/harness/compare_reports.py bench/results/2026-10-16-gretel-pii-finance/head-to-head.txt \
    bench/results/2026-10-16-gretel-pii-finance/{ppe-rules-phone-optional,ppe-rules-phone-required,presidio-min0,presidio-min0.5}.json
.venv/bin/python bench/harness/miss_shapes.py gretel-pii-finance /path/outside/repo \
    bench/results/2026-10-16-gretel-pii-finance/miss_shapes.txt
```

## Detector fixes this run found (PPE bugs, now fixed and tested)

| Bug | Effect before the fix | After (Gretel / Nemotron) |
|---|---|---|
| **An IBAN followed by a word was never reported.** The optional space in the IBAN pattern let the match run on into the next words; the longer string failed mod 97 and nothing was reported. Earlier tests and the stdnum cross-check only put an IBAN before a full stop. Now every cut at a space is tried, longest first. | `pay DE89370400440532013000 and more`: no finding | IBAN found 153 → 157 / findings 16 → 59, on `account_number` 5 → 22 |
| **E-mail with non-ASCII letters was missed** (RFC 6531 local parts, IDNA domains: `anna@företag.se`). | 8 of the 14 missed addresses that contain an `@` | e-mail found 1,367 → 1,375 / 53,632 → 53,647 |
| **An IPv6 match could start or end inside a word.** EDIFACT uses `::` as a separator, so `Name::2`, `ID::9` and `Zip::4` gave IPv6 findings. | 39 false IPv6 findings | IPv6 findings 175 → 136, precision 0.623 → 0.801, recall unchanged / 6 fewer findings and 5 overlap hits lost, all on gold values that are not valid IPv6 |

The IPv6 fix also clears 4 of the 10 code snippets in conformance claim C-07 (review finding F-02:
`std::io`, `ns::util`, `Foo::Bar`, `a::before`); C-07 still fails on the other 6. Every figure below
and in the two Nemotron write-ups is from the fixed detector.

## Head to head on the types both claim

CARD, EMAIL, IBAN, IPV4, IPV6 and PHONE (R = typed recall, overlap; P = typed precision):

| type | support | PPE optional R / P / F1 | PPE required R / P / F1 | Presidio ≥0 R / P / F1 | Presidio ≥0.5 R / P / F1 |
|---|---:|---|---|---|---|
| CARD | 120 | 0.450 / 0.462 / 0.456 | same | 0.375 / 0.776 / 0.506 | same |
| EMAIL | 1,422 | 0.967 / 0.965 / 0.966 | same | 0.961 / 0.965 / 0.963 | same |
| IBAN | 203 | 0.773 / 0.938 / 0.848 | same | 0.768 / 0.968 / 0.857 | same |
| IPV4 | 162 | 0.988 / 1.000 / 0.994 | same | 0.981 / 1.000 / 0.991 | same |
| IPV6 | 134 | 0.813 / 0.801 / 0.807 | same | 0.813 / 0.801 / 0.807 | 0.813 / 0.813 / 0.813 |
| PHONE | 946 | 0.729 / 0.511 / 0.601 | **0.594 / 0.900 / 0.716** | 0.785 / 0.251 / 0.380 | 0.332 / 0.680 / 0.446 |
| **micro, shared types** | 2,987 | 0.852 / 0.758 / 0.802 | **0.809 / 0.919 / 0.861** | 0.863 / 0.526 / 0.654 | 0.720 / 0.899 / 0.799 |

- **Pattern types are close.** E-mail, IPv4, IPv6 and IBAN agree to within 0.007 in recall. Both
  systems check IBAN mod 97, so the 44 invalid gold IBANs (22%) are missed by both; German IBAN recall
  is 0.346 for both, because most German gold IBANs are invalid. E-mail strict recall is lower than
  overlap recall (PPE 0.911): 75 of PPE's 79 strict misses are gold spans that include their brackets.
  PPE's 25 IPv6 misses are exactly the 25 gold spans that touch a further colon; the pattern refuses
  to start or end next to a colon, so as not to report a piece of a longer run.
- **Cards: PPE has no IIN check.** PPE finds all 54 Luhn-valid gold cards (recall 0.450 = 54/120;
  the other 66 fail Luhn) but 62 of its 117 card findings fall on no gold span, and 51 of those 62 have
  no valid card-brand prefix and length: account and reference numbers that pass Luhn by chance
  (about 1 in 10 random numbers do). Presidio's card recogniser checks brand patterns: 0.776 precision
  at 0.375 recall. ADR-0005 specifies Luhn plus IIN ranges for cards; the IIN part is not built (C-08,
  F-02).
- **Phone: same trade-off as on Nemotron, plus a language gap** (next section).

## Each system's own scope, everything labelled, and noise

| | PPE optional | PPE required | Presidio ≥0 | Presidio ≥0.5 |
|---|---|---|---|---|
| micro over own claimed types (R / P / F1) | 0.812 / 0.760 / 0.785 | 0.771 / 0.919 / 0.839 | 0.646 / 0.288 / 0.398 | 0.633 / 0.292 / 0.399 |
| micro over every mapped type (R / P / F1) | 0.073 / 0.760 / 0.134 | 0.070 / 0.919 / 0.130 | 0.642 / 0.288 / 0.398 | 0.630 / 0.292 / 0.399 |
| any-type coverage, 36,990 gold spans | 0.074 | 0.068 | **0.758** | 0.727 |
| system spans | 3,376 | 2,652 | 106,870 | 85,276 |
| … overlapping no gold span | 664 (19.7%) | 167 (6.3%) | 72,218 (67.6%) | 53,753 (63.0%) |

PPE's claimed scope here also includes SECRET (191 gold spans; recall 0.178: 25 of the 32
vendor-prefixed API keys, 3 generic keys and 6 passwords; the 7 prefixed keys missed are 41-character
`AIza…` strings, two longer than real Google keys). Presidio has no secret recogniser. The no-gold share is far
higher than on Nemotron (PPE 0.4%, Presidio 15.4%) for both systems: part of it is real noise, part is
values the machine-made labels missed (the card says so; for example, 10 PPE IBAN findings with valid
check digits sit on no gold span). Read precision on this dataset as a lower bound.

Presidio's NER is weaker on financial documents than on Nemotron's prose:

| Presidio ≥0, type | support | R overlap | R strict | P typed | F1 | spans on no gold span |
|---|---:|---:|---:|---:|---:|---:|
| PERSON | 10,792 | 0.643 | 0.408 | 0.288 | 0.398 | 14,262 |
| DATE_TIME | 10,554 | 0.742 | 0.574 | 0.652 | 0.694 | 3,514 |
| ORGANIZATION | 6,341 | 0.605 | 0.347 | 0.119 | 0.199 | 26,361 |
| LOCATION | 4,304 | 0.326 | 0.000 | 0.249 | 0.282 | 5,830 |

LOCATION strict recall is 0 because the gold label is `street_address`, a whole address, and spaCy
marks the city or country inside it. Presidio's weak US pattern recognisers fire here too:
`US_DRIVER_LICENSE` 11,402 spans (9,906 on no gold span), `US_BANK_NUMBER` 5,936.

## By language

Presidio runs `en_core_web_lg` on every document (its default set-up is English only); PPE's rules
have no language. Shared-type micro and Presidio's PERSON recall per language:

| language | docs | PPE required R / P | Presidio ≥0 R / P | Presidio PERSON R |
|---|---:|---|---|---:|
| English | 2,962 | 0.842 / 0.922 | 0.866 / 0.576 | 0.742 |
| German | 476 | 0.822 / 0.910 | 0.795 / 0.430 | 0.654 |
| Dutch | 447 | 0.726 / 0.928 | 0.870 / 0.489 | 0.550 |
| Spanish | 444 | 0.810 / 0.971 | 0.820 / 0.432 | 0.480 |
| Italian | 441 | 0.816 / 0.921 | 0.876 / 0.456 | 0.614 |
| Swedish | 430 | 0.776 / 0.978 | 0.865 / 0.506 | 0.555 |
| French | 394 | 0.667 / 0.794 | 0.921 / 0.507 | 0.580 |

The gap in PPE's column is phone numbers:

| language | phone support | PPE optional R / P | PPE required R / P | Presidio ≥0 R / P |
|---|---:|---|---|---|
| English | 532 | 0.718 / 0.502 | 0.658 / 0.877 | 0.763 / 0.285 |
| German | 49 | 0.939 / 0.548 | 0.816 / 0.909 | 0.735 / 0.158 |
| Spanish | 71 | 0.901 / 0.587 | 0.732 / 0.981 | 0.775 / 0.202 |
| Italian | 63 | 0.825 / 0.456 | 0.746 / 0.904 | 0.937 / 0.227 |
| Dutch | 69 | 0.725 / 0.568 | 0.333 / 0.920 | 0.783 / 0.222 |
| Swedish | 75 | 0.667 / 0.510 | 0.413 / 1.000 | 0.693 / 0.206 |
| French | 87 | 0.529 / 0.479 | 0.218 / 0.947 | 0.931 / 0.288 |

Two causes, both in `src/prompt_privacy/detectors/patterns.py`: national formats are SG, NANP and UK
shapes only (French `01 23 45 67 89` is none of them), and the context words that
`phone_context=required` looks for are English (`phone`, `call`, `mobile`, …; only `tel`, `fax` and
`sms` work across these languages). The `detection.phone_context` knob text now says so. Adding
national formats and per-language context words is a detector change for phase 4 or earlier.

## Validation

- **Detector fixes:** each has tests that failed before the fix (`tests/detectors/test_patterns.py`:
  `test_iban_followed_by_words`, `test_email_with_non_ascii_letters`, `test_ipv6_not_inside_words`)
  and a mutation that restores the old code and must be caught. The stdnum cross-check (680 valid
  IBANs, 85 countries) still passes. C-07's strict xfail now applies per snippet: the 4 fixed snippets
  must pass, the 6 open ones stay strict xfail.
- **Loader:** `row_doc` reads per-dataset columns and JSON spans (`json.loads`, never `eval`); a span
  outside its text is still an error unless the dataset declares `out_of_range="drop"`, and dropped
  spans are counted in the report. Tests cover both, and a mutation that drops everywhere is caught.
- **Mutation check** (`bench/results/2026-10-16-nemotron-pii/mutation.txt`): control run first, then
  **24/24** faults caught with Presidio installed, 23/23 without.
- **Every PPE result was regenerated with the fixed detector**, on both datasets: per type, only the
  types named in the fixes table changed (Nemotron: IBAN, EMAIL, IPV6, and CARD and PHONE by 1 and 3
  findings that are now IBANs). Every ratio in this document and the two Nemotron documents was
  recomputed from the raw counts in the JSON reports and checked against the text.
- **No dataset text in the results** (`bench/harness/leak_scan.py gretel-pii-finance …`, output
  `leak_scan.txt`): no run of 35+ characters of any document in any result file; a planted 60-character
  excerpt is caught. The 62 gold values that occur in the files are common words (`name`, `address`),
  4-digit counts, `Italia` (from "Italian"), `Pass` (Presidio's passport recogniser name) and two
  surnames that are also the dataset authors' names in the attribution.
- **Presidio** ran offline (bundled suffix list; no cache appeared) from the local model directory.

## Comparability

Gretel's card reports no detection baseline. The numbers above compare only with systems run through
this harness against this pin and label map. Next dataset: Samsung CredData for secrets, where both
systems are weakest here.
