# Break-glass and privileged access in the real world — case studies and lessons (2026-10-02)

Purpose: validate ADR-0010/0011 (sealed audit, two-approver break-glass) against what has actually
happened when high-security access controls were **defeated**, **locked out legitimate users**, or
**served (or failed) as evidence after the fact**; then project the lessons onto quantum computing
and increasingly capable AI. Method: web research on 2026-10-02; mostly secondary reporting of
official findings (GAO, NYDFS, CSRB, regulators, company post-mortems). Confidence is noted where a
claim is disputed. The most damaging incidents are often never published, so this is a lower bound
on what can go wrong.

## 1. Defeated — valid controls bypassed with invalid or misused credentials

| Case | What failed | Lesson for PPE |
|---|---|---|
| **Bybit, Feb 2025 (~US$1.5 B)** — Lazarus compromised a Safe{Wallet} developer machine and injected JavaScript into `app.safe.global`. Bybit's multisig signers saw a legitimate-looking transfer and signed a transaction that handed over the cold wallet ([BleepingComputer](https://www.bleepingcomputer.com/news/security/lazarus-hacked-bybit-via-a-breached-safe-wallet-developer-machine/), [The Block](https://www.theblock.co/post/343530)) | **Multi-party approval defeated by tampering with what approvers saw.** Every signature was valid; the display lied | Approvers must verify **what they sign on an independent device** (WYSIWYS), never only on the broker's or requester's UI |
| **Ronin bridge, Mar 2022 (~US$620 M)** — 5 of 9 validator keys: Sky Mavis held 4, and an Axie DAO allowlist granted in Nov 2021 "was discontinued in December 2021 but the allowlist wasn't revoked" ([Forklog](https://forklog.com/en/ronin-sidechain-developers-reveal-further-details-of-625-million-hack/), [The Block](https://www.theblock.co/post/154590/axie-infinitys-ronin-ethereum-bridge-officially-reopens-following-hack)) | **Threshold defeated by concentration + a stale delegation** | Approvers must be independent of each other; delegations and roles expire automatically; roster review is a control |
| **Arup, Jan 2024 (US$25.6 M)** — Hong Kong finance employee joined a video call where the CFO and colleagues were deepfakes; 15 transfers ([CNN via ABC17](https://abc17news.com/money/cnn-business-consumer/2024/05/16/british-engineering-giant-arup-revealed-as-25-million-deepfake-scam-victim/)) | **Human recognition as an approval factor defeated by generative AI** | No approval by voice, video, chat or e-mail; only hardware-key signatures over the exact request |
| **Twitter, Jul 2020** — phone spear-phishing posing as IT about VPN problems, credentials + MFA codes relayed live; one internal tool reached every account. NYDFS: five controls that would have prevented it "existed, were documented, and were available" ([NYDFS report](https://www.dfs.ny.gov/Twitter_Report)) | Phishable MFA; an all-powerful admin tool | Phishing-resistant FIDO2 only; no "god tool"; scope every session |
| **Uber, Sep 2022** — MFA push fatigue + WhatsApp "IT" message; then a PowerShell script on a share with **hard-coded admin credentials for the PAM system (Thycotic)** ([Appsecco](https://appsecco.com/blog/how-was-uber-hacked-and-what-can-we-learn-from-the-incident)) | The privileged-access vault itself unlocked by a static secret | The broker must have **no static admin secret** anywhere; push-approval MFA is not acceptable |
| **Okta support system, Sep–Oct 2023** — stolen credential into the support case system; **HAR files** customers uploaded for troubleshooting held session tokens; 134 customers' files accessed, sessions of 5 hijacked (incl. 1Password, BeyondTrust, Cloudflare) ([The Hacker News](https://thehackernews.com/2023/11/oktas-recent-customer-support-data.html), [BleepingComputer](https://www.bleepingcomputer.com/news/security/okta-breach-134-customers-exposed-in-october-support-system-hack/amp/)) | Troubleshooting artefacts were bearer secrets | Session credentials must be **bound to the holder's hardware key** (useless if copied); diagnostics never contain session material |
| **LastPass, 2022** — a senior DevOps engineer, **one of four** with access to vault-backup decryption keys, was keylogged through an unpatched Plex server on their home computer ([Wikipedia summary](https://en.wikipedia.org/wiki/2022_LastPass_data_breach), [The Hacker News](https://thehackernews.com/2023/02/lastpass-reveals-second-attack.html)) | Key holders' personal endpoints were the real perimeter | **No person's device ever holds the key** (ADR-0011 already); approver devices dedicated and managed |
| **Microsoft Storm-0558, 2023** — a stolen MSA signing key forged tokens for 22 organisations. The CSRB found Microsoft "has no evidence or logs showing the stolen key's presence in or exfiltration from a crash dump", and that automatic key rotation and limiting key scope would likely have prevented it ([TechTarget](https://www.techtarget.com/cybersecurity/news/366577765/Cyber-Safety-Review-Board-slams-Microsoft-security-failures), [CyberScoop](https://cyberscoop.com/microosft-csrb-china-hacking/)) | Long-lived, broad-scope key outside hardware; missing evidence of its handling | Keys in hardware, scoped per period, rotated; **every key operation sealed-logged and retained** |
| **Microsoft / Midnight Blizzard, 2024** — password spray on a **legacy non-production test tenant without MFA**, then a forgotten, over-privileged test OAuth app reached corporate mailboxes ([CSA](https://cloudsecurityalliance.org/articles/the-latest-microsoft-midnight-blizzard-breach-is-a-wakeup-call-for-saas-security)) | Test artefacts with production power | Dev/test keys **refused** in production (ADR-0010 rail) and expiring; inventory every principal |
| **Snowden / NSA, 2013** — a SharePoint administrator moved data out; the NSA then introduced a **two-person rule** for system administrators, modelled on nuclear-weapons handling ([Infosecurity](https://www.infosecurity-magazine.com/news/nsa-to-implement-two-man-rule-in-wake-of-snowden/), [GovInfoSecurity](https://www.govinfosecurity.com/nsa-moves-to-avert-snowden-like-leaks-a-6284)) | Single trusted administrator | Validates two-person integrity; also: **broker administrators must not be able to see sessions** |
| **Barings, 1995 / Société Générale, 2008** — Leeson controlled front and back office ([RBA](https://www.rba.gov.au/publications/bulletin/1995/nov/1.html)); Kerviel, ex-back-office, "misappropriated the IT access codes belonging to operators" and knew the controls ([CNBC](https://www.cnbc.com/id/23007201), [Risk.net](https://www.risk.net/risk-management/1506466/reports-highlight-sg-weaknesses)) | Segregation of duties missing; borrowed credentials; insider knowledge of controls | Disjoint roles enforced in hardware policy; credentials that can't be lent (FIDO2 + user verification); assume insiders know the design |
| **Coinbase, Dec 2024–May 2025** — overseas support agents **bribed** to extract data on 69,461 customers; US$20 M extortion attempt refused ([The Hacker News](https://thehackernews.com/2025/05/coinbase-agents-bribed-data-of-1-users.html), [CyberInsider](https://cyberinsider.com/coinbase-says-insider-data-breach-impacted-over-69000-users/)) | Legitimate access sold | Least-privilege scope, volume caps per session, view-only default, watermarking, approver diversity |
| **Bangladesh Bank, Feb 2016 (US$81 M)** — malware sent SWIFT orders with valid credentials and **doctored the printed confirmations** ([PYMNTS](https://www.pymnts.com/news/security-and-risk/2018/bangladesh-bank-heist-swift-phishing-scam-fraud-doj/)) | The evidence channel ran on the compromised system | Integrity verification and approver notifications on an **independent** channel |
| **Minuteman PAL "00000000"** (claim by Bruce Blair: SAC set launch-enable codes to zeros until 1977 so they'd be available; the Air Force says such a code "has never been used to enable" a missile — **disputed**) ([Wikipedia](https://en.wikipedia.org/wiki/Permissive_action_link), [Nextgov](https://www.nextgov.com/digital-government/2014/01/pentagon-insists-nuclear-missile-launch-code-was-never-00000000/77351/)) | (if true) a control neutered by operators who feared lockout | A control that blocks legitimate urgent work **will be bypassed**. The emergency path must be usable |

## 2. Prevented — locked down so hard that valid users couldn't do valid work

| Case | What happened | Lesson |
|---|---|---|
| **CrowdStrike, 19 Jul 2024** — faulty update crashed ~8.5 M Windows hosts. BitLocker recovery keys were needed per machine, and "the server that hosts the recovery keys had also crashed" for some customers ([TechTarget](https://www.techtarget.com/cybersecurity/news/366596023/Defective-CrowdStrike-update-triggers-mass-IT-outage), [Wikipedia](https://en.wikipedia.org/wiki/2024_CrowdStrike-related_IT_outages)) | **Recovery secrets in the same failure domain** as what they recover |
| **Facebook/Meta, 4 Oct 2021** — a backbone command (an audit tool bug failed to stop it) disconnected all data centres. DNS loss broke internal tools, out-of-band access was down, and on-site recovery was slowed by the facilities' own physical security ([Meta engineering](https://engineering.fb.com/2021/10/05/networking-traffic/outage-details/)) | Break-glass that depends on the platform it must repair; strong physical controls slowed recovery |
| **QuadrigaCX, 2018–2020** — the founder ran everything from one encrypted laptop; after his death customers were told ~C$250 M sat in cold wallets only he could open. Later the wallets were found empty, and the Ontario Securities Commission found it "operated like a Ponzi scheme" ([Cointelegraph](https://cointelegraph.com/features/quadrigacx-users-lose-190m-as-speculations-over-cottens-death-swirl), [Wikipedia](https://en.wikipedia.org/wiki/QuadrigaCX)) | A single key holder is both a lockout risk **and** an unaccountable one |
| Microsoft Entra guidance (validation, not an incident): keep **at least two** cloud-only emergency accounts, FIDO2 keys stored in separate secure locations, alert other admins on every sign-in ([Microsoft Learn](https://learn.microsoft.com/bg-bg/azure/active-directory/roles/security-emergency-access), [CIS M365 1.1.2](https://www.tenable.com/audits/items/CIS_Microsoft_365_Foundations_v4.0.0_L1_E5.audit:a206a8c4219fe49fa2c9b10bb0672ed6)) | Redundant break-glass, independently stored, loudly monitored |

## 3. Records after the fact — evidence that helped, was missing, or became the target

| Case | Records' role | Lesson |
|---|---|---|
| **UCLA Health, 2008** — audit logs showed 165 workers improperly viewed 1,041 patients' records (Spears, Shriver, Fawcett). Break-the-glass required re-entering the password and a reason. Intrusions were known since **1995** ([FierceHealthcare](https://www.fiercehealthcare.com/healthcare/ucla-snooping-report-released-more-records-compromised-than-previously-thought), [Dark Reading](https://www.darkreading.com/risk/hospital-workers-busted-for-snooping-on-britney-spears-medical-records)) | Logs proved misuse, but **logs nobody reviews don't deter**. A reason field alone isn't a control |
| **Storm-0558 detection, 2023** — the US State Department caught it through `MailItemsAccessed` events, then a **premium-tier** audit feature. Afterwards Microsoft made expanded logging free for federal agencies and raised default retention from 90 to 180 days ([The Hacker News](https://thehackernews.com/2024/02/microsoft-expands-free-logging.html), [Nextgov](https://www.nextgov.com/cybersecurity/2023/07/chinese-cybercriminals-breach-government-email-accounts-microsoft-cloud-hack/388416/)) | Detectability decided by whether logging was enabled and kept. **Essential audit must never be optional or paid-tier** |
| **Storm-0558 root cause** — no logs proved how the key left (CSRB, above) | Missing evidence of key handling = permanent uncertainty |
| **Equifax, 2017** — an expired certificate on a traffic-inspection device left encrypted traffic uninspected for **about 10 months**; on renewal, staff "immediately began noticing suspicious activity" (GAO) ([Venafi on GAO](https://venafi.com/blog/gao-report-expired-certificate-allowed-extended-exfiltration), [Security Affairs](https://securityaffairs.com/76067/reports/equifax-hack-gao-report.html)) | **The monitor went blind silently.** Monitor the monitors (expiry, heartbeat, coverage) |
| **Okta HAR files, 2023** (above) | Support records became the attack vector | Records are targets. Minimise, seal (ADR-0010) |
| **Bangladesh Bank** (above) | Attackers rewrote the confirmations people relied on | Tamper-evident records verified elsewhere |

## 4. Patterns

1. **The approval is only as good as what the approver sees and who they are** (Bybit, Arup,
   Twitter, Uber). Cryptographic multi-party approval works when the thing signed is verified
   independently and the signer is hardware-bound.
2. **Concentration and stale grants defeat thresholds** (Ronin, LastPass, Midnight Blizzard).
3. **Static secrets inside the privileged system** (Uber's PAM password, Storm-0558's key) turn the
   safe into the single point of failure.
4. **Insiders with legitimate access can be bribed, curious, or coerced** (Coinbase, UCLA,
   Snowden, Kerviel). Scope, volume caps, deterrence and review matter as much as the gate.
5. **Over-tight controls get bypassed or cause outages** (PAL claim, CrowdStrike, Facebook,
   QuadrigaCX). Redundancy, independent failure domains and **rehearsed** recovery are part of
   security.
6. **Evidence decides outcomes**, but only if it exists, is retained, is reviewed, and the monitor
   itself is monitored (Storm-0558, Equifax, UCLA).

## 5. Quantum computing

- **Standards now:** FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA) final since 13 Aug 2024; HQC
  selected as a backup KEM on 11 Mar 2025 ([NIST](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization),
  [CyberInsider](https://cyberinsider.com/nist-selects-hqc-as-a-backup-post-quantum-encryption-algorithm/)).
  NIST IR 8547 (still an initial public draft) proposes deprecating RSA/ECC after 2030 and
  disallowing them after 2035 ([PostQuantum](https://postquantum.com/security-pqc/nist-ir-8547-ipd/)).
  NSA CNSA 2.0 wants national security systems fully quantum-resistant by 2035
  ([Entrust](https://www.entrust.com/resources/learn/what-is-cnsa-2-0)).
- **Building blocks for PPE:** IETF X-Wing (X25519 + ML-KEM-768 hybrid KEM, draft-11 Sep 2026)
  and `draft-ietf-hpke-pq` (PQ and hybrid KEMs for HPKE, -04 Mar 2026)
  ([X-Wing](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-11.html),
  [PQ HPKE](https://www.ietf.org/archive/id/draft-ietf-hpke-pq-04.html)). The TCG TPM 2.0 Library
  spec **v1.85 (Mar 2026)** adds ML-KEM and ML-DSA; wolfTPM implements it; hardware support varies
  by vendor ([TCG](https://trustedcomputinggroup.org/new-computing-specification-implements-pqc-measures-to-protect-users-from-quantum-attacks/),
  [wolfSSL](https://www.wolfssl.com/wolftpm-post-quantum-cryptography-release-ml-dsa-and-ml-kem-support-via-tcg-tpm-2-0-library-specification-v1-85/)).
- **What this means for our design:**
  - **Harvest now, decrypt later** is the threat to a sealed audit kept for months or years. The
    X25519 HPKE wraps in ADR-0010 are quantum-vulnerable; AES-256-GCM, HMAC-SHA-256 and the XOR
    2-of-2 split are not (the split is information-theoretic; Grover only halves symmetric
    strength). → **Use a hybrid KEM (X-Wing / ML-KEM-768 + X25519) for both wraps from day one**,
    with the algorithm id in the envelope (crypto agility).
  - Checkpoint and approval signatures: Ed25519 is quantum-vulnerable for *future forgery*, not
    for confidentiality. Plan **hybrid Ed25519 + ML-DSA-65** checkpoints when libraries mature, and
    re-sign (witness) old checkpoints with PQ signatures before 2030.
  - TPM: prefer v1.85-capable TPMs for the broker; until then the TPM protects the classical part
    and the ML-KEM private key is sealed by the TPM (key at rest protected; operation in software).
  - **Shorter retention is the strongest quantum mitigation**: data destroyed before a quantum
    computer exists can't be decrypted by it. Crypto-shredding (ADR-0010) matters more, not less.

## 6. Increasingly capable AI ("super intelligence" trajectory)

- **Observed already:** an AI-orchestrated espionage campaign in which the model performed 80–90 % of
  tactical work across ~30 targets, "at physically impossible request rates" (Anthropic report on
  GTG-1002, Nov 2025: [PDF](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf),
  [The Hacker News](https://thehackernews.com/2025/11/chinese-hackers-use-anthropics-ai-to.html));
  deepfake approval fraud (Arup); an AI coding agent with valid credentials that dropped a production
  database during an explicit code freeze (Replit/SaaStr, Jul 2025:
  [Fortune](https://fortune.com/2025/07/23/ai-coding-tool-replit-wiped-database-called-it-a-catastrophic-failure)).
- **Assumptions to design for:**
  1. Any request, message, voice or video can be synthesised. **Only signatures from enrolled
     hardware, over a canonical request the approver reads on that hardware's trusted display (or a
     second, independent device), count.**
  2. Attack speed exceeds human reaction. **Rate- and velocity-limit releases** (e.g. ≤ 1 active
     release per investigator, ≤ N per week, cool-down after denial), and make the system fail
     closed on anomalies without waiting for a human.
  3. AI agents are insiders with credentials. **No AI agent may hold any break-glass role**, and
     agent identities can't request releases. Agents' credentials are short-lived and scoped
     (ADR-0007's observation of agent tool use is the detection layer).
  4. Vulnerabilities will be found faster than humans patch. Keep the broker **minimal, memory-safe,
     formally specified** (policy as a small, testable state machine), and keep the hardware
     boundary (TPM/HSM) as the last line, independent of software correctness.
  5. Unknown future risks: **defence in depth + crypto agility + data minimisation + rehearsal**.
     What isn't stored can't be stolen. What's sealed under hybrid PQ wraps survives the next break.
     Rehearsal shows when the safety mechanism itself has rotted.

## 7. Changes this research recommends for ADR-0010 / ADR-0011

| # | Change | Driven by |
|---|---|---|
| H1 | **WYSIWYS approval**: the canonical request (investigator, scope, periods, duration, reason) is rendered and signed on an approver-controlled device independent of the broker and requester (hardware key with display, or a dedicated approval app on a separate managed phone/laptop). The broker's UI is never the only view | Bybit, Bangladesh |
| H2 | Approval factor = **FIDO2/PIV signature with user verification only**. No push, SMS, voice, video or chat approvals, ever | Arup, Twitter, Uber |
| H3 | **Approver independence**: the two approvers must come from different reporting lines (and ideally different sites); no person or team may control a quorum; roles and delegations expire (e.g. 90 days) unless re-confirmed by quorum | Ronin, Barings, Coinbase |
| H4 | Session credentials **bound to the investigator's hardware key** (proof-of-possession per request), never bearer tokens; diagnostics/HAR never include them | Okta HAR |
| H5 | **No static secrets** in the broker, its config or scripts. PPE's own secret detector runs on the broker's config repo in CI | Uber |
| H6 | **Velocity limits** on requests and releases; auto-deny under anomaly; **no AI agent identity** eligible for any role | GTG-1002, Replit |
| H7 | Notifications and integrity checks on an **independent channel**: approvers' devices verify checkpoints and receive open/close notices without trusting the broker host | Bangladesh, Equifax |
| H8 | **Mandatory post-session review** by both approvers within N days (the sealed access summary). Unreviewed sessions block future releases for that investigator | UCLA |
| H9 | **Failure-domain separation for recovery**: ≥ 3 approvers; broker independent of the PPE host; offline decrypter (ADR-0010) as disaster path; second escrowed token stored separately (Entra-style "two, separately stored") | CrowdStrike, Facebook, QuadrigaCX |
| H10 | **Quarterly break-glass drill** (synthetic data): request → approve → live view → close → verify; failure is a high-severity finding | Facebook, CrowdStrike, PAL claim |
| H11 | **Hybrid post-quantum wraps** (X-Wing / ML-KEM-768 + X25519) for both shares, algorithm id in the envelope; hybrid ML-DSA checkpoints planned; prefer TPM v1.85 | HNDL, NIST IR 8547, CNSA 2.0 |
| H12 | **Canary records**: synthetic, sealed records whose decoy identifiers (G1/G2 surrogates) are watched for in egress and observation. If a canary value ever appears in traffic, someone decrypted the audit outside a release | detection of offline compromise |
| H13 | Monitor the monitors: alarms on key/cert expiry, TPM health, broker heartbeat, checkpoint gaps | Equifax |
</content>
</invoke>
