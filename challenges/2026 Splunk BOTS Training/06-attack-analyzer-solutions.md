# Solutions — Section 6 (Q51–Q60) — Splunk Attack Analyzer

⚠️ **Last resort — try every problem honestly first.**

> Section 6 is mostly **design-style** since SAA is a cloud service the lab can't host. SPL solutions assume you've indexed simulated SAA JSON output per the setup notes in [06-attack-analyzer.md](06-attack-analyzer.md).

---

## Q51 — When to submit

| # | Artifact | Submit? | Justification |
|---|---|---|---|
| 1 | URL from user-reported phishing | **Yes** | Highest-yield SAA use case — credential phishing detection |
| 2 | Known-good corporate URL clicked 10k times | **No** | Already known, wastes budget; whitelist instead |
| 3 | Unknown `.docm` from external sender | **Yes** | Macros are high-risk; SAA's sandbox detonates them safely |
| 4 | SHA-256 with 50/70 VT detections | **No (or only for forensic detail)** | VT verdict already conclusive — submit only if you need behavioral IOCs for hunting |
| 5 | URL containing internal customer ID | **No, conditionally** | Data-sensitivity — internal IDs may leak via SAA logs. Sanitize the URL or use on-prem analysis instead |
| 6 | BOTS v1 `.tmp` from `cscript.exe` parent | **Yes** | Even though it's a known scenario, real production would submit to get the IOC chain for hunting elsewhere |

**Pattern:** submit when SAA adds information *you don't already have*. Don't submit just because you *can*.

---

## Q52 — SAA in IR flow

```
1. User reports phishing email via Report button
2. Email lands in SOC mailbox
3. Tier 1 analyst opens it
4. >>> SAA auto-submit (URLs + attachments) <<<     (consistency: same engines every time)
5. Verdict known
6. Tier 1 decides: false positive vs escalate       (now armed with SAA verdict + IOCs + screenshots)
7. If escalate:
   - >>> SAA-extracted IOCs feed search <<<         (find other recipients, lateral exposure)
   - block sender, sinkhole URL
8. Notify affected users, close ticket
```

**Why SAA at step 4, not the analyst:** SAA detonates URLs in an instrumented browser — *no human should be clicking suspect links from their workstation*. The screenshot + credential-phishing-kit detection is consistent and reproducible; analyst judgment varies.

---

## Q53 — Parse SAA verdict

```spl
index=main sourcetype=_json source=saa_samples.json
| eval submitted_epoch = strptime(submitted_at, "%Y-%m-%dT%H:%M:%SZ"),
       completed_epoch = strptime(completed_at, "%Y-%m-%dT%H:%M:%SZ"),
       analysis_duration_sec = completed_epoch - submitted_epoch,
       top_reason = mvindex(verdict_reasons, 0)
| rename submission.type AS submission_type,
         submission.value AS submission_value
| table submitted_at submission_type submission_value verdict score top_reason analysis_duration_sec
| sort - score
```
`mvindex(field, 0)` returns the first element of a multivalue field. For nested JSON like `submission.type`, Splunk's auto-extracted field name preserves the dot — you reference it as `'submission.type'` in `eval` (single quotes for fields with special chars).

---

## Q54 — IOC extraction & dedup

```spl
index=main sourcetype=_json source=saa_samples.json verdict="malicious"
| eval url_iocs    = 'iocs.urls',
       domain_iocs = 'iocs.domains',
       ip_iocs     = 'iocs.ips',
       hash_iocs   = 'iocs.hashes'
| eval iocs_combined = mvappend(
        mvmap(url_iocs,    "url|" .    url_iocs),
        mvmap(domain_iocs, "domain|" . domain_iocs),
        mvmap(ip_iocs,     "ip|" .     ip_iocs),
        mvmap(hash_iocs,   "hash|" .   hash_iocs))
| mvexpand iocs_combined
| eval ioc_type  = mvindex(split(iocs_combined, "|"), 0),
       ioc_value = mvindex(split(iocs_combined, "|"), 1)
| stats earliest(_time) as first_seen,
        latest(_time)   as last_seen,
        count           as submission_count,
        max(score)      as sample_score
    by ioc_type ioc_value
| convert ctime(first_seen) ctime(last_seen)
| sort - sample_score
```
**Why this works:** `mvappend` concatenates multivalue fields; `mvmap` runs a transform per element (prepending the type label so we can split it back out); `mvexpand` turns each multivalue value into its own event row; the final `stats` aggregates per unique `(ioc_type, ioc_value)` pair.

The output IOC table is exactly what feeds a KV-store / lookup that other detections will reference.

---

## Q55 — Ingestion architecture

**Recommended pattern: Webhook → HEC**

```
┌─────┐    POST /services/collector/event  ┌─────────────────┐
│ SAA │ ──────────────────────────────────▶│ Splunk HEC :8088│
└─────┘   (Authorization: Splunk <token>)  └────────┬────────┘
   ▲                                                │
   │                                                ▼
   │                                       ┌────────────────┐
   │                                       │ index=saa      │
   │                                       │ sourcetype=    │
   │                                       │   _json:saa    │
   │                                       └────────────────┘
   │
   │ (job submitted)
   │
   ▼ (SOAR / playbook submits artifact)
```

**Why webhook over polling:**
- **No latency floor** — verdicts arrive within seconds of completion, not minutes
- **No wasted API calls** — polling burns SAA quota even when nothing changed
- **Self-throttling** — SAA only emits when there's something to emit

**Two biggest risks:**
1. **Webhook delivery failures are invisible** — if HEC is down for 10 minutes, those verdicts are *lost*. Mitigation: SAA queue + retry on the SAA side; or a periodic reconciliation poll as a backstop.
2. **HEC token leakage** — the SAA → HEC call must use HTTPS + a token-rotated secret. If the token leaks, anyone can inject fake SAA verdicts into your index, poisoning downstream detections.

---

## Q56 — Enrich Cerber Finding with SAA

1. **Auto-submit:** both the **URL** (`solidaritedeproximite.org` HTTP traffic) and the dropped **file hash** (the `121214.tmp` payload, if you have it from EDR / Sysmon FileCreate).

2. **5 most useful SAA fields on the Finding card:**
   - `verdict` — malicious / suspicious / benign (single-glance triage)
   - `score` — drives severity bumps (see decision rule below)
   - `verdict_reasons` — explains *why* SAA flagged it (e.g. `credential_phishing`, `cobalt_strike_beacon_traffic`)
   - `iocs` — extracted indicators (URLs, domains, hashes, IPs) — feed into hunt queries
   - `screenshots` (URLs only) — visual proof for the analyst

3. **Decision rule** (from question template — calibrated):
```
IF saa_verdict = "malicious"  AND saa_score >= 90  THEN bump severity to CRITICAL,
                                                       auto-trigger SOAR isolate playbook
IF saa_verdict = "malicious"  AND saa_score >= 70  THEN keep severity HIGH,
                                                       attach IOCs to Finding, page Tier 2
IF saa_verdict = "suspicious"                      THEN keep severity MEDIUM,
                                                       attach IOCs, queue for analyst review
IF saa_verdict = "benign"                          THEN downgrade to LOW,
                                                       auto-close after 24h if no other signals
IF saa_verdict = "error" OR "timeout"              THEN keep original severity,
                                                       tag Finding "saa_unavailable" for retry
```

---

## Q57 — SAA + endpoint correlation Finding-Based Detection

| Field | Value |
|---|---|
| **Name** | High-confidence: SAA malicious IOC + endpoint hit |
| **Description** | Generates a Finding Group when SAA returns a malicious verdict (score ≥ 80) on an IOC that *also* appears in any endpoint Finding on the same entity within 2 hours. Eliminates the noise of "saw it in mail" vs "it actually ran". |
| **Grouping mechanism** | Custom (cross-source correlation) |
| **Time range** | 2h |
| **Entity field** | `dest` — the entity at risk is the endpoint that *executed* the IOC. (Choose `src` if you care more about the attacker than the victim.) |
| **Preview SPL** | *(see question template — the `union` query)* |

The reason ES 8 abstracts this pattern into Finding-Based Detections: in plain SPL the `union` + multi-source correlation runs every search cycle and is slow + brittle. ES caches finding state and runs the correlation incrementally — much cheaper.

---

## Q58 — Phishing URL playbook

| Step | Node | Type | Notes |
|---|---|---|---|
| 1 | `extract_url` | input | The URL is extracted from the Finding's `url` field via Splunk macro |
| 2 | `saa_submit_url` | action — `splunk_attack_analyzer.submit_url` | Block until done, 5-min timeout, retry once on `error` |
| 3 | `branch_verdict` | decision | Switch on `verdict` field of SAA response |
| 4a | `block_perimeter` | action (malicious) | `palo_alto.block_url` + `proxy.add_to_blocklist` |
| 4b | `quarantine_review` | action (suspicious) | `email_quarantine.move_to_review` — let Tier 2 inspect |
| 4c | `release_mail` | action (benign) | `email_quarantine.release_to_inbox` |
| 5 | `comment_finding` | action | `splunk_es.add_comment` — write SAA verdict + score + IOCs to the Finding |
| 6 | `close_or_escalate` | action | `splunk_es.close_finding` if benign; `splunk_es.escalate_to_tier2` otherwise |

---

## Q59 — Failure-mode design

1. **`verdict="error"` after retry:** keep Finding open, tag `saa_unavailable`, route to a Tier 2 manual queue. Never auto-close on error — that's how analysts miss real incidents during cloud outages.

2. **No verdict within 5 min:** treat as `timeout`. Same as error path. Optionally enqueue for re-submission in 1 hour with a longer SAA timeout window — some real malware is slow to detonate.

3. **Dedup:** maintain a KV-store keyed on `sha256(url)` or `sha256(file_hash)` with a 24h TTL. Before submitting, check the cache. If hit → reuse the prior verdict; if miss → submit and write the verdict back. This single mechanism kills "campaign with 100 identical URLs" submission storms.

4. **Auto-block vs recommend-block trade-off:**
   - **Auto-block** → faster MTTR (seconds), but a false positive blocks legitimate traffic (e.g. SAA flagging Microsoft login because of unusual TLS fingerprint = users locked out of email).
   - **Recommend-block** → safer, but MTTR includes analyst response time (minutes to hours).
   - **Pragmatic policy:** auto-block IOCs that score ≥ 90 **and** have ≥ 2 verdict_reasons (multiple engines confirmed). Recommend-block for everything else. Roll forward gradually as confidence builds.

---

## Q60 — Capstone (sample)

### 1. SOAR Playbook — Q58 expanded for both URL + file

| Step | Node | Type | Notes |
|---|---|---|---|
| 1 | `extract_artifacts` | input | URL from email body, attachment hash from EDR |
| 2a | `saa_submit_url` | action | Parallel branch |
| 2b | `saa_submit_file` | action | Parallel branch |
| 3 | `join` | wait | Block on both 2a + 2b completing |
| 4 | `branch_verdict` | decision | If *any* artifact returns malicious → malicious branch |
| 5a | `block_perimeter` + `block_attachment_hash_in_email_gateway` | action | malicious path |
| 5b | `quarantine_review` | action | suspicious path |
| 5c | `release` | action | benign path |
| 6 | `comment_finding` + `write_iocs_to_lookup` | action | always — even benign verdicts add to knowledge |
| 7 | `close_or_escalate` | action | based on combined verdict |

### 2. Event-Based Detection — match future SAA-IOCs in env
```spl
index=botsv1
[ search index=saa sourcetype=_json:saa verdict="malicious"
  | mvexpand iocs.domains
  | rename "iocs.domains" as query
  | table query ]
| stats count by host sourcetype query
```
Returns any event in the env mentioning any malicious-verdict domain from SAA. (Use `iocs.urls` / `iocs.hashes` for other artifact types.)

### 3. Finding-Based Detection — escalate when user also has endpoint match
*(see Q57 above — same shape, scoped to phishing victim user)*

### 4. IOC lookup table schema (CSV header)
```csv
ioc_value,ioc_type,first_seen,last_seen,sources_count,max_score,verdict_reasons,case_ids
```
- `ioc_value` (PK), `ioc_type` (url/domain/ip/hash) — basic identity
- `first_seen` / `last_seen` — drives retention + ageing
- `sources_count` — how many SAA submissions surfaced this IOC (higher = more reliable)
- `max_score` — keep the worst-case score across submissions
- `verdict_reasons` — multivalue, accumulated from all submissions
- `case_ids` — ES Finding Group IDs this IOC participated in (forensic backlink)

### 5. MTTR measurement
> "Define MTTR for phishing as: time from email-arrives → email-quarantined (or marked safe). Track median + p95 weekly. Compare 4 weeks pre-SAA vs 4 weeks post-SAA. Target: ≥ 60% MTTR reduction on auto-block path within 90 days. Reported via the Detection Analytics dashboard's `mean_response_time` panel filtered by `source_rule = 'phishing_url_playbook'`."

---

✅ End Section 6 solutions
