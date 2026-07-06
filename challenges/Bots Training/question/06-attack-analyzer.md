# Section 6 — Splunk Attack Analyzer (SAA) (Q51–Q60)

🟣 **Level:** Advanced
🎯 **Goal:** Use Splunk Attack Analyzer — automated phishing/malware analysis — as the enrichment engine that feeds verdicts into ES Findings and drives SOAR playbooks. Most exercises are *design* deliverables since SAA is a cloud product; a few have SPL that runs on your local lab using simulated SAA output.

> SAA appears on the ES 8.3 workshop deck (slide *"Actionize your data by integrating SOAR with Splunk ES and Splunk Attack Analyzer"*) but the deck itself does not deep-dive — this section fills that gap.

---

## What is Splunk Attack Analyzer?

A cloud-hosted automated threat-analysis service (originally TwinWave, acquired 2022). You submit a suspicious artifact and SAA runs a chain of engines and returns a verdict:

| Artifact type | What SAA does |
|---|---|
| URL | Visits in instrumented browser, follows redirects, screenshots landing page, flags credential phishing kits |
| File | Static analysis + dynamic detonation in a sandbox, extracts behavior, IOCs, network connections |
| Email (.eml) | Extracts attachments and URLs, recursively analyzes each |
| Hash | Reputation lookup across vendor feeds + prior SAA results |

**Output shape (simplified JSON):**
```json
{
  "job_id": "abc-123",
  "submission": { "type": "url", "value": "https://login-microsoft365.tk/o365" },
  "verdict": "malicious",
  "score": 95,
  "verdict_reasons": ["credential_phishing", "brand_impersonation:microsoft"],
  "iocs": {
    "urls":     ["https://login-microsoft365.tk/o365/post.php"],
    "domains":  ["login-microsoft365.tk"],
    "ips":      ["185.220.101.4"],
    "hashes":   ["sha256:..."]
  },
  "engines": [
    { "name": "url_browser",     "result": "credential_phishing_kit_detected" },
    { "name": "static_analyzer", "result": "obfuscated_javascript" },
    { "name": "threat_intel",    "result": "domain_age_under_7_days" }
  ],
  "screenshots": ["https://.../shot1.png"],
  "submitted_at": "2026-05-22T10:13:00Z",
  "completed_at": "2026-05-22T10:14:42Z"
}
```

Keep this shape in mind — most exercises use it.

---

## ⚠️ Setup paths

| Path | What you can do |
|---|---|
| **A. Lab-only (default)** | All design-style exercises (Q51, Q52, Q56, Q58, Q60) + Q53/Q54/Q55 using simulated SAA JSON you build yourself |
| **B. SAA trial** ([splunk.com/en_us/products/splunk-attack-analyzer.html](https://www.splunk.com/en_us/products/splunk-attack-analyzer.html)) | Submit real URLs/files and verify your designs end-to-end |
| **C. BOSS Platform** ([bots.splunk.com](https://bots.splunk.com)) | Some BOTS competitions include SAA tracks with hosted access |

> 💡 To build simulated data for Path A, save 5–10 SAA JSON blobs (varying verdicts) into a local file `saa_samples.json`, upload via *Settings → Add Data → Files & directories → Index it now*, choose sourcetype `_json` and index `main`. You'll then have `index=main sourcetype=_json source=saa_samples.json` to query.

---

## Subsection A — SAA Fundamentals (Q51–Q52)

### Q51 — When should you submit an artifact to SAA?

For each SOC artifact below, decide: **submit to SAA**, **don't submit**, or **submit only if conditions met**. Justify in one line. Think about: cost (cloud submission is metered), data sensitivity, and whether SAA can add information beyond what you already have.

| # | Artifact | Submit? | Justification |
|---|---|---|---|
| 1 | URL from a user-reported phishing email | ? | ? |
| 2 | A known-good corporate URL clicked 10k times today | ? | ? |
| 3 | `.docm` attachment from external sender, never seen before | ? | ? |
| 4 | A SHA-256 hash that already has a VirusTotal verdict of "malicious" with 50/70 vendors | ? | ? |
| 5 | URL containing an internal customer ID in the path | ? | ? |
| 6 | `cscript.exe` parent + `.tmp` child process from BOTS v1 — should you submit the `.tmp` file? | ? | ? |

**Skill:** cost/benefit framing for cloud analysis — *not everything goes to SAA*.

---

### Q52 — Map SAA into your IR flow

Place SAA correctly in this generic phishing IR sequence by inserting it (you may insert it in multiple places):

```
1. User reports phishing email via the Report button
2. Email lands in the SOC mailbox
3. Tier 1 analyst opens it
4. ???
5. Verdict known
6. Tier 1 decides: false positive vs escalate
7. If escalate: block sender, sinkhole URL, search environment for other recipients
8. Notify affected users, close ticket
```

**Deliverable:** redraw the sequence inserting SAA step(s). For each insertion, write 1 sentence explaining *why SAA, not the analyst, does this step* (e.g. "consistency", "10x faster", "safe detonation environment").
**Skill:** workflow design — SAA replaces parts of the manual triage, not the whole loop

---

## Subsection B — Reading SAA Results (Q53–Q54)

### Q53 — Parse a SAA verdict in SPL

Given the sample JSON at the top of this file is indexed as `index=main sourcetype=_json source=saa_samples.json`, write SPL that returns one row per submission with these columns: `submitted_at`, `submission_type`, `submission_value`, `verdict`, `score`, `top_reason`, `analysis_duration_sec`.

**Hint:**
```spl
index=main sourcetype=_json source=saa_samples.json
| eval submitted_epoch = strptime(submitted_at, "%Y-%m-%dT%H:%M:%SZ"),
       completed_epoch = strptime(completed_at, "%Y-%m-%dT%H:%M:%SZ"),
       analysis_duration_sec = completed_epoch - submitted_epoch,
       top_reason = mvindex(verdict_reasons, 0)
| rename submission.type AS submission_type,
         submission.value AS submission_value
| table submitted_at submission_type submission_value verdict score top_reason analysis_duration_sec
```
**Skill:** parsing nested JSON; `mvindex`; `strptime` to compute analysis latency

---

### Q54 — IOC extraction & dedup

From all SAA submissions with `verdict="malicious"`, build a clean IOC table: one row per unique IOC value, with columns `ioc_type` (`url` / `domain` / `ip` / `hash`), `ioc_value`, `first_seen`, `last_seen`, `submission_count`, `sample_score`.

**Hint:** `mvexpand` each IOC array, then aggregate.
```spl
index=main sourcetype=_json source=saa_samples.json verdict="malicious"
| eval url_iocs    = iocs.urls,
       domain_iocs = iocs.domains,
       ip_iocs     = iocs.ips,
       hash_iocs   = iocs.hashes
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
This IOC table is exactly what you would feed into a threat-intel KV store / lookup to enrich future detections.
**Skill:** flattening structured JSON IOCs into a queryable, dedup'd form

---

## Subsection C — Splunk Ingestion (Q55)

### Q55 — Design the SAA → Splunk ingestion path

Sketch the ingestion architecture in 1 paragraph + a diagram (ASCII is fine). Constraints:
- SAA results are produced asynchronously (jobs take 30s–5min)
- ~500 submissions/day → ~3500 events/week (low volume)
- You need to query SAA results within 5 minutes of completion
- You also want to *trigger* re-detections in ES when a new verdict arrives

**Pick one of three patterns** and defend the choice:
1. **Polling**: scheduled Splunk REST call to SAA's `/jobs?status=completed` every minute
2. **Webhook → HEC**: SAA pushes to your HEC (`http://localhost:8088`) on completion
3. **Modular input**: a Splunk app that subscribes to SAA's job-completed stream

**Deliverable:** ~5 lines + a diagram. Choose the pattern, list its 2 biggest risks.
**Skill:** ingestion architecture trade-offs — *don't poll if you can webhook*

---

## Subsection D — ES Integration (Q56–Q57)

### Q56 — Enrich an ES Finding with SAA verdict

For the Section 3 Scenario B Cerber detection, design how SAA enrichment changes the Finding card the analyst sees. Specifically — for the drive-by-domain detection that already fires on `solidaritedeproximite.org`:

1. Which artifact would you auto-submit to SAA? (URL? file hash? both?)
2. Once SAA returns, which of its fields land on the ES Finding? Pick the 3–5 most useful and explain why.
3. What's the **decision rule** that takes SAA's `verdict` and adjusts the Finding's severity?

**Suggested decision rule template:**
```
IF saa_verdict = "malicious"  AND saa_score >= 90  THEN bump severity to CRITICAL
IF saa_verdict = "malicious"  AND saa_score >= 70  THEN keep severity HIGH, attach IOCs to Finding
IF saa_verdict = "suspicious"                      THEN keep severity MEDIUM, attach IOCs, request analyst review
IF saa_verdict = "benign"                          THEN downgrade to LOW or auto-close
```
**Skill:** designing enrichment that *changes analyst behavior* (not just decoration)

---

### Q57 — Finding-Based Detection: "SAA confirmed malicious + executed on endpoint"

Configure a Finding-Based Detection (ES 8 style, see [Section 5 Q46](05-es8-workshop.md)) that fires only when both conditions are true on the **same entity** within **2 hours**:

- ≥ 1 SAA result with `verdict="malicious"` and `score≥80` against an IOC
- ≥ 1 endpoint Finding referencing that same IOC (e.g. a process executing a file with the matching hash, or a connection to the matching domain)

Fill in the artifact:

| Field | Value |
|---|---|
| **Name** | ? |
| **Description** | ? |
| **Grouping mechanism** | Custom (cross-source correlation) |
| **Time range** | 2h |
| **Entity field** | `dest` or `src` (your choice — justify) |
| **Preview SPL** | ? — must join SAA results with endpoint findings on the IOC |

**Preview SPL hint:**
```spl
| union
    [search index=main sourcetype=_json source=saa_samples.json
        verdict="malicious" score>=80
        | mvexpand iocs.domains
        | eval ioc = 'iocs.domains', source_type = "saa"
        | table _time ioc source_type score]
    [search index=notable signature="*"
        | rex field=description "(?<ioc>[a-z0-9.-]+\.(com|net|org|tk|ru|info|biz))"
        | eval source_type = "endpoint", score = 0
        | table _time ioc source_type]
| stats values(source_type) as types,
        values(score)       as saa_score,
        count
    by ioc
| where mvcount(types) >= 2 AND mvfind(types, "saa") >= 0 AND mvfind(types, "endpoint") >= 0
```
This is a multi-source correlation that's slow and brittle in plain SPL — it's exactly the use case ES 8's Finding-Based Detections were built for. (The custom-search type in ES 8 wraps queries like this.)
**Skill:** designing high-signal cross-source detections; understanding why ES 8 abstracts this pattern

---

## Subsection E — SOAR Integration (Q58–Q59)

### Q58 — Playbook: "Phishing URL Triage with SAA"

Design a SOAR playbook end-to-end. Input: a `phishing_report` Finding with a URL. Output: a verdict-driven response. List **at least 6 nodes** with branching:

| Step | Node | Type | Notes |
|---|---|---|---|
| 1 | ? | input | The URL is extracted from the Finding's `url` field |
| 2 | ? | action — saa_submit_url | block until job done, with 5-min timeout |
| 3 | ? | decision | branch on `verdict` |
| 4a | ? | action (malicious branch) | … |
| 4b | ? | action (suspicious branch) | … |
| 4c | ? | action (benign branch) | … |
| 5 | ? | action | post summary back to the Finding's comments |
| 6 | ? | action | close Finding if benign; escalate to Tier 2 otherwise |

**Deliverable:** complete the table. For each action, name the SOAR app/connector that performs it.
**Skill:** decomposing IR response → automatable atomic actions; branching on verdicts

---

### Q59 — Limits & failure modes of automation

SAA has rate limits and can return verdicts of `error` or `timeout`. Write the design rules for your playbook's **failure handling**:

1. What happens if SAA `verdict="error"` after retry?
2. What happens if SAA returns no verdict within 5 minutes?
3. How do you prevent the playbook from re-submitting the same URL 100 times (e.g. a campaign with the same phishing link in 100 different emails)?
4. What's the cost/safety trade-off if you set the playbook to *auto-block* malicious URLs at the perimeter vs *recommend block* and require analyst approval?

**Skill:** automation discipline — the most dangerous playbooks are the ones with no failure paths

---

## Capstone

### Q60 — End-to-end SAA-driven incident response

Take a real phishing scenario: a user reports an email; it contains a `.docm` attachment and a URL pointing to a credential-harvester. Produce the complete artifact set:

1. **SOAR playbook** (Q58-style) — full table, with both URL submission and file submission to SAA
2. **ES Event-Based Detection** that catches *future* emails sharing the same SAA-IOCs (any of the URLs/domains/hashes from this case)
3. **ES Finding-Based Detection** (Q57-style) that escalates to CRITICAL if the same user *also* shows endpoint activity matching SAA IOCs
4. **Lookup table schema** (CSV header) for the IOC store that gets populated from every SAA verdict — design the columns
5. **One sentence: how do you measure that adding SAA to the loop reduced phishing dwell time?**

**Deliverable:** ~1.5 pages of structured Markdown — the artifact you'd hand a Detection Engineering lead to ship SAA into production.
**Skill:** end-to-end design — SAA is *not* a feature, it's an integration point; the value is in the loop, not the tool

---

🎓 **End of SAA section.**

If you completed Q51–Q60, you've designed the full integration surface of SAA with ES and SOAR — submission, verdict parsing, finding enrichment, finding-based correlation, automated response, and ingestion architecture.

**Next:**
- Sign up for the SAA trial and submit a few of your favorite phishing URLs from threat-intel feeds — compare its verdict to your own analysis
- Read the [SAA REST API docs](https://docs.splunk.com/Documentation/SAA) and convert Q55's pattern choice into actual config (HEC endpoint URL + token, or modular input app skeleton)
- Pair this section with [Section 5](05-es8-workshop.md) — SAA is one of the most common things you'd see invoked from an ES 8 Response Plan
