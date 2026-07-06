# Section 4 — Splunk Enterprise Security (Q29–Q38)

🟣 **Level:** Advanced
🎯 **Goal:** Move beyond raw SPL into the ES-style workflow: CIM data models, correlation searches, notable events, Risk-Based Alerting (RBA), and the Asset & Identity framework.

---

## ⚠️ Prerequisites — read before starting

The default lab (`splunk/splunk:latest`) **does not ship ES**. To complete this section in full you will need one of:

| Need | Option A — Lightweight | Option B — Full ES |
|---|---|---|
| CIM data models (Q29–Q31) | Install **Splunk Common Information Model** app (free) | Comes with ES |
| Notable events / Incident Review (Q34–Q35) | Simulate `index=notable` manually with `| collect` | Real ES correlation searches |
| Risk-Based Alerting (Q36–Q37) | Simulate `index=risk` manually with `| collect` | Real risk rules + Risk Analysis dashboard |
| Asset & Identity (Q38 bonus) | Build `assets.csv` / `identities.csv` lookups by hand | Asset & Identity framework UI |

**Install ES (trial) in the lab:**
1. Download a Splunk ES trial package from [splunk.com](https://www.splunk.com/en_us/download/enterprise-security.html) (60-day trial, free account)
2. Splunk Web → **Apps → Manage Apps → Install app from file** → upload the `.tgz`
3. Restart Splunk (`docker compose restart splunk`)
4. Open **Apps → Enterprise Security** to bootstrap

**Lightweight path (no ES install):** install only the [Splunk Common Information Model](https://splunkbase.splunk.com/app/1621) app + a handful of TAs (Stream, Windows, Suricata) — that unlocks Q29–Q31 plus the simulation versions of Q34–Q37.

> Throughout this section, "ES required" tags mark exercises that need the full ES app.

---

## Subsection A — CIM Data Models (Q29–Q31)

> Why this matters: ES correlation searches almost always pivot on the normalized field names (`src`, `dest`, `user`, `action`, `signature`, …) rather than raw fields like `IpAddress` or `TargetUserName`. Get fluent here first.

### Q29 — Datamodel basics with `| from`

In the **Authentication** data model, return the 10 users with the most failed logons across the dataset. Use `| from datamodel:"Authentication"` (not `tstats`).

**Hint:**
```spl
| from datamodel:"Authentication"
| search action="failure"
| stats count by user
| sort - count | head 10
```
**Skill:** `| from datamodel:` syntax; understanding the normalized field `user` and `action`

---

### Q30 — Same answer, but fast: `tstats` + summariesonly

Recreate Q29 using `tstats` against the *accelerated* Authentication data model. Compare execution time vs Q29.

**Hint:**
```spl
| tstats summariesonly=t count
    FROM datamodel=Authentication
    WHERE Authentication.action="failure"
    BY Authentication.user
| rename Authentication.user as user
| sort - count | head 10
```
Why is `summariesonly=t` faster but riskier?
**Skill:** `tstats FROM datamodel`, accelerated DM, the `<DataModel>.<field>` naming convention

---

### Q31 — Multi-model join: "failed logon followed by success"

Find every `user` who had ≥ 5 failed logons in `Authentication` **and** then had at least one successful logon from the same `src` within 1 hour. (Classic brute-force-success pattern.)

**Hint:** This needs `tstats` twice (or once with `values(action)`), correlated by `user` and `src`. A working shape:
```spl
| tstats summariesonly=t count
    FROM datamodel=Authentication
    BY _time, Authentication.user, Authentication.src, Authentication.action
    span=1h
| rename Authentication.* as *
| eval fail = if(action="failure", count, 0),
       success = if(action="success", count, 0)
| stats sum(fail) as fails, sum(success) as successes by _time user src
| where fails >= 5 AND successes >= 1
```
**Skill:** cross-action correlation inside one DM with `tstats` + `eval`

---

## Subsection B — Correlation Search Logic (Q32–Q33)

> A "correlation search" in ES is just a saved search whose result rows become **notable events**. You can write and test the SPL today on Splunk Core — turning it into a real correlation search just means saving it with a notable adaptive response.

### Q32 — Write the SPL behind a correlation search

Author the detection SPL for: **"Excessive failed Windows logons from a single source within 5 minutes (≥10 fails to ≥3 distinct accounts)."** The output row must include the fields ES expects in a notable: `src`, `user`, `dest`, `signature`, `severity`.

**Hint:**
```spl
source=XmlWinEventLog EventCode=4625
| bin span=5m _time
| stats count as fails, dc(TargetUserName) as targets,
        values(TargetUserName) as user, values(Computer) as dest
        by _time IpAddress
| rename IpAddress as src
| where fails >= 10 AND targets >= 3
| eval signature = "Excessive Failed Logons - Multiple Accounts",
       severity  = "high"
| table _time src dest user fails targets signature severity
```
**Skill:** shaping output for the Notable Event Framework (right field names, one row per incident)

---

### Q33 — Simulate writing to the notable index (no ES required)

Take the result of Q32 and write the matching rows into a simulated notable index using `| collect index=notable`. Then query that index back to "review" the notable.

**Hint:**
```spl
<SPL from Q32>
| eval rule_name = signature, rule_id = "TA-WIN-BRUTE-001"
| collect index=notable
```
Verify with:
```spl
index=notable rule_id="TA-WIN-BRUTE-001"
| table _time src dest user fails rule_name
```
> 🛈 First-time `| collect` users: the target index must exist. Create it via *Settings → Indexes → New Index* (name: `notable`).
**Skill:** `| collect` to persist a detection result; designing rule metadata

---

## Subsection C — Notable Event Triage (Q34–Q35)

### Q34 — Triage view from `index=notable` *(ES-required or use Q33 simulation)*

Build the **analyst triage table** for `index=notable`: one row per *unique* `(src, signature)` pair, showing earliest seen, latest seen, count, and the latest `severity`. Sort by count descending.

**Hint:**
```spl
index=notable
| stats earliest(_time) as first_seen,
        latest(_time)   as last_seen,
        count,
        latest(severity) as severity
    by src signature
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```
**Skill:** `stats earliest()`/`latest()` + `convert ctime()` to produce a human-readable triage list

---

### Q35 — Suppress noisy notables for 1 hour

Add a *suppression window*: for every `(src, signature)` pair, only the **first** notable in any 1-hour window should be displayed (others are duplicates from the same campaign). Re-run Q34 with that filter.

**Hint:**
```spl
index=notable
| bin span=1h _time as window
| stats min(_time) as first_event, count by window src signature severity
| where count >= 1
| stats earliest(first_event) as first_seen,
        latest(first_event)   as last_seen,
        sum(count) as total_events
    by src signature severity
| convert ctime(first_seen) ctime(last_seen)
| sort - total_events
```
Real ES handles this with the `dispatch.earliest_time` + throttle window on the saved search — but the logic is identical.
**Skill:** throttling / dedup-by-window pattern

---

## Subsection D — Risk-Based Alerting (Q36–Q37)

> RBA flips the model: instead of one notable per detection, every detection contributes a **risk score** to a `risk_object` (host or user). When the cumulative score over a window crosses a threshold, *that* fires the notable.

### Q36 — Emit a risk event from a detection

Modify the Q22 (long-PowerShell) detection from Section 3 to write a risk event per match: `risk_object=Computer`, `risk_object_type="system"`, `risk_score=40`, `risk_message` = brief description.

**Hint:**
```spl
source=XmlWinEventLog EventCode=4688 NewProcessName="*powershell.exe"
| eval cmd_length = len(CommandLine)
| where cmd_length > 150
| eval risk_object       = Computer,
       risk_object_type  = "system",
       risk_score        = 40,
       risk_message      = "Suspicious long PowerShell command line ("+tostring(cmd_length)+" chars)",
       source_rule       = "Suspicious PowerShell - Long CmdLine"
| table _time risk_object risk_object_type risk_score risk_message source_rule
| collect index=risk
```
> Create `index=risk` the same way as `notable` in Q33.
**Skill:** writing risk events; the `risk_object` / `risk_score` schema ES expects

---

### Q37 — Aggregate risk → fire a "risk incident" when total ≥ 100

Query `index=risk` and find any `risk_object` whose **cumulative** `risk_score` in the last 24 hours is ≥ 100. Include how many distinct `source_rule` values contributed (more rules = stronger signal than one rule firing repeatedly).

**Hint:**
```spl
index=risk earliest=-24h
| stats sum(risk_score) as total_risk,
        dc(source_rule) as distinct_rules,
        values(source_rule) as rules,
        latest(_time) as last_seen
    by risk_object risk_object_type
| where total_risk >= 100
| sort - total_risk
| convert ctime(last_seen)
```
Tune the threshold — in real ES this query *itself* becomes a correlation search.
**Skill:** the core RBA "risk notable" pattern

---

## Subsection E — Asset & Identity Enrichment (Q38)

### Q38 — Enrich an event with a CSV lookup *(bonus)*

Create a quick `assets.csv` lookup that maps hostname → criticality + business unit, then enrich the Q22 result with those columns. (This mirrors what ES's *Asset & Identity Framework* does automatically.)

**Hint:**
1. Build a CSV with header `host,criticality,business_unit` and rows like `WEBSERVER-01,high,ecommerce`
2. Splunk Web → *Settings → Lookups → Lookup table files* → upload the CSV
3. Define a *Lookup definition* named `assets_lookup` over the file
4. Use it:
```spl
source=XmlWinEventLog EventCode=4688 NewProcessName="*powershell.exe"
| eval cmd_length = len(CommandLine) | where cmd_length > 150
| lookup assets_lookup host AS Computer OUTPUT criticality business_unit
| table _time Computer criticality business_unit cmd_length CommandLine
```
**Skill:** CSV lookups → asset context (exactly how the ES Asset & Identity framework joins under the hood)

---

🎓 **End of ES section.**
If you finished Q29–Q38 you have hands-on intuition for: CIM, correlation searches, notable events, RBA, and asset enrichment — the core daily workflow of a SOC analyst on ES.

**Next steps:**
- Read the [ES Use Case Library](https://docs.splunk.com/Documentation/ES/latest/UseCases/Overview) and adapt three to BOTS data
- Tag detections with MITRE ATT&CK technique IDs in `annotations.mitre_attack` and pivot by technique
- Try the [splunk-bots/](../../splunk-bots/) BOTS walkthroughs through an ES-style lens (everything becomes a correlation search candidate)
