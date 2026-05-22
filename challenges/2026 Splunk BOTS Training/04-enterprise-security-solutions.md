# Solutions — Section 4 (Q29–Q38)

⚠️ **Last resort.** Try every problem honestly first.

> **Prerequisite:** install the **Splunk Common Information Model** app (lightweight path) or **Splunk ES trial** (full path), and create indexes `notable` and `risk` via *Settings → Indexes*. See [04-enterprise-security.md](04-enterprise-security.md) for setup.

---

## Subsection A — CIM Data Models

### Q29 — Datamodel basics with `| from`
```spl
| from datamodel:"Authentication"
| search action="failure"
| stats count by user
| sort - count | head 10
```
If you get zero rows, the workshop sourcetypes aren't tagged into CIM. Fallback:
```spl
source=XmlWinEventLog EventCode=4625
| stats count by TargetUserName
| sort - count | head 10
```
The lesson: CIM trades a one-time investment in TA mapping for **portable** SPL that works across any environment.

---

### Q30 — tstats + summariesonly
```spl
| tstats summariesonly=t count
    FROM datamodel=Authentication
    WHERE Authentication.action="failure"
    BY Authentication.user
| rename Authentication.user as user
| sort - count | head 10
```
Same answer as Q29 but ~10–1000× faster. Risk of `summariesonly=t`: if acceleration is paused or behind schedule, you silently get *incomplete* results with no warning. Set `summariesonly=f` (the slower but accurate mode) when correctness matters more than speed.

---

### Q31 — Brute-force-then-success pattern
```spl
| tstats summariesonly=t count
    FROM datamodel=Authentication
    BY _time, Authentication.user, Authentication.src, Authentication.action
    span=1h
| rename Authentication.* as *
| eval fail    = if(action="failure", count, 0),
       success = if(action="success", count, 0)
| stats sum(fail) as fails, sum(success) as successes
    by _time user src
| where fails >= 5 AND successes >= 1
| sort - fails
```
The `span=1h` correlates fail+success that happen **in the same 1-hour bucket** on the same `(user, src)` pair. Drop the span to widen the correlation window.

---

## Subsection B — Correlation Search Logic

### Q32 — Correlation search SPL
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
Output **shape** matters: ES expects fields named `src`, `dest`, `user`, `signature`, `severity`. Calling them `IpAddress`, `Computer`, `TargetUserName` works in your search but breaks ES's Notable framework.

---

### Q33 — Persist to simulated `index=notable`
```spl
<Q32 search>
| eval rule_name = signature,
       rule_id = "TA-WIN-BRUTE-001"
| collect index=notable
```
Verify:
```spl
index=notable rule_id="TA-WIN-BRUTE-001"
| table _time src dest user fails rule_name
```
`| collect` writes the result rows into the named index. Re-running appends — production scheduling uses cron + throttle so the same notable isn't re-emitted.

---

## Subsection C — Notable Triage

### Q34 — Triage table
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
`convert ctime()` converts an epoch-time field into a human-readable string in-place. Without it, `first_seen` shows as `1471824000` instead of `2016-08-22 00:00:00`.

---

### Q35 — Throttle by 1-hour window
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
Real ES achieves this via `throttle window=1h key=src,signature` on the saved-search config. Logic is identical; ES just gives you the dial in the UI.

---

## Subsection D — Risk-Based Alerting

### Q36 — Emit risk event
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
ES's risk schema (the fields you must populate):
- `risk_object` — the entity at risk (user, host, IP, …)
- `risk_object_type` — `system` / `user` / `other`
- `risk_score` — your contribution (0–100 typical)
- `risk_message` — short human-readable description
- `source_rule` — which detection rule contributed

---

### Q37 — Aggregate risk → fire incident
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
**Threshold = 100** is just a convention — pick based on your max single-rule score. Rule of thumb: threshold should require at least 2–3 distinct rules to fire (high signal). If 100 is reachable by one noisy rule, lower that rule's score or raise the threshold.

---

## Subsection E — Asset & Identity

### Q38 — CSV lookup enrichment
**assets.csv:**
```csv
host,criticality,business_unit
WEBSERVER-01,high,ecommerce
DBSERVER-01,critical,finance
WORKSTATION-01,low,general
```

**Query after lookup is defined:**
```spl
source=XmlWinEventLog EventCode=4688 NewProcessName="*powershell.exe"
| eval cmd_length = len(CommandLine) | where cmd_length > 150
| lookup assets_lookup host AS Computer OUTPUT criticality business_unit
| table _time Computer criticality business_unit cmd_length CommandLine
```
ES's *Asset & Identity Framework* ships two pre-defined lookups: `asset_lookup_by_str` and `identity_lookup_expanded`. They auto-join on `src` / `dest` / `user` whenever you display notable events — same idea, productized.

---

✅ End Section 4 solutions
