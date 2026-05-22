# Section 4 — Enterprise Security Workflow (Q51–Q60)

🟣 **Level:** Advanced
🎯 **Goal:** Re-do the attack stories from Sections 1–3 through the lens of Splunk Enterprise Security — CIM data models, correlation searches, notable events, Risk-Based Alerting (RBA), and asset/identity enrichment.

> Time picker per scenario (same as Section 3):
> - **Scenario A — Web attack:** `8/10/2016 00:00:00` → `8/12/2016 00:00:00`
> - **Scenario B — Ransomware:** `8/24/2016 00:00:00` → `8/25/2016 00:00:00`

---

## ⚠️ Prerequisites — read first

The default lab runs `splunk/splunk:latest` with **no ES app installed**. There are two paths through this section:

| Path | What to install | Covers |
|---|---|---|
| **Lightweight** (recommended) | [Splunk Common Information Model](https://splunkbase.splunk.com/app/1621) (free) + a few CIM-compliant TAs (Stream, Windows, Suricata) | All 10 questions, using `\| collect index=notable` / `index=risk` to simulate ES indexes |
| **Full ES** | Splunk Enterprise Security trial (60-day, free account at splunk.com) | Same, plus the real Incident Review, Risk Analysis, and Adaptive Response UI |

**Lightweight install — 5 steps:**
1. Download CIM app `.tgz` from [splunkbase.splunk.com/app/1621](https://splunkbase.splunk.com/app/1621)
2. Splunk Web → **Apps → Manage Apps → Install app from file**
3. Optional: install [Splunk_TA_windows](https://splunkbase.splunk.com/app/742), [TA-suricata](https://splunkbase.splunk.com/app/2760), [Splunk_TA_stream](https://splunkbase.splunk.com/app/1923) for cleaner CIM mappings on BOTS v1
4. Splunk Web → **Settings → Data models** → pick a model → **Edit Acceleration** → enable (1 day backfill is enough for BOTS v1)
5. Create indexes `notable` and `risk` via **Settings → Indexes → New Index**

> 💡 If a `| from datamodel:` query returns zero rows, the most likely cause is missing TAs — the BOTS v1 sourcetypes aren't tagged into CIM out of the box.

---

## Subsection A — CIM Data Models (Q51–Q53)

### Q51 — Failed logons via the Authentication data model

Using the `Authentication` data model (not the raw `WinEventLog:Security` sourcetype), find the top 10 users by **failed** logon count during the Scenario A window. Compare your output against your earlier raw-SPL answer for the same question.

**Hint:** Two equivalent shapes — pick whichever you want first:
```spl
| from datamodel:"Authentication"
| search action="failure"
| stats count by user
| sort - count | head 10
```
The normalized field names — `user`, `action`, `src`, `dest` — are the whole point of CIM. Notice you no longer have to remember `TargetUserName` vs `subject_account` vs whatever the sourcetype calls it.
**Skill:** `| from datamodel:` + CIM normalization

---

### Q52 — Same question, accelerated via `tstats`

Re-run Q51 with `tstats summariesonly=t`. Compare runtime against Q51.

**Hint:**
```spl
| tstats summariesonly=t count
    FROM datamodel=Authentication
    WHERE Authentication.action="failure"
    BY Authentication.user
| rename Authentication.user as user
| sort - count | head 10
```
Why is `tstats` an order of magnitude faster? What's the *risk* of `summariesonly=t` if your acceleration is behind?
**Skill:** `tstats FROM datamodel`, accelerated DM, `<DataModel>.<field>` naming

---

### Q53 — Network traffic via CIM

Using the `Network_Traffic` data model, find the top 10 external `src` values by **bytes_out** to `imreallynotbatman.com` (or its IP) during Scenario A. (BOTS v1 backs `Network_Traffic` from `stream:ip` / `suricata`.)

**Hint:**
```spl
| tstats summariesonly=t sum(All_Traffic.bytes_out) as bytes_out
    FROM datamodel=Network_Traffic
    WHERE All_Traffic.dest_ip="192.168.250.70"
    BY All_Traffic.src
| rename All_Traffic.src as src
| sort - bytes_out | head 10
```
Adjust `dest_ip` if your dataset shows a different IP for the web server (you confirmed it in Q31 of Section 3).
**Skill:** numeric aggregations inside `tstats`; CIM `Network_Traffic` schema

---

## Subsection B — Correlation Search Logic (Q54–Q55)

> A "correlation search" in ES is just a saved search whose output rows become notable events. Author the SPL today on plain Splunk; turning it into a real ES correlation search later is one checkbox.

### Q54 — Write the correlation SPL for the Q31–Q40 web attack

Author a single SPL that, given the Scenario A time window, returns **one row per attacker IP** with the fields ES expects on a notable: `src`, `dest`, `signature`, `severity`, `count`. The detection logic should be: a source IP that hit ≥ 200 distinct `uri_path` values OR ≥ 5 SQL-injection-style URLs (`uri` contains `union`/`select`/`%27`) against the same `dest_ip`.

**Hint:**
```spl
index=botsv1 sourcetype=stream:http
| eval is_sqli = if(match(uri, "(?i)(union|select|0x|%27|--)"), 1, 0)
| stats count, dc(uri_path) as unique_paths, sum(is_sqli) as sqli_hits
        by src_ip dest_ip
| where unique_paths >= 200 OR sqli_hits >= 5
| rename src_ip as src, dest_ip as dest
| eval signature = case(sqli_hits >= 5, "SQL Injection Probe",
                        unique_paths >= 200, "Web Scanner Activity",
                        true(), "Suspicious Web Activity"),
       severity  = if(sqli_hits >= 5, "high", "medium")
| table _time src dest signature severity count unique_paths sqli_hits
```
**Skill:** designing the *output shape* of a correlation search

---

### Q55 — Persist the result into a simulated `index=notable`

Take Q54's output and write it into `index=notable` with rule metadata so an analyst can review it later.

**Hint:**
```spl
<Q54 search>
| eval rule_name        = signature,
       rule_id          = case(sqli_hits >= 5, "WEB-SQLI-001",
                               true(),         "WEB-SCAN-001"),
       rule_description = "Authored from self-practice Section 4 Q55"
| collect index=notable
```
Verify with:
```spl
index=notable rule_id IN ("WEB-SQLI-001", "WEB-SCAN-001")
| table _time src dest rule_name rule_id severity unique_paths sqli_hits
```
**Skill:** `| collect` to materialize detections; rule metadata schema

---

## Subsection C — Notable Event Triage (Q56–Q57)

### Q56 — Build the analyst triage view

Query `index=notable` and produce a triage table: one row per `(src, signature)`, showing `first_seen`, `last_seen`, total `count`, and the latest `severity`, sorted by count descending.

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
**Skill:** `earliest()`/`latest()` + `convert ctime()` for a human-readable triage list

---

### Q57 — Throttle: 1 notable per (src, signature) per hour

Repeat Q56, but if the same `(src, signature)` fires multiple times in a single hour, count it as **one** notable. (This mirrors ES's throttle window on a correlation search.)

**Hint:**
```spl
index=notable
| bin span=1h _time as window
| stats min(_time) as first_event, count by window src signature severity
| stats earliest(first_event) as first_seen,
        latest(first_event)   as last_seen,
        sum(count) as total_events,
        count as throttled_groups
    by src signature severity
| convert ctime(first_seen) ctime(last_seen)
| sort - throttled_groups
```
`throttled_groups` = how many distinct 1-hour windows this `(src, signature)` showed up in — a better noise-vs-signal metric than raw count.
**Skill:** throttling / dedup-by-time-window pattern

---

## Subsection D — Risk-Based Alerting (Q58–Q59)

> RBA flips the model: instead of one notable per detection, each detection contributes a **risk score** to a `risk_object` (host or user). When the *cumulative* score crosses a threshold, that fires a single notable. Result: 100 low-confidence signals on one box = one high-confidence incident, not 100 alerts.

### Q58 — Emit risk events from the Scenario B (Cerber) detections

Re-run two of your Scenario B detections — pick *any* two of: drive-by domain hit (`solidaritedeproximite.org`), Cerber file extensions (`*.cerber`), `cscript.exe` spawning suspicious processes, ET TROJAN Suricata alerts — and for each match emit a risk event into `index=risk`. Use:
- `risk_object` = the affected host (e.g. `we8105desk`)
- `risk_object_type` = `"system"`
- `risk_score` = your judgment (suggest 30 for the domain hit, 60 for the Suricata TROJAN alert, etc.)
- `source_rule` = a short rule name

**Hint:** Detection 1 — drive-by domain hit:
```spl
index=botsv1 sourcetype=stream:http site="*solidaritedeproximite.org*"
| eval risk_object      = host,
       risk_object_type = "system",
       risk_score       = 30,
       risk_message     = "HTTP contact to known drive-by domain solidaritedeproximite.org",
       source_rule      = "Cerber - Drive-by Domain"
| table _time risk_object risk_object_type risk_score risk_message source_rule
| collect index=risk
```
Detection 2 — Suricata TROJAN alerts:
```spl
index=botsv1 sourcetype=suricata alert.signature="*ET TROJAN*Cerber*"
| eval risk_object      = host,
       risk_object_type = "system",
       risk_score       = 60,
       risk_message     = "Suricata ET TROJAN signature: " . 'alert.signature',
       source_rule      = "Cerber - Suricata IDS"
| table _time risk_object risk_object_type risk_score risk_message source_rule
| collect index=risk
```
Run both, then check `index=risk` to confirm.
**Skill:** the RBA event schema (`risk_object`, `risk_score`, `source_rule`)

---

### Q59 — Aggregate risk → fire one "risk incident"

Query `index=risk` over the last 24h of dataset time and surface any `risk_object` whose **cumulative** `risk_score` ≥ 80 and which has triggered ≥ 2 *distinct* `source_rule` values (multiple rules firing on the same host is much stronger evidence than one rule firing repeatedly).

**Hint:**
```spl
index=risk
| stats sum(risk_score)         as total_risk,
        dc(source_rule)         as distinct_rules,
        values(source_rule)     as rules_fired,
        latest(_time)           as last_seen,
        values(risk_message)    as risk_details
    by risk_object risk_object_type
| where total_risk >= 80 AND distinct_rules >= 2
| convert ctime(last_seen)
| sort - total_risk
```
This is *exactly* the kind of SPL that ES ships as the "Risk Notable" correlation search out of the box.
**Skill:** the cumulative-risk → notable pattern

---

## Subsection E — Asset & Identity Enrichment (Q60)

### Q60 — Enrich notables with criticality from a CSV lookup

Build a minimal `assets.csv` lookup that captures business context for the three notable BOTS v1 hosts, then re-run Q56 with the enrichment columns added.

**Steps:**
1. Create `assets.csv` (use any text editor) with this content:
   ```csv
   host,ip,criticality,owner,business_unit
   imreallynotbatman.com,192.168.250.70,critical,batman,marketing
   we8105desk,192.168.250.100,medium,bob.smith,sales
   we9041srv,192.168.250.20,high,file-share,sales
   ```
2. Splunk Web → **Settings → Lookups → Lookup table files → New** → upload the CSV
3. **Settings → Lookups → Lookup definitions → New** → name `assets_lookup`, file `assets.csv`
4. Query:
   ```spl
   index=notable
   | lookup assets_lookup host AS dest OUTPUT criticality owner business_unit
   | stats earliest(_time) as first_seen,
           latest(_time)   as last_seen,
           count,
           values(criticality)   as criticality,
           values(owner)         as owner,
           values(business_unit) as business_unit
       by src signature
   | convert ctime(first_seen) ctime(last_seen)
   | sort - count
   ```

This is exactly how the ES **Asset & Identity Framework** works under the hood — pre-defined lookups (`asset_lookup_by_str`, `identity_lookup_expanded`) auto-join via `src`/`dest`/`user` on the `Notable Events` data model. The framework just makes it automatic.
**Skill:** CSV lookups → enrichment join pattern

---

🎓 **End of self-practice (60 questions).** If you completed every section, you now have hands-on fluency across:
- raw SPL (Sections 1–2)
- SOC Tier 1 investigation flow (Section 3)
- ES analyst workflow: CIM, correlation, notables, RBA, enrichment (Section 4)

**Where next?**
- Re-do Sections 1–3 against BOTS v2 / v3 (`./setup.sh --v2` / `--v3`)
- Convert each Section-4 detection into an actual saved search → schedule it → wire an alert action
- Map every detection to a MITRE ATT&CK technique in `annotations.mitre_attack` and pivot by technique to see your detection coverage as a heatmap
