# Section 4 — CIM, Data Models & the Enterprise Security Workflow (Q51–Q67)

🟠→🟣 **Level:** Intermediate (Part 1, Q51–Q60) → Advanced (Part 2, Q61–Q67)
🎯 **Goal:** Learn to think in **normalized fields** with CIM data models (Part 1), then use that skill to build the core Splunk Enterprise Security workflow — correlation searches, notable events, Risk-Based Alerting (RBA), and asset/identity enrichment (Part 2).

> **New to CIM? Read this.** Part 1 (Q51–Q60) is a gentle, intermediate warm-up: you just learn what a data model is and how to query one. **Do these first.** Part 2 (Q61–Q67) is advanced detection-engineering — come back to it only once Part 1 feels comfortable. You do **not** need to finish Part 2 to call Section 4 "done" as a beginner.

> Time picker per scenario (same as Section 3):
> - **Scenario A — Web attack:** `8/10/2016 00:00:00` → `8/12/2016 00:00:00`
> - **Scenario B — Ransomware:** `8/24/2016 00:00:00` → `8/25/2016 00:00:00`

---

## ⚠️ Prerequisites — read first

The default lab runs `splunk/splunk:latest` with **no ES app installed**. There are two paths through this section:

| Path | What to install | Covers |
|---|---|---|
| **Lightweight** (recommended) | [Splunk Common Information Model](https://splunkbase.splunk.com/app/1621) (free) + a few CIM-compliant TAs (Stream, Windows, Suricata) | All 17 questions. Part 2 uses `\| collect index=notable` / `index=risk` to simulate ES indexes |
| **Full ES** | Splunk Enterprise Security trial (60-day, free account at splunk.com) | Same, plus the real Incident Review, Risk Analysis, and Adaptive Response UI |

**Lightweight install — 5 steps:**
1. Download CIM app `.tgz` from [splunkbase.splunk.com/app/1621](https://splunkbase.splunk.com/app/1621)
2. Splunk Web → **Apps → Manage Apps → Install app from file**
3. Optional: install [Splunk_TA_windows](https://splunkbase.splunk.com/app/742), [TA-suricata](https://splunkbase.splunk.com/app/2760), [Splunk_TA_stream](https://splunkbase.splunk.com/app/1923) for cleaner CIM mappings on BOTS v1
4. Splunk Web → **Settings → Data models** → pick a model → **Edit Acceleration** → enable (1 day backfill is enough for BOTS v1)
5. **(Part 2 only)** Create indexes `notable` and `risk` via **Settings → Indexes → New Index**

> 💡 If a `| from datamodel:` query returns zero rows, the most likely cause is missing TAs — the BOTS v1 sourcetypes aren't tagged into CIM out of the box. Every Part-1 solution includes a raw-SPL fallback so you're never stuck.

---

## Primer — What are Data Models and CIM? (read before Q51)

If you've only ever written `index=... sourcetype=...` searches, this section introduces two new ideas. Read this once; the rest of Section 4 assumes it.

### The problem they solve

Every log source names the same thing differently. A failed Windows logon, a failed SSH logon, and a failed VPN logon all mean *"someone failed to authenticate"* — but the raw fields look nothing alike:

| Raw source | "who" field | "outcome" field |
|---|---|---|
| `WinEventLog:Security` | `TargetUserName` | derived from `EventCode` (4625 = fail) |
| Linux `secure` | `user` | text in the message body |
| A VPN appliance | `login` | `status` |

To hunt across all three, you'd have to memorize every vendor's field names and write three different searches. That doesn't scale.

### CIM = a shared dictionary of field names

**CIM (Common Information Model)** is Splunk's agreed-upon set of field names and event categories. Under CIM, *all* authentication events — no matter the vendor — expose the same normalized fields:

- `user` — the account (instead of `TargetUserName` / `login` / …)
- `action` — `success` or `failure`
- `src` / `dest` — source and destination host
- `app` — the application involved

The normalization isn't magic — it's done by **TAs** (Technology Add-ons), small apps that map a sourcetype's raw fields onto CIM names and **tag** the events (e.g. tag `authentication`). That's why the Prerequisites step asks you to install a few TAs: without them, BOTS v1's raw sourcetypes aren't tagged into CIM and the data models come back empty.

> **CIM (the app)** ships ~25 pre-built data models: `Authentication`, `Network_Traffic`, `Web`, `Malware`, `Endpoint`, `Change`, … Installing the CIM app is what gives you `datamodel=Authentication` to search against.

### Data Model = a schema (a named, structured view) built on those fields

A **Data Model** is a hierarchical, schema-on-top-of-raw-logs. Instead of "all events in an index," a data model says: *"here is a dataset called `Authentication`; it contains only events tagged `authentication`; and it exposes these normalized fields."* You then query the **model**, not the sourcetype.

Three ways to touch a data model — you'll use all three in Part 1:

```spl
| datamodel Authentication Authentication search   ← explore the model's raw events (Q52)
| from datamodel:"Authentication"                  ← pipe the model into normal SPL (Q53)
| tstats ... FROM datamodel=Authentication         ← fast, aggregate-only, uses the acceleration (Q55)
```

Two naming quirks to expect:
- Inside `tstats` you must fully qualify fields with the dataset name: `Authentication.user`, `Authentication.action` (then usually `| rename Authentication.user AS user`).
- **Acceleration** = Splunk pre-computes summaries of the model on a schedule so `tstats` is near-instant. `summariesonly=t` reads *only* those pre-computed summaries — blazing fast, but if acceleration is paused or behind, you silently get an **incomplete** answer. Use `summariesonly=f` when you're unsure (Q60 is all about this check).

### Why this matters for Enterprise Security

Every ES correlation search, the Risk framework, and the Asset & Identity framework are all built **on top of CIM data models** — not raw sourcetypes. Learning to think in `user` / `action` / `src` / `dest` instead of `TargetUserName` is the entire on-ramp to ES. Q53 has you answer a question you already solved with raw SPL — this time through the `Authentication` model — precisely so you can feel the difference.

---

# Part 1 — CIM & Data Model Basics (Q51–Q60) 🟠 Intermediate

> Goal for this part: get comfortable *finding*, *exploring*, and *querying* data models, and learn to **trust but verify** their output against raw logs. Full SPL is shown for every question — this is your first exposure, so nothing is hidden. Retype it by hand rather than copy/pasting.

## Subsection A — Finding & exploring data models (Q51–Q52)

### Q51 — Discover which data models exist

Before you can query a model, find out which ones CIM installed and which are **accelerated** (accelerated = fast `tstats` works).

**Hint:** List every model with the `datamodel` command on its own:
```spl
| datamodel
```
For acceleration status and size, browse **Settings → Data models** in the UI, or query the REST endpoint:
```spl
| rest /services/datamodel/model
| table title acceleration.enabled
```
Note which of `Authentication`, `Network_Traffic`, and `Web` you'll use in Part 1 show `acceleration.enabled = 1`. If they're all `0`, go back to Prerequisites step 4 and enable acceleration.
**Skill:** discovering data models + reading acceleration status

---

### Q52 — Look inside the Authentication model

Pull a handful of raw events *out of* the `Authentication` model and eyeball the normalized fields. Which raw sourcetype did each event come from, and what are its `user` / `action` values?

**Hint:**
```spl
| datamodel Authentication Authentication search
| head 10
| table _time sourcetype user action src dest app
```
The syntax is `| datamodel <Model> <Dataset> search` — here the model and its root dataset are both named `Authentication`. Compare the `user`/`action` columns to the raw `TargetUserName`/`EventCode` fields you used back in Section 2: **same events, friendlier names.**
**Skill:** `| datamodel <model> <dataset> search`; seeing the raw→normalized mapping

---

## Subsection B — Querying the Authentication model (Q53–Q56)

### Q53 — Top users by failed logon (via `from datamodel:`)

Using the `Authentication` data model (not the raw `WinEventLog:Security` sourcetype), find the top 10 users by **failed** logon count during the Scenario A window. Compare your output against your earlier raw-SPL answer for the same question.

**Hint:**
```spl
| from datamodel:"Authentication"
| search action="failure"
| stats count by user
| sort - count | head 10
```
The normalized field names — `user`, `action`, `src`, `dest` — are the whole point of CIM. Notice you no longer have to remember `TargetUserName` vs `subject_account` vs whatever the sourcetype calls it.
**Skill:** `| from datamodel:` + CIM normalization

---

### Q54 — Split logons by outcome, then find failure sources

Two quick questions against the same model: (a) how many logons were `success` vs `failure` in Scenario A, and (b) which top 5 source hosts (`src`) produced the most **failed** logons?

**Hint:** The whole outcome lives in one normalized field — `action` — with just two values:
```spl
| from datamodel:"Authentication"
| stats count by action
```
Then pivot to the noisy sources:
```spl
| from datamodel:"Authentication"
| search action="failure"
| stats count by src
| sort - count | head 5
```
No `EventCode=4624` vs `4625` to memorize — `action` already means "did it succeed?"
**Skill:** filtering & grouping on the normalized `action` field

---

### Q55 — Same question, accelerated via `tstats`

Re-run Q53 with `tstats summariesonly=t`. Compare runtime against Q53.

**Hint:**
```spl
| tstats summariesonly=t count
    FROM datamodel=Authentication
    WHERE Authentication.action="failure"
    BY Authentication.user
| rename Authentication.user as user
| sort - count | head 10
```
Why is `tstats` an order of magnitude faster? What's the *risk* of `summariesonly=t` if your acceleration is behind? (You'll answer that risk head-on in Q60.)
**Skill:** `tstats FROM datamodel`, accelerated DM, `<DataModel>.<field>` naming

---

### Q56 — Failed logons over time

Chart failed logons **per hour** across Scenario A using accelerated `tstats`. When does the brute force spike, and which host was targeted?

**Hint:** `tstats` can bucket by time directly with `BY _time span=`:
```spl
| tstats summariesonly=t count
    FROM datamodel=Authentication
    WHERE Authentication.action="failure"
    BY _time span=1h
```
Switch to the **Visualization** tab → Line chart to see the spike. Add `Authentication.dest` to the `BY` clause to split the line per targeted host:
```spl
| tstats summariesonly=t count
    FROM datamodel=Authentication
    WHERE Authentication.action="failure"
    BY _time span=1h Authentication.dest
```
This `tstats ... BY _time` shape is exactly how ES renders its dashboards fast.
**Skill:** `tstats ... BY _time span=`; time-series straight from an accelerated DM

---

## Subsection C — Other core models: Web & Network_Traffic (Q57–Q59)

### Q57 — Web requests via the `Web` data model

Using the `Web` data model, find the top 10 `url` values hitting the web server (`dest` = the batman host, `192.168.250.70`) during Scenario A, plus a count of requests broken down by HTTP `status`.

**Hint:**
```spl
| tstats summariesonly=t count
    FROM datamodel=Web
    WHERE Web.dest="192.168.250.70"
    BY Web.url
| rename Web.url as url
| sort - count | head 10
```
And the status-code breakdown:
```spl
| tstats summariesonly=t count
    FROM datamodel=Web
    WHERE Web.dest="192.168.250.70"
    BY Web.status
```
The `Web` model normalizes `stream:http`, `suricata`, IIS, and Apache all to the same `url` / `status` / `http_method` fields.
**Skill:** the CIM `Web` schema (`url`, `status`, `http_method`)

---

### Q58 — Bytes out via the `Network_Traffic` model

Using the `Network_Traffic` data model, find the top 10 external `src` values by **bytes_out** to the web server during Scenario A. (BOTS v1 backs `Network_Traffic` from `stream:ip` / `suricata`.)

**Hint:**
```spl
| tstats summariesonly=t sum(All_Traffic.bytes_out) as bytes_out
    FROM datamodel=Network_Traffic
    WHERE All_Traffic.dest_ip="192.168.250.70"
    BY All_Traffic.src
| rename All_Traffic.src as src
| sort - bytes_out | head 10
```
Adjust `dest_ip` if your dataset shows a different IP for the web server (you confirmed it in Q31 of Section 3). Note the dataset is called `All_Traffic`, not `Network_Traffic` — that's the root dataset name inside the model.
**Skill:** numeric aggregations (`sum()`) inside `tstats`; CIM `Network_Traffic` schema

---

### Q59 — Top talkers & port spread

Still in `Network_Traffic`: find the top external `src` hosts by **connection count** to the web server, and how many **distinct destination ports** each one touched (a port-sweep tell).

**Hint:** You can put `count` and `dc()` in the same `tstats`:
```spl
| tstats summariesonly=t count dc(All_Traffic.dest_port) as distinct_ports
    FROM datamodel=Network_Traffic
    WHERE All_Traffic.dest_ip="192.168.250.70"
    BY All_Traffic.src
| rename All_Traffic.src as src
| sort - count | head 10
```
Read the two numbers together: **many distinct ports** from one source = scanning; **one port, huge count** = brute force / flooding.
**Skill:** `count` + `dc()` together inside `tstats`; reading connection patterns

---

## Subsection D — Trust but verify (Q60)

### Q60 — Does the data model agree with the raw logs?

Take any Part-1 answer (Q53's failed-logon *total* is a good one) and run it **both** ways — through the accelerated data model **and** directly against the raw sourcetype. Do the totals match? If not, what does the gap tell you?

**Hint:**
```spl
# (a) via the data model — accelerated summaries only
| tstats summariesonly=t count
    FROM datamodel=Authentication
    WHERE Authentication.action="failure"
```
```spl
# (b) the same count, straight from raw events
index=botsv1 sourcetype=WinEventLog:Security EventCode=4625
| stats count
```
If (a) is **lower** than (b), your acceleration is behind *or* a sourcetype isn't CIM-tagged. Re-run (a) with `summariesonly=f` — that forces Splunk to read raw events for the un-summarized gap:
```spl
| tstats summariesonly=f count
    FROM datamodel=Authentication
    WHERE Authentication.action="failure"
```
This "does my model agree with raw?" check is the single most important habit before you trust any detection built on a data model — and it's the bridge into Part 2.
**Skill:** validating DM completeness; `summariesonly=t` vs `f` vs raw

---

🎓 **End of Part 1.** You can now discover data models, explore them, query them three ways (`from datamodel:`, `datamodel search`, `tstats`), and verify their output. That's the whole foundation ES stands on. **If you're a beginner, this is a great place to stop and consolidate** — repeat Part 1 in a couple of days before moving on.

---

# Part 2 — Enterprise Security Workflow (Q61–Q67) 🟣 Advanced

> ⚠️ **Advanced — detection-engineering territory.** These questions ask you to *design* detections, not just run them. From here on, `**Hint:**` is a prose nudge and the full SPL is tucked into a collapsible **▸ Show full SPL** block — try it yourself first. If Part 1 didn't feel solid, go back; everything below builds on thinking in normalized fields.

## Subsection E — Correlation Search Logic (Q61–Q62)

> A "correlation search" in ES is just a saved search whose output rows become notable events. Author the SPL today on plain Splunk; turning it into a real ES correlation search later is one checkbox.

### Q61 — Write the correlation SPL for the Q31–Q40 web attack

Author a single SPL that, given the Scenario A time window, returns **one row per attacker IP** with the fields ES expects on a notable: `src`, `dest`, `signature`, `severity`, `count`. The detection logic should be: a source IP that hit ≥ 200 distinct `uri_path` values OR ≥ 5 SQL-injection-style URLs (`uri` contains `union`/`select`/`%27`) against the same `dest_ip`.

**Hint:** A correlation search is really just a `stats` that ends in the exact fields ES puts on a notable. Start from `sourcetype=stream:http`; flag SQLi-looking URIs with `eval ... if(match(uri, ...))`; then in **one** `stats` compute `count`, `dc(uri_path)`, and `sum()` of your SQLi flag, grouped by source + dest. Filter the rows with `where`, then use `eval case()` to label `signature` and `severity`. Finish with `rename` so the output columns are `src`/`dest`.

<details><summary>Show full SPL</summary>

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

</details>

**Skill:** designing the *output shape* of a correlation search

---

### Q62 — Persist the result into a simulated `index=notable`

Take Q61's output and write it into `index=notable` with rule metadata so an analyst can review it later.

**Hint:** Reuse your whole Q61 pipeline, then append an `eval` that stamps rule metadata (`rule_name`, a `rule_id` chosen with `case()`, `rule_description`) and finish with `| collect index=notable` to write the rows into the index. `| collect` is the manual stand-in for what a real ES correlation search does automatically. Then run a second search against `index=notable` to confirm the rows landed.

<details><summary>Show full SPL</summary>

```spl
<Q61 search>
| eval rule_name        = signature,
       rule_id          = case(sqli_hits >= 5, "WEB-SQLI-001",
                               true(),         "WEB-SCAN-001"),
       rule_description = "Authored from self-practice Section 4 Q62"
| collect index=notable
```
Verify with:
```spl
index=notable rule_id IN ("WEB-SQLI-001", "WEB-SCAN-001")
| table _time src dest rule_name rule_id severity unique_paths sqli_hits
```

</details>

**Skill:** `| collect` to materialize detections; rule metadata schema

---

## Subsection F — Notable Event Triage (Q63–Q64)

### Q63 — Build the analyst triage view

Query `index=notable` and produce a triage table: one row per `(src, signature)`, showing `first_seen`, `last_seen`, total `count`, and the latest `severity`, sorted by count descending.

**Hint:** One `stats` over `index=notable`, grouped by `src signature`. Ask for `earliest(_time)` and `latest(_time)` (your first/last seen), a `count`, and `latest(severity)`. Those time fields come back as raw epoch numbers — make them human-readable with `convert ctime(...)` — then `sort - count`.

<details><summary>Show full SPL</summary>

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

</details>

**Skill:** `earliest()`/`latest()` + `convert ctime()` for a human-readable triage list

---

### Q64 — Throttle: 1 notable per (src, signature) per hour

Repeat Q63, but if the same `(src, signature)` fires multiple times in a single hour, count it as **one** notable. (This mirrors ES's throttle window on a correlation search.)

**Hint:** This is a two-stage `stats`. **Stage 1:** `bin span=1h _time` to bucket events into hourly windows, then aggregate per `(window, src, signature)` — this collapses everything inside one hour into a single group. **Stage 2:** a second `stats` that *counts how many distinct hourly windows* each `(src, signature)` appeared in. That window count (call it `throttled_groups`) is a far better noise-vs-signal metric than raw event count.

<details><summary>Show full SPL</summary>

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

</details>

`throttled_groups` = how many distinct 1-hour windows this `(src, signature)` showed up in — a better noise-vs-signal metric than raw count.
**Skill:** throttling / dedup-by-time-window pattern

---

## Subsection G — Risk-Based Alerting (Q65–Q66)

> RBA flips the model: instead of one notable per detection, each detection contributes a **risk score** to a `risk_object` (host or user). When the *cumulative* score crosses a threshold, that fires a single notable. Result: 100 low-confidence signals on one box = one high-confidence incident, not 100 alerts.

### Q65 — Emit risk events from the Scenario B (Cerber) detections

Re-run two of your Scenario B detections — pick *any* two of: drive-by domain hit (`solidaritedeproximite.org`), Cerber file extensions (`*.cerber`), `cscript.exe` spawning suspicious processes, ET TROJAN Suricata alerts — and for each match emit a risk event into `index=risk`. Use:
- `risk_object` = the affected host (e.g. `we8105desk`)
- `risk_object_type` = `"system"`
- `risk_score` = your judgment (suggest 30 for the domain hit, 60 for the Suricata TROJAN alert, etc.)
- `source_rule` = a short rule name

**Hint:** The shape is the same for every detection: filter to the matching events, then `eval` the four RBA fields — `risk_object` (the affected host), `risk_object_type="system"`, a numeric `risk_score` you choose, and a short `source_rule` name (plus a human `risk_message`) — and finish with `| collect index=risk`. Do it once per detection with a different filter and score, then search `index=risk` to confirm both landed.

<details><summary>Show full SPL</summary>

Detection 1 — drive-by domain hit:
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

</details>

**Skill:** the RBA event schema (`risk_object`, `risk_score`, `source_rule`)

---

### Q66 — Aggregate risk → fire one "risk incident"

Query `index=risk` over the last 24h of dataset time and surface any `risk_object` whose **cumulative** `risk_score` ≥ 80 and which has triggered ≥ 2 *distinct* `source_rule` values (multiple rules firing on the same host is much stronger evidence than one rule firing repeatedly).

**Hint:** One `stats` over `index=risk`, grouped by `risk_object`. Sum the scores (`sum(risk_score)` → cumulative risk), count *distinct* rules (`dc(source_rule)`), and keep `values(source_rule)` so you can see which rules fired. Then `where total_risk >= 80 AND distinct_rules >= 2` — the "≥2 distinct rules" test is the key idea: many rules on one host beats one rule firing repeatedly.

<details><summary>Show full SPL</summary>

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

</details>

This is *exactly* the kind of SPL that ES ships as the "Risk Notable" correlation search out of the box.
**Skill:** the cumulative-risk → notable pattern

---

## Subsection H — Asset & Identity Enrichment (Q67)

### Q67 — Enrich notables with criticality from a CSV lookup

Build a minimal `assets.csv` lookup that captures business context for the three notable BOTS v1 hosts, then re-run Q63 with the enrichment columns added.

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
4. Build the enriched query: take your **Q63** triage search and drop a `| lookup assets_lookup host AS dest OUTPUT criticality owner business_unit` in *before* the `stats`, then add `values(criticality)`, `values(owner)`, and `values(business_unit)` to the `stats` so each notable now carries its business context.

<details><summary>Show full SPL</summary>

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

</details>

This is exactly how the ES **Asset & Identity Framework** works under the hood — pre-defined lookups (`asset_lookup_by_str`, `identity_lookup_expanded`) auto-join via `src`/`dest`/`user` on the `Notable Events` data model. The framework just makes it automatic.
**Skill:** CSV lookups → enrichment join pattern

---

🎓 **End of self-practice (67 questions).** If you completed every section, you now have hands-on fluency across:
- raw SPL (Sections 1–2)
- SOC Tier 1 investigation flow (Section 3)
- CIM data models (Section 4, Part 1)
- ES analyst workflow: correlation, notables, RBA, enrichment (Section 4, Part 2)

**Where next?**
- Re-do Sections 1–3 against BOTS v2 / v3 (`./setup.sh --v2` / `--v3`)
- Convert each Part 2 detection into an actual saved search → schedule it → wire an alert action
- Map every detection to a MITRE ATT&CK technique in `annotations.mitre_attack` and pivot by technique to see your detection coverage as a heatmap
