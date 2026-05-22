# Section 5 — Splunk ES 8.3 Workshop Lab (Q39–Q50)

🟣 **Level:** Advanced
🎯 **Goal:** Mirror the official ES 8.3 Hands-On Lab Guide (workshop exercises 1–9) and translate every UI step into a concrete deliverable — either a piece of SPL authored on your lab, or a written design artifact that you would type into the ES 8 detection editor.

> 📖 **Companion deck:** `Enterprise Security 8.3 Hands-On Lab Gude.pdf` (same folder)
> Each question below references the matching workshop exercise number.

---

## ⚠️ Setup paths

ES 8.3 is a separate, licensed Splunk app. Three ways to follow along:

| Path | Effort | What you can verify |
|---|---|---|
| **A. Splunk Core only** (current lab default) | None | Write SPL that *would* power each ES detection + design artifacts on paper |
| **B. Install ES trial** in the lab | 30 min | Author detections in the real ES 8 UI, see Findings / Finding Groups / Response Plans |
| **C. BOSS Platform** ([bots.splunk.com](https://bots.splunk.com)) | Free account | Splunk-hosted ES 8 instance with the workshop data preloaded — the **exact** environment shown in the PDF |

Use Path A as a baseline and upgrade to B or C for the UI-only exercises (Q39, Q45, Q48).

---

## ES 8 Terminology Map (read first)

ES 8 renamed several core concepts. The PDF uses the new terms — Section 4 of this pack used the old ones. Keep this table open:

| Old (ES 7.x / Section 4 here) | ES 8 (PDF) | Where it lives |
|---|---|---|
| Notable Event | **Finding** | Analyst Queue |
| Correlation Search | **Detection** (Event-Based) | Content Management → Detections |
| Risk Incident Rule | **Finding-Based Detection** | Content Management → Detections |
| Aggregated risk notable | **Finding Group** | Analyst Queue |
| (manually grouped notable) | **Intermediate Finding** | Internal — not triaged directly |
| Adaptive Response action | **Response Action** / Playbook | Response Plans + SOAR |
| Investigation Workbench | **Investigations** (formal lifecycle + Response Plans) | Side panel |

---

## Exercise 1 — UI Familiarization

### Q39 — ES 8 navigation muscle memory *(workshop Exercise 1)*

Without opening anything, map each analyst question to the ES 8 **menu path** you'd click. (If you've only used ES 7, look up the new menu names in the PDF / ES docs.)

| Analyst question | ES 8 menu path |
|---|---|
| "Show me everything that fired in the last hour" | ? |
| "Open the detection that produced this alert" | ? |
| "Start a formal investigation on this Finding Group" | ? |
| "Compare the current detection to last week's version" | ? |
| "Run a SOAR playbook against this finding" | ? |

**Deliverable:** fill in the 5 paths. Self-check against the screenshots in the PDF (Exercise 1 pages).
**Skill:** ES 8 navigation literacy — pure UI fluency, no SPL

---

## Exercise 2 — Response Plans

> The PDF lists 8 built-in Response Plans (Account Compromise, Data Breach, Network Indicator Enrichment, NIST 800-61, Generic Incident Response, Self-Replicating Malware, Suspicious Email, Vulnerability Disclosure). Each is a *template* of phases + tasks.

### Q40 — Pick the right plan *(Exercise 2)*

For each scenario from the BOTS v1 dataset, pick the **one** built-in response plan that fits best, and justify in one line:

| Scenario | Best-fit plan | Why |
|---|---|---|
| `imreallynotbatman.com` brute force (Section 3 Scenario A) | ? | ? |
| Cerber ransomware on `we8105desk` (Section 3 Scenario B) | ? | ? |
| Phishing email reported by a user | ? | ? |
| Critical CVE published for a webapp dependency | ? | ? |
| Suspicious sign-in from a new country (Section 3 Q25 Impossible Travel) | ? | ? |

**Deliverable:** 5-row table. No SPL — this is detection-engineering judgment.
**Skill:** matching incident type → IR playbook (NIST 800-61 categories)

---

### Q41 — Author a custom response plan *(Exercise 2, extension)*

For the **Cerber ransomware** scenario, sketch a custom plan with 4 phases (e.g. Detect → Contain → Eradicate → Recover) and **at least 3 tasks per phase**. For each task list: owner role (SOC T1, T2, IR lead), expected duration, and the SOAR action (if any) that automates it.

**Deliverable:** Markdown table — `phase | task | owner | duration | soar_action`. Example row:
```
Contain | Isolate we8105desk via EDR | SOC T2 | 5 min | crowdstrike_contain_host
```
This is what you'd type into ES 8's *Response Plans → Custom Plan → New Phase/Task*.
**Skill:** playbook design

---

## Exercise 3 — Investigations *(referenced but not deep in PDF; inferred from ES 8 docs)*

### Q42 — From Finding → Investigation

Describe the ES 8 lifecycle of a finding using these states, **in order**: `New`, `In Progress`, `Pending`, `Resolved`, `Closed`. For each state explain (1 sentence each):
- Who owns it
- What triggers the transition to the *next* state
- What artifacts (notes, evidence, tasks) accumulate at this state

**Deliverable:** 5-row table.
**Skill:** case management lifecycle (the part of ES 8 that replaces the old Incident Review)

---

## Exercise 4 — Detections Overview

### Q43 — Event-Based vs Finding-Based: when to use which *(Exercise 4)*

For each of these 6 detection ideas, decide: **Event-Based** or **Finding-Based**? Explain in one line.

| # | Detection idea | E or F | Why |
|---|---|---|---|
| 1 | "Single failed login from a brand-new geolocation" | ? | ? |
| 2 | "User accumulated risk score > 100 in 24h across ≥ 2 distinct detections" | ? | ? |
| 3 | "Suricata signature ET TROJAN Cerber alert" | ? | ? |
| 4 | "≥ 3 MITRE tactics observed on the same host within 1 hour" | ? | ? |
| 5 | "Process `cscript.exe` spawning `.tmp` payload" | ? | ? |
| 6 | "≥ 10 similar findings against the same source IP in 1 hour" | ? | ? |

**Rule of thumb:** Event-Based = directly on raw events (`tstats` / SPL); Finding-Based = grouping/scoring on top of existing findings.
**Skill:** correct framing of a detection at the right altitude

---

## Exercise 5 — Create Event-Based Detection

### Q44 — Author an Event-Based Detection for BOTS v1 *(Exercise 5)*

Author the **complete artifact** that you'd save into ES 8's Detection Editor for: **"Cerber ransomware indicator: cscript.exe spawning a 6-digit `.tmp` file on a workstation."**

The artifact has 5 fields — fill them in:

| Field | Value |
|---|---|
| **Name** | ? |
| **Description** | ? (1–2 sentences) |
| **Detection SPL** | ? — must produce one row per match with fields `dest`, `user`, `process`, `parent_process`, `file_name` |
| **Annotations: MITRE ATT&CK** | ? (tactic + technique, e.g. `TA0002 / T1059.005`) |
| **Throttling** | ? (window + key fields) |

**SPL hint:**
```spl
index=botsv1 sourcetype=WinEventLog:Security EventCode=4688
    ParentProcessName="*cscript.exe"
    NewProcessName="*.tmp"
| rex field=NewProcessName "\\\\(?<file_name>\d{6}\.tmp)$"
| where isnotnull(file_name)
| rename Computer as dest, Account_Name as user,
         NewProcessName as process, ParentProcessName as parent_process
| table _time dest user process parent_process file_name
```
**Skill:** authoring a complete detection (not just SPL — metadata + annotations + throttling are required by ES 8)

---

## Exercise 6 — Detection Versioning

### Q45 — Diff comparison workflow *(Exercise 6)*

In Q44 the detection had a false positive: legitimate IT scripts also spawn `.tmp` files. You ship **v2** of the detection that adds: `AND NOT (user="svc_*" OR user IN ("administrator", "SYSTEM"))`.

Answer in writing:
1. In ES 8's *Diff Comparison* view, what would be marked **dark red** vs **dark green** vs **light red/green** between v1 and v2? (See PDF Exercise 6 legend.)
2. List 2 concrete reasons you'd want to **rollback to v1** rather than keep v2 — i.e. when adding exclusions is *wrong*.
3. The PDF says change history captures "who, what, when". Why is *who* the most important field for compliance / audit?

**Skill:** detection lifecycle thinking — versioning isn't a developer feature, it's a **forensic** feature for the detection engineering team

---

## Exercise 7 — Finding-Based Detections

> The PDF lists 6 grouping types: **Entity, Threat Object, Cumulative Entity Risk, Kill Chain, MITRE ATT&CK, Similar Findings**, plus **Custom**. Q46 and Q47 each pick one and have you fully configure it.

### Q46 — Finding-Based Detection: Cumulative Entity Risk *(Exercise 7)*

Configure a Cumulative-Entity-Risk Finding-Based Detection: "If the **risk score** accumulated against any single entity exceeds **80** within **24 hours**, generate a Finding Group titled `<entity> – cumulative risk over threshold`."

Fill in:

| Field | Value |
|---|---|
| **Name** | ? |
| **Description** | ? |
| **Grouping mechanism** | Cumulative Entity Risk |
| **Risk score threshold** | 80 |
| **Time range** | 24h |
| **Entity field(s)** | ? (e.g. `risk_object` / `dest` / `user`) |
| **Finding Group title (with variables)** | ? — use ES 8 variable syntax like `$entity$ – cumulative risk $total_risk$` |
| **Equivalent preview SPL** *(ES 8 auto-generates this when you hit Preview)* | ? — should be a `tstats` over `index=risk` |

**Preview SPL hint:**
```spl
| tstats summariesonly=t sum(All_Risk.calculated_risk_score) as total_risk,
                        dc(All_Risk.source) as distinct_rules,
                        values(All_Risk.source) as rules
    FROM datamodel=Risk
    WHERE earliest=-24h
    BY All_Risk.risk_object, All_Risk.risk_object_type
| where total_risk >= 80
```
**Skill:** the most-used Finding-Based Detection type — Risk-Based Alerting promoted to a first-class object in ES 8

---

### Q47 — Finding-Based Detection: MITRE ATT&CK tactics *(Exercise 7)*

Configure a MITRE-based Finding-Based Detection: "If a single entity (`dest`) has findings spanning **≥ 3 distinct MITRE ATT&CK tactics** within **6 hours**, generate a Finding Group."

The intuition: a single tactic (e.g. *Defense Evasion* alone) is noisy, but **Execution + Persistence + Defense Evasion** chained on one host within hours is a high-confidence attack pattern.

Fill in:

| Field | Value |
|---|---|
| **Grouping mechanism** | MITRE ATT&CK |
| **Pivot field** | tactic (not technique) |
| **Threshold (number of tactics)** | 3 |
| **Time range** | 6h |
| **Entity field** | `dest` |
| **Equivalent preview SPL** | ? |

**Preview SPL hint:**
```spl
| tstats summariesonly=t
        dc(All_Risk.annotations.mitre_attack.mitre_tactic) as tactic_count,
        values(All_Risk.annotations.mitre_attack.mitre_tactic) as tactics,
        values(All_Risk.source) as rules
    FROM datamodel=Risk
    WHERE earliest=-6h
    BY All_Risk.risk_object
| where tactic_count >= 3
```
**Skill:** MITRE-aware detection design — *not* "did we see this technique?" but "did we see *enough breadth*?"

---

## Exercise 8 — Embedded Dashboards

### Q48 — Pick the right dashboard *(Exercise 8)*

ES 8 ships several embedded dashboards. For each analyst question, name the dashboard you'd open first:

| Analyst question | Dashboard |
|---|---|
| "How healthy is our SOC pipeline right now?" | ? |
| "Which users are accumulating the most risk this week?" | ? |
| "Which detections are firing the most — and could they be tuned?" | ? |
| "Did anything trigger on assets owned by the marketing org?" | ? |
| "Coverage map of our detections against MITRE ATT&CK" | ? |

**Hint:** Security Posture, Risk Analysis, Detection Analytics / Use Case Library, Asset Investigator, Security Content / ATT&CK matrix dashboards.
**Skill:** matching the question → the right ES 8 dashboard (so you don't pivot through 5 wrong ones first)

---

## Exercise 9 — SOAR Integration

### Q49 — Map Cerber response to SOAR actions *(Exercise 9)*

For the Cerber incident from Section 3 Scenario B, list **5 concrete SOAR actions** you'd build into a playbook, in the order they'd run. For each: action name, target (host/user/network), the integration that performs it, and whether it's *fully automatic* or *requires analyst approval*.

Example row:
```
1 | isolate_endpoint | host=we8105desk | CrowdStrike | analyst approval
```

**Suggested 5:**
1. Enrich the suspicious domain (`solidaritedeproximite.org`) via VirusTotal / threat intel
2. Isolate `we8105desk` via EDR
3. Disable user `bob.smith` in AD
4. Block the C2 domain at the perimeter firewall
5. Create a ticket in ServiceNow / Jira for IR follow-up

**Skill:** decomposing an IR runbook into discrete SOAR atomic actions — what's automatable vs what needs a human

---

## Capstone

### Q50 — End-to-end ES 8 design

Take **one detection idea** from anywhere in this self-practice pack (Sections 1–4), and produce its full ES 8 artifact set. Submit:

1. **Event-Based Detection** — full Q44-style table (Name, Description, SPL, MITRE annotation, throttling)
2. **A Finding-Based Detection** that consumes findings from (1) — Q46- or Q47-style table
3. **Response Plan** — which built-in plan you'd attach, or a custom one (Q41 style)
4. **SOAR Playbook** — 3–5 actions (Q49 style)
5. **One sentence: how would you measure that this end-to-end detection actually reduced mean-time-to-respond (MTTR)?**

**Deliverable:** ~1 page of structured Markdown. This is the artifact you'd hand to a Detection Engineering manager to ship.
**Skill:** thinking like a detection engineer, not just an analyst

---

🎓 **End of ES 8.3 workshop section.**

If you completed Q39–Q50, you've now walked the same path as the official ES 8.3 hands-on workshop *and* mapped every UI step onto concrete artifacts (SPL, design tables, playbook decomposition) that survive outside the ES UI.

**Next:**
- Sign up for [bots.splunk.com](https://bots.splunk.com) to try the exact ES 8 instance from the PDF for free
- Re-read the PDF's *Built-in Response Plans* slide and pick the two you've never used — design a sandbox incident around each
- Pair this section with [Section 4](04-enterprise-security.md): Section 4 teaches the *concepts* on Splunk Core; Section 5 teaches the *ES 8 product workflow* on top
