# Solutions — Section 5 (Q39–Q50) — ES 8.3 Workshop

⚠️ **Last resort — try every problem honestly first.**

> Section 5 is mostly **design-style** rather than SPL-style. The "answers" below are **representative sample answers** — multiple valid responses exist. Compare your work against the *reasoning*, not the literal wording.

---

## Q39 — UI navigation cheat sheet

| Analyst question | ES 8 menu path |
|---|---|
| "Show me everything that fired in the last hour" | **Analyst Queue** (lists all open Findings + Finding Groups by time) |
| "Open the detection that produced this alert" | From a Finding card → click the rule name → **Content Management → Detections** |
| "Start a formal investigation on this Finding Group" | Right-click the Finding Group → **Triage to Investigation** → pick a Response Plan |
| "Compare the current detection to last week's version" | **Content Management → Detections → [detection] → Versions tab → Diff comparison** |
| "Run a SOAR playbook against this finding" | Open the Finding → **Run Playbook** button (top-right action menu) |

The mental model: **Analyst Queue** is daily home base; **Content Management** is where detection engineers live; **Investigations** is where active cases live.

---

## Q40 — Best-fit response plans

| Scenario | Best-fit plan | Why |
|---|---|---|
| `imreallynotbatman.com` brute force | **Account Compromise** | The brute-force *target* is an account on the web app; if successful, the next step is the compromised credentials |
| Cerber ransomware on `we8105desk` | **Self-Replicating Malware** | Cerber actively encrypts files and spreads across SMB shares — propagation is the threat model |
| User-reported phishing email | **Suspicious Email** | Plan literally exists for this; handles attachment + URL analysis flow |
| Critical CVE on a webapp dependency | **Vulnerability Disclosure** | Plan covers asset inventory, patching, public communication |
| Impossible Travel sign-in | **Account Compromise** | Same template as case 1 — the asset at risk is the identity, not the host |

If your environment doesn't fit one of the 8 built-in plans, **Generic Incident Response** or **NIST 800-61** are the safe fallbacks.

---

## Q41 — Custom Cerber response plan (sample)

| phase | task | owner | duration | soar_action |
|---|---|---|---|---|
| Detect | Confirm Cerber IOC on host (file extension `.cerber`, registry mods) | SOC T1 | 5 min | `osquery_query_iocs` |
| Detect | Pull list of files encrypted on host + shared drives | SOC T1 | 10 min | `enumerate_encrypted_files` |
| Detect | Verify Suricata ET TROJAN signature fired | SOC T1 | 2 min | (manual SPL search) |
| Contain | Isolate host via EDR network containment | SOC T2 | 5 min | `crowdstrike_contain_host` |
| Contain | Disable user account in AD | SOC T2 | 3 min | `ad_disable_user` |
| Contain | Block C2 domain at perimeter firewall | SOC T2 | 5 min | `palo_alto_block_url` |
| Eradicate | Remove Cerber payload + scheduled tasks | IR Lead | 30 min | `crowdstrike_quarantine_file` |
| Eradicate | Re-image host from gold image | IR Lead | 90 min | (manual) |
| Eradicate | Reset user credentials + force password change | IR Lead | 15 min | `ad_reset_password` |
| Recover | Restore encrypted files from last clean backup | IR Lead | 2 hr | (manual / backup tool) |
| Recover | Re-enable account once endpoint is clean | SOC T2 | 5 min | `ad_enable_user` |
| Recover | Validate host activity returns to baseline | SOC T2 | 24 hr | (monitor) |

---

## Q42 — Finding lifecycle

| State | Owner | Transition trigger | Artifacts collected |
|---|---|---|---|
| **New** | Auto-assigned to queue | Finding emitted by detection | Detection rule ID, fired time, raw events |
| **In Progress** | Tier 1 analyst | Analyst claims via "Assign to me" | Triage notes, screenshots, initial verdict |
| **Pending** | Tier 1, blocked | Waiting on external info (IT, user, vendor) | "Waiting on…" tag, escalation note |
| **Resolved** | Tier 1 / Tier 2 | Verdict + remediation actions complete | Final verdict, IOCs added to threat intel, playbook run logs |
| **Closed** | Auto (after 7 days) | Resolved + cool-down expired | Locked artifacts — read-only audit record |

---

## Q43 — Event-Based vs Finding-Based

| # | Detection | E or F | Why |
|---|---|---|---|
| 1 | Single failed login from new geolocation | **E** | Direct from raw auth events — one event = one finding |
| 2 | User cumulative risk > 100 in 24h across ≥ 2 detections | **F** | Aggregates existing findings — perfect Cumulative Entity Risk fit |
| 3 | Suricata ET TROJAN Cerber alert | **E** | Direct from IDS event — no grouping needed |
| 4 | ≥ 3 MITRE tactics on same host in 1h | **F** | Groups findings by MITRE annotation — MITRE-type Finding-Based |
| 5 | `cscript.exe` spawning `.tmp` payload | **E** | Direct from process-create event |
| 6 | ≥ 10 similar findings against same source IP in 1h | **F** | Similar-Findings Finding-Based — group identical signals |

**Rule of thumb:** if the input is `index=` (raw events), it's Event-Based. If the input is *other findings*, it's Finding-Based.

---

## Q44 — Event-Based Detection artifact for Cerber

| Field | Value |
|---|---|
| **Name** | Cerber Ransomware — `cscript.exe` spawning `<6digits>.tmp` |
| **Description** | Detects the Cerber dropper pattern where `cscript.exe` (typically launched from a malicious Office macro or drive-by JS) writes and executes a 6-digit `.tmp` payload. Observed during the BOTS v1 8/24/2016 incident. |
| **Detection SPL** | `source=XmlWinEventLog EventCode=4688 ParentProcessName="*cscript.exe" NewProcessName="*.tmp"`<br>`\| rex field=NewProcessName "\\\\(?<file_name>\d{6}\.tmp)$"`<br>`\| where isnotnull(file_name)`<br>`\| rename Computer as dest, Account_Name as user, NewProcessName as process, ParentProcessName as parent_process`<br>`\| table _time dest user process parent_process file_name` |
| **MITRE annotation** | Tactic `TA0002 Execution` / Technique `T1059.005 Command and Scripting Interpreter: Visual Basic` |
| **Throttling** | Window `1h`, key `dest,file_name` (don't re-fire for the same payload on the same host) |

---

## Q45 — Versioning workflow

1. **Diff comparison color legend** (from the PDF):
   - **Dark green** = newly added text in v2 (the exclusion clauses you added)
   - **Dark red** = deleted text from v1 (likely nothing in this case if you only *appended* exclusions)
   - **Light green / light red** = modified text (e.g. an existing line you reformatted)

2. **When to rollback v1**:
   - You added the exclusion `user IN ("administrator", "SYSTEM")` and overnight a real attacker used a compromised SYSTEM account — your v2 silently missed it. v1 caught it.
   - The exclusion list excluded a **service account naming pattern** that an attacker can trivially mimic (e.g. `svc_*`). Now any attacker who renames their malware `svc_anything` evades detection.

3. **Why "who" matters most in audit**: regulators and IR reviewers ask "*who* loosened the detection?" not "what was loosened" — accountability for detection coverage is a named-person responsibility. Compliance frameworks (PCI, HIPAA, SOC 2) require a documented change-author trail; ES's versioning provides this.

---

## Q46 — Cumulative Entity Risk Finding-Based Detection

| Field | Value |
|---|---|
| **Name** | Cumulative risk threshold breach |
| **Description** | Fires when any single entity (host or user) accumulates risk score ≥ 80 within a 24h window across any combination of detections. |
| **Grouping mechanism** | Cumulative Entity Risk |
| **Risk score threshold** | 80 |
| **Time range** | 24h |
| **Entity field(s)** | `risk_object` (any of system/user types) |
| **Finding Group title** | `$risk_object$ – cumulative risk $total_risk$ (over threshold)` |
| **Preview SPL** | `\| tstats summariesonly=t sum(All_Risk.calculated_risk_score) as total_risk, dc(All_Risk.source) as distinct_rules, values(All_Risk.source) as rules FROM datamodel=Risk WHERE earliest=-24h BY All_Risk.risk_object, All_Risk.risk_object_type \| where total_risk >= 80` |

---

## Q47 — MITRE ATT&CK Finding-Based Detection

| Field | Value |
|---|---|
| **Grouping mechanism** | MITRE ATT&CK |
| **Pivot field** | `tactic` (not `technique` — tactics give breadth, techniques can be noisy) |
| **Threshold** | ≥ 3 distinct tactics |
| **Time range** | 6h |
| **Entity field** | `dest` (the host; for identity-driven attacks swap to `user`) |
| **Preview SPL** | `\| tstats summariesonly=t dc(All_Risk.annotations.mitre_attack.mitre_tactic) as tactic_count, values(All_Risk.annotations.mitre_attack.mitre_tactic) as tactics, values(All_Risk.source) as rules FROM datamodel=Risk WHERE earliest=-6h BY All_Risk.risk_object \| where tactic_count >= 3` |

**Intuition:** *Defense Evasion* alone is noisy (every legitimate AV signature triggers some EDR ML model these days). But **Execution + Persistence + Defense Evasion** on the same host in 6 hours is an attack chain you can't ignore.

---

## Q48 — Dashboard picker

| Analyst question | Dashboard |
|---|---|
| "How healthy is our SOC pipeline right now?" | **Security Posture** (top-level KPIs) |
| "Which users are accumulating the most risk this week?" | **Risk Analysis** |
| "Which detections are firing the most — and could they be tuned?" | **Detection Analytics / Use Case Library** (volume + signal-to-noise per detection) |
| "Did anything trigger on assets owned by marketing?" | **Asset Investigator** (pivot by `business_unit` / `criticality`) |
| "Coverage map of detections against MITRE ATT&CK" | **Security Content** (ATT&CK matrix dashboard) |

---

## Q49 — Cerber SOAR playbook

| Step | Action | Target | Connector | Mode |
|---|---|---|---|---|
| 1 | `domain_lookup` | `solidaritedeproximite.org` | VirusTotal | auto |
| 2 | `isolate_endpoint` | host `we8105desk` | CrowdStrike | analyst approval |
| 3 | `disable_user` | `bob.smith` | Active Directory | analyst approval |
| 4 | `block_url` | `cerberhhyed5frqa.xmfir0.win` | Palo Alto firewall | auto |
| 5 | `create_ticket` | the incident | ServiceNow | auto |

**Approval rule of thumb:** automatic enrichment + blocking domains → auto. Anything that **impacts users** (disable account, isolate endpoint) → analyst approval. Auto-isolating wrong host = SOC pager going off at 3am.

---

## Q50 — Capstone (sample structure)

Below is a *sample* end-to-end design taking Q44's Cerber detection through the full ES 8 lifecycle. Your answer should follow the same shape with whatever detection idea you picked.

### 1. Event-Based Detection
*(same as Q44 — Cerber `cscript.exe` → `.tmp` artifact)*

### 2. Finding-Based Detection consuming (1)
| Field | Value |
|---|---|
| **Name** | Cerber chain — script-execution risk on endpoint |
| **Grouping** | Cumulative Entity Risk |
| **Threshold** | 60 in 4h |
| **Entity** | `dest` (host) |
| **Reason** | Combines the Q44 detection (risk 40) with any Suricata ET TROJAN finding (risk 60) → 100 cumulative → fires |

### 3. Response Plan
**Self-Replicating Malware** (built-in, see Q40 row 2).

### 4. SOAR Playbook
Same as Q49.

### 5. MTTR measurement
> "Compare mean time-to-respond (Finding emitted → Finding closed) for incidents matching this detection family, measured monthly, before vs after enabling the playbook auto-actions. Target: 50% MTTR reduction on the auto-isolate path within 60 days. Track via the *Detection Analytics* dashboard's `mean_response_time` per `source_rule` metric."

---

✅ End Section 5 solutions
