# Self-Practice: Splunk + SOC Tier 1 + Enterprise Security

A set of **67 hands-on exercises** for practicing SPL (Splunk Search Processing
Language), core SOC Tier 1 analyst skills, and the Splunk Enterprise Security
workflow, progressing from beginner to advanced. All exercises use the
**BOTS v1** dataset (the default loaded by `setup.sh`).

---

## Learning Objectives

After completing all 67 exercises, you should be able to:
- Write SPL to search, filter, aggregate, and visualize events fluently
- Read logs from the key security sourcetypes — Windows, Sysmon, Suricata IDS, DNS, web
- Answer SOC Tier 1 triage questions (Who? What? When? Where? How?)
- Build a basic attack timeline and identify Indicators of Compromise (IOCs)
- Draft a short incident-report summary from your search findings
- Pivot to the **Splunk Enterprise Security** workflow: CIM data models, correlation searches, notable events, Risk-Based Alerting (RBA), and asset/identity enrichment

---

## Structure

| File | Level | Items | Focus |
|---|---|---|---|
| [01-splunk-fundamentals.md](01-splunk-fundamentals.md) | Beginner | Q1–Q15 | SPL syntax: search, stats, top, table, eval, rex |
| [02-security-log-analysis.md](02-security-log-analysis.md) | Beginner–Intermediate | Q16–Q30 | Windows / Sysmon / Suricata / DNS / web log reading |
| [03-soc-tier1-investigations.md](03-soc-tier1-investigations.md) | Intermediate | Q31–Q50 | Brute force, web breach, ransomware, IOCs, timeline |
| [04-enterprise-security.md](04-enterprise-security.md) | Intermediate–Advanced | Q51–Q67 | **Part 1 (Q51–Q60):** CIM data models — discover, explore, query (`from datamodel:` / `tstats`), verify. **Part 2 (Q61–Q67):** correlation searches, notable events, RBA, asset & identity |
| [SOLUTIONS.md](SOLUTIONS.md) | — | — | Reference answers with SPL and explanations |

---

## Prerequisites

1. The lab is running — http://localhost:8000 reachable (admin / `p@ssw0rd`)
2. The **BOTS v1** dataset is loaded — quick check: `index=botsv1 | head 1` returns events
3. You know how to set the **time picker** in the Splunk Web UI
4. **Section 4 only:** install either the **Splunk Common Information Model** app (free, lightweight path) **or** the full **Splunk Enterprise Security** trial. See [04-enterprise-security.md](04-enterprise-security.md) for setup details.

---

## Time Range Guidance — IMPORTANT

The BOTS v1 dataset spans **August 10–26, 2016**, but real activity is
concentrated on **2 specific days**. Use the tightest window that still
contains the events you need — keep searches fast and focused on practice:

| Section / Questions | Recommended time picker | Why this window |
|---|---|---|
| **Section 1** (Q1–Q15) | `8/10/2016 00:00:00` → `8/11/2016 00:00:00` | Pure SPL practice — any 1-day window with rich data works |
| **Section 2: Q16–Q26** (Win logons, HTTP, DNS, Suricata, SQLi) | `8/10/2016 00:00:00` → `8/11/2016 00:00:00` | Web attack + brute force day — has 4625/4624 spike + Suricata alerts |
| **Section 2: Q27–Q30** (PowerShell, registry, network conns) | `8/24/2016 00:00:00` → `8/25/2016 00:00:00` | Ransomware day — Sysmon-rich activity |
| **Scenario A — Web defacement** (Q31–Q40) | `8/10/2016 00:00:00` → `8/12/2016 00:00:00` | Covers full attack chain |
| **Scenario B — Ransomware** (Q41–Q50) | `8/24/2016 00:00:00` → `8/25/2016 00:00:00` | The Cerber infection window |
| **Section 4 — CIM & ES workflow** (Q51–Q67) | Same as Scenarios A/B above (per question) | Re-uses Section 3's attack windows |

You can either set the time picker manually (Date Range → Between) or
inline it in SPL:

```spl
index=botsv1
  earliest="08/24/2016:00:00:00"
  latest="08/25/2016:00:00:00"
  ...
```

A 1-day window typically returns in **seconds** instead of minutes —
critical for iterating on SPL while learning.

If a search returns zero results, your time picker is probably wrong —
not your SPL. Switch the window and try again.

---

## How To Use This Pack

1. **Read the question, then try it yourself** in the Splunk Web UI before peeking at hints
2. **Give it 10–15 minutes** before reading the *Hint* below each question
3. **Open SOLUTIONS.md only as a last resort.** When you do, retype the SPL by hand — don't copy/paste
4. **Repeat the exercises in 2–3 days** without looking at solutions to lock the patterns in memory

---

## SPL Cheat Sheet (Read Before Q1)

```spl
index=<name>                          # choose the index to search
sourcetype=<name>                     # filter by sourcetype
| where <field>=<value>               # filter in the pipeline
| stats count by <field>              # count grouped by a field
| top <field>                         # most frequent values (default top 10)
| rare <field>                        # least frequent values
| table <f1> <f2> <f3>                # show as a table with selected columns
| sort - <field>                      # sort descending (use + for ascending)
| dedup <field>                       # drop duplicate values of <field>
| head 10                             # keep first 10 rows
| eval <new>=<expression>             # create a new field
| rex field=<f> "<regex>"             # extract a field with regex
| rename <old> AS <new>               # rename a field
| transaction <field>                 # group events into transactions
| timechart count by <field>          # time-series chart
```

**Time syntax (inline in SPL):**
```spl
earliest="08/24/2016:00:00:00"        # absolute, MM/DD/YYYY:HH:MM:SS
latest="08/25/2016:00:00:00"
earliest=-24h latest=now              # relative (not useful for BOTS data)
earliest=0                            # epoch 0 — equivalent to "All time"
```

---

## SOC Tier 1 Mindset

- **Start with 5W1H** — Who, What, When, Where, Why, How
- **Don't conclude from a single event** — look for corroborating evidence
- **Think in kill-chain terms** — Recon → Weaponize → Deliver → Exploit → Install → C2 → Actions on Objective
- **Record every IOC** as you go: IP, domain, hash, filename, user agent, registry key
- **Time matters** — always order events on a timeline before forming a story

---

## After this pack — Specialized tracks

Once you're fluent with these 67 exercises, move on to the **specialized BOTS v1
tracks** in [`../../specialized/botsv1/`](../../specialized/botsv1/). Those are
methodology-driven — instead of "find the one answer," each hands you a
hypothesis or a case and grades the *process*. **8 tracks**: Threat Hunting ·
DFIR · Network Forensics · Detection Engineering · Purple Team · Reporting ·
Threat-Intel, all tied together by a full-incident
[capstone](../../specialized/botsv1/04-capstone-full-incident.md).

> Rule of thumb: finish self-practice before specialized — you can't hunt if
> you're still fighting the syntax.

## Credits

These exercises are designed for use with the Splunk BOTS v1 dataset.
Official BOTS walkthroughs (full answers and deeper analysis) live in
[../splunk-bots/](../../splunk-bots/).
