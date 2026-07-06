# MD101 — Splunk Search Command Hands-On (BOTS Edition)

A set of SPL exercises adapted from the `MD101_For BOTS_Hands-On_Workshop.pdf`
deck. The exercises follow the same flow as the workshop —
Basic → Intermediate → Applied scenarios.

---

## Learning Objectives

After completing all questions, you should be able to:
- Write SPL fluently with the basic commands (`stats`, `tstats`, `metadata`, `timechart`, `top`, `rare`, `sort`, `reverse`, `table`, `dedup`, `iplocation`)
- Use `eval` (including `if` and `case`) to create and transform fields for analysis
- Use `rex` to extract values from raw logs with regular expressions
- Read events from the main BOTS workshop sourcetypes (`stream:http`, `XmlWinEventLog`, `mscs:azure:eventhub`, `o365`, `auditd`, etc.)
- Build short detection logic on your own — e.g. Suspicious PowerShell, Impossible Travel
- Pivot to the **Splunk Enterprise Security** workflow: CIM data models, correlation searches, notable events, Risk-Based Alerting (RBA), and asset/identity enrichment
- Walk through the **ES 8.3 analyst workflow**: Findings vs Finding Groups, Response Plans, Detection Versioning, Finding-Based Detections (Cumulative Risk, MITRE), and SOAR playbooks
- Design the integration surface of **Splunk Attack Analyzer (SAA)** with ES and SOAR — automated phishing/malware verdicts driving findings and playbooks

---

## Structure

| File | Level | Items | Focus | Solutions |
|---|---|---|---|---|
| [question/01-basic-spl-commands.md](question/01-basic-spl-commands.md) | Beginner | Q1–Q14 | One+ exercise per basic command | [→](answer/01-basic-spl-commands-solutions.md) |
| [question/02-intermediate-spl.md](question/02-intermediate-spl.md) | Intermediate | Q15–Q21 | `eval` (3 forms), `rex`, chaining commands | [→](answer/02-intermediate-spl-solutions.md) |
| [question/03-detection-scenarios.md](question/03-detection-scenarios.md) | Applied | Q22–Q28 | Suspicious PowerShell, Impossible Travel, IOC hunting | [→](answer/03-detection-scenarios-solutions.md) |
| [question/04-enterprise-security.md](question/04-enterprise-security.md) | Advanced | Q29–Q38 | CIM data models, correlation searches, notable events, RBA, asset & identity | [→](answer/04-enterprise-security-solutions.md) |
| [question/05-es8-workshop.md](question/05-es8-workshop.md) | Advanced | Q39–Q50 | ES 8.3 workshop walkthrough — Findings, Finding-Based Detections, Response Plans, Detection Versioning, SOAR | [→](answer/05-es8-workshop-solutions.md) |
| [question/06-attack-analyzer.md](question/06-attack-analyzer.md) | Advanced | Q51–Q60 | Splunk Attack Analyzer (SAA) — submission, verdict parsing, ES enrichment, SOAR playbooks | [→](answer/06-attack-analyzer-solutions.md) |

> 📖 **Solutions are intentionally separated by section** so you can grade yourself one section at a time without spoiling later ones.
> Sections 5–6 are largely **design-style** questions — the solutions show *representative* sample answers, not the only valid response.

> This pack ships **without an answer key on purpose** — try every question yourself first.
> If you are stuck past 15 minutes, use the cheat sheet below or open the
> official BOTS walkthroughs at [../splunk-bots/](../splunk-bots/).

---

## Prerequisites

1. The Splunk lab is running — `http://localhost:8000` is reachable (admin / `p@ssw0rd`)
2. The BOTS workshop dataset is loaded into the `botsv1` index (follow the *Add Data* steps in the MD101 PDF, pages 14–17)
3. You know how to set the **time picker** in the Splunk Web UI
4. **Section 4 only:** install either the **Splunk Common Information Model** app (free, lightweight path) **or** the full **Splunk Enterprise Security** trial. See [question/04-enterprise-security.md](question/04-enterprise-security.md) for setup details.

> 💡 If a search returns zero results, **check the time picker first**.
> The workshop dataset has a narrow active window — use **All time** or set
> explicit `earliest` / `latest` values that cover the data.

---

## Workshop Sourcetypes (from the *Guide for log sources* slide)

```
stream:ip
stream:http
sourcetype="auditd"
sourcetype="ms:o365:email"
sourcetype="o365"
sourcetype="slack:messages"
source=XmlWinEventLog
sourcetype="Script:InstalledApps"
sourcetype="mscs:azure:eventhub"
index=risk
```

---

## SPL Cheat Sheet (read before Q1)

```spl
# === Searching ===
index=<name> sourcetype=<name> [key=value ...]

# === Metadata / fast counting ===
| tstats count WHERE index=* sourcetype=* BY index sourcetype
| metadata type=hosts | sources | sourcetypes

# === Aggregation ===
| stats count by <field>                  # count per value
| stats dc(<field>) as unique             # distinct count
| stats sum/avg/max/min(<field>) by <f>   # numeric aggregations

# === Top-N / outliers ===
| top <field>                             # most frequent values (default 10)
| rare <field>                            # least frequent values

# === Ordering / shaping ===
| sort - <field>                          # descending (+ for ascending)
| reverse                                 # flip result order
| dedup <field>                           # drop duplicates
| table <f1> <f2> ...                     # pick columns to display

# === Time / location ===
| timechart count by <field>
| iplocation <ip_field>

# === Field manipulation ===
| eval new = <expr>
| eval bucket = if(<cond>, <a>, <b>)
| eval cat = case(<c1>, <v1>, <c2>, <v2>, true(), <default>)
| rex field=<f> "<regex>"
```

---

## How to use this pack

1. **Read the question, then try the SPL yourself** in the Splunk Web UI before peeking at the hint
2. Give every question 10–15 minutes before reading the *Hint*
3. Repeat the exercises 2–3 days later without hints — the goal is to make the patterns muscle-memory
4. When your output looks odd, ask yourself "could I get the same answer with a different command?" — alternative paths deepen the intuition

Happy hunting 🔍
