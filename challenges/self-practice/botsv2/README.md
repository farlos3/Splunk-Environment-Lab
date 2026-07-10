# BOTS v2 — Graduated Practice Pack

A dataset-scoped learning path on `index=botsv2`, designed to take you from
**SPL fluency** to **intensive specialized work**, the same way the v1 packs
do — but on a richer, more advanced incident.

> 📦 **Dataset: BOTS v2** (`./setup.sh --v2`) — the *froth.ly* brewery, an APT
> scenario. Verified on load: **226M+ events · 104 sourcetypes · 23 hosts ·
> all of August 2017**. Much richer than v1: Windows **+ Linux** + **MySQL** +
> Apache web + **Palo Alto** firewall + Symantec EP + osquery. All exercises
> are confirmed against the loaded data — nothing is guessed.

---

## The path (beginner → intensive)

| Stage | File | Goal |
|---|---|---|
| **1. Fundamentals** (Q1–20) | [01-fundamentals.md](01-fundamentals.md) | Get *fluent* with core SPL — `search`, `stats`, `top`/`rare`, `table`, `sort`, `dedup`, `timechart`. Speed and muscle memory first. |
| **2. Intermediate SPL** (Q21–40) | [02-intermediate-spl.md](02-intermediate-spl.md) | `eval` (if/case/strftime/match), `rex`, `tstats`/`metadata`, `streamstats`, chaining, subsearches. |
| **3. Log analysis** (Q41–60) | [03-log-analysis.md](03-log-analysis.md) | Read every v2 sourcetype fluently (Windows, Sysmon, Linux, MySQL, web, IDS, Palo Alto, SMTP, FTP, Symantec, osquery) — incl. which need `rex`. |
| **4. Intensive specialized** | [`../../specialized/botsv2/`](../../specialized/botsv2/) | Threat Hunting · DFIR · Network Forensics · Detection Engineering · Purple Team · Reporting · Threat-Intel — continuous scenarios + capstone (8 tracks), same rigour as [`botsv1`](../../specialized/botsv1/). |

**Do them in order.** Query fluency (Stages 1–3) is the prerequisite for the
specialized work — you can't hunt if you're still fighting the syntax.

> **Stages 1–3: 60 exercises (Q1–Q60)** — every answer verified against the
> loaded `index=botsv2`. Stage 4 (specialized tracks) lives in
> [`../../specialized/botsv2/`](../../specialized/botsv2/).

---

## Prerequisites
1. Lab running — `http://localhost:8000` (admin / `p@ssw0rd`)
2. BOTS v2 loaded — `index=botsv2 | head 1` returns events (`./setup.sh --v2`)
3. You know how to set the **time picker** (v2 has its own active window — set it, or a "no results" will fool you)

---

## Time picker — IMPORTANT

v2 spans **all of August 2017** (`08/01/2017` → `08/31/2017`), but real activity
is concentrated. Set the window to match what you're searching — a wrong picker
returns *zero results*, not an error. For counting/discovery use
`tstats`/`metadata` (no window needed).

| What you're searching | Time picker (set "Between" in the UI) |
|---|---|
| Frothly web server (`access_combined`) | `08/23/2017 00:00:00` → `08/24/2017 00:00:00` |
| brewertalk.com scan + SQLi (`stream:http`, Q40) | `08/11/2017 00:00:00` → `08/17/2017 00:00:00` |
| Windows endpoint / Sysmon (4688, EID 1, Empire exec) | `08/24/2017 00:00:00` → `08/25/2017 00:00:00` |
| APT artifacts (C2, phishing, FTP drop, registry, osquery) | `08/15/2017 00:00:00` → `08/26/2017 00:00:00` |
| Counting / discovery (`tstats`, `metadata`) | any / All time — it's fast |

Inline in SPL, the same window uses a **colon** between date and time:
```spl
… earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
```

> ⚠️ Always scope raw searches to a day — a bare `index=botsv2` over All time
> scans 226M events and can OOM the lab.

---

## SPL cheat sheet (read before Stage 1)

```spl
# Searching
index=botsv2 sourcetype=<name> [key=value ...]

# Fast counting / discovery
| tstats count where index=botsv2 by sourcetype
| metadata type=sourcetypes | hosts | sources

# Aggregation
| stats count by <field>
| stats dc(<field>) as unique
| stats sum/avg/max/min(<field>) by <field>

# Top-N / outliers
| top <field>          | rare <field>

# Shaping
| sort - <field>       | dedup <field>       | table <f1> <f2> ...
| eval new = <expr>    | eval x = if(<c>,<a>,<b>)   | eval y = case(...)
| rex field=<f> "<regex>"
| timechart span=1h count by <field>
| iplocation <ip_field>
```

**Time (inline):** `earliest="MM/DD/YYYY:HH:MM:SS" latest=...` · `earliest=0` = All time.

---

## How to use
1. Try each question yourself before peeking at the solution.
2. Give it 10–15 minutes; retype SPL by hand rather than copy/paste.
3. Repeat a stage 2–3 days later without solutions — fluency is the goal.
4. Only move to the specialized tracks once Stages 1–3 feel automatic.
