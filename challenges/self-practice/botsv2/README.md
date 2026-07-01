# BOTS v2 — Graduated Practice Pack

A dataset-scoped learning path on `index=botsv2`, designed to take you from
**SPL fluency** to **intensive specialized work**, the same way the v1 packs
do — but on a richer, more advanced incident.

> 📦 **Dataset: BOTS v2** (`./setup.sh --v2`). BOTS v2 is a larger, more
> APT-flavoured scenario than v1. **Exact incidents, sourcetypes, hosts, and
> answers are confirmed against the loaded data** before any exercise is
> written here — nothing is guessed.

---

## The path (beginner → intensive)

| Stage | File | Goal |
|---|---|---|
| **1. Fundamentals** | `01-fundamentals.md` | Get *fluent* with core SPL — `search`, `stats`, `top`/`rare`, `table`, `sort`, `dedup`, `timechart`. Speed and muscle memory first. |
| **2. Intermediate SPL** | `02-intermediate-spl.md` | `eval` (if/case), `rex`, `tstats`/`metadata`, chaining commands, subsearches. |
| **3. Log analysis** | `03-log-analysis.md` | Read every v2 sourcetype fluently (Windows, Sysmon, IDS, DNS, web, + whatever v2 adds). |
| **4. Intensive specialized** | [`../specialized/botsv2/`](../../specialized/botsv2/) | Threat Hunting · DFIR · Network Forensics · Detection Engineering · Purple Team · Reporting · Threat-Intel — continuous scenarios + capstone, same rigour as [`../specialized/botsv1/`](../../specialized/botsv1/). |

**Do them in order.** Query fluency (Stages 1–3) is the prerequisite for the
specialized work — you can't hunt if you're still fighting the syntax.

> Status: 🚧 **Being built.** Structure is fixed; exercises are populated with
> verified queries/answers as the dataset finishes loading. Check back per stage.

---

## Prerequisites
1. Lab running — `http://localhost:8000` (admin / `p@ssw0rd`)
2. BOTS v2 loaded — `index=botsv2 | head 1` returns events (`./setup.sh --v2`)
3. You know how to set the **time picker** (v2 has its own active window — set it, or a "no results" will fool you)

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
