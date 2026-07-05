# BOTS v2 — Stage 1: SPL Fundamentals (Query Fluency)

Goal: get **fast and fluent** with core SPL on a big, messy, real dataset.
Fluency first — speed, muscle memory, and knowing which command to reach
for. The incident hunting comes later (Stages 2–4); here you just learn to
*move* through `index=botsv2`.

**About this dataset (verified):** 226M+ events · **104 sourcetypes** ·
**23 hosts** · spans **all of August 2017**. It's the *froth.ly* brewery
environment — Windows + Linux + MySQL + web + Palo Alto firewall.

> ⚠️ **v2 is huge — always scope your time window.** A bare `index=botsv2`
> over "All time" scans 226M events and will crawl (or OOM the lab). Habits:
> use `| tstats …` for counting, `| metadata …` for discovery, and add
> `earliest=`/`latest=` (a single day) on raw searches. If a search hangs,
> you forgot to scope it.

⏱ **Time picker — Stage 1**

| Questions | Time picker |
|---|---|
| Q1–Q6, Q16–Q17 (discovery) | none needed — use `tstats` / `metadata` |
| Q7–Q20 (web) | `08/23/2017 00:00:00` → `08/24/2017 00:00:00` |

> **Hints are nudges, not answers** — they name the approach and the commands
> to reach for. Try to write the SPL yourself; the full query + verified result
> is in [SOLUTIONS.md](SOLUTIONS.md) (Stage 1), for a last resort.

---

### Q1 — What sourcetypes exist, and which are biggest?
Use the *fast* path (metadata/tstats), not a raw search.
**Hint:** `tstats` counts straight from the index without scanning raw events. Aggregate `count` by `sourcetype`, then `sort` descending.

### Q2 — How many total events are in the index?
**Hint:** `tstats count` with no `by` clause returns the grand total instantly. (Picture the raw `| stats count` alternative — then don't run it; it would scan all 226M events.)

### Q3 — How many *distinct* sourcetypes and hosts?
**Hint:** One `tstats` can carry two distinct-counts at once — `dc(sourcetype)` and `dc(host)`.

### Q4 — What is the dataset's time span?
**Hint:** `tstats min(_time)` and `max(_time)`; those come back as epoch numbers, so wrap each in `strftime(…,"%F %T")` to read them.

### Q5 — List the hosts, busiest first.
**Hint:** `tstats count by host`, `sort` descending. Read the naming as you go: `wrk-*` = workstations, single words (`cassiopeia`, `venus`) = servers, and two Macs stand out.

### Q6 — Which sourcetypes does one host emit?
Pick a workstation, e.g. `wrk-ghoppy`.
**Hint:** Same shape as Q1 (`tstats count by sourcetype`) but add a `host=` filter for the one workstation.

### Q7 — Top client IPs hitting the web server (one day).
Scope to a single day and use `top`.
**Hint:** Set the day window, then `top clientip` on `sourcetype=access_combined`. `top` gives you the ranked list + percentages for free.

### Q8 — Break down web requests by HTTP status and method.
**Hint:** `stats count by status method` on the day's web logs, then `sort` descending. Which statuses dominate? Any `4xx`/`5xx` spikes?

### Q9 — Chart events per day for one noisy sourcetype.
**Hint:** `timechart span=1d count` on `sourcetype=suricata`. (~2M events — still set a window if it drags.)

### Q10 — Which host has the most Sysmon process-creation events?
**Hint:** `tstats count by host`, filtered to the Sysmon sourcetype (`*ysmon*`). (Sysmon field extraction is supplied by the lab add-on, like v1.)

### Q11 — Show 10 raw web events as a clean table.
**Hint:** `table` only the columns you care about (`_time`, `clientip`, `method`, `uri`, `status`), then `head 10`.

### Q12 — Unique URIs requested on the web server (one day).
**Hint:** `dc(uri)` gives the count; `stats count by uri | sort` shows the popular ones; `dedup uri` lists them. Pick the one that answers what you're asking.

### Q13 — Sort & limit: the 5 rarest User-Agents.
**Hint:** `stats count by useragent`, then `sort` *ascending* (`sort count`, no `-`) and `head 5`. Rare UAs are where recon tools hide.

### Q14 — `eval`: bucket requests into success vs. error.
**Hint:** `eval` a new field using `if(status>=400,"error","ok")`, then `stats count by` it. Once that clicks, redo it with `case()` for 2xx/3xx/4xx/5xx buckets.

### Q15 — `rex`: pull a field out of a raw string.
Extract the top-level path segment from the URI.
**Hint:** `rex field=uri` with a named capture group for the first `/segment`, then `top` it. `rex` is the one regex you must own — everything else is optional.

### Q16 — `rare` / ascending sort: the least-common sourcetypes.
**Hint:** Same as Q1, but `sort` *ascending* and `head 5`. The 1-event sourcetypes (`stream:irc`, `symantec:ep:security:file`, …) are often the *interesting* ones — the opposite instinct from "biggest first."

### Q17 — Scope a count to one host, one day.
**Hint:** `tstats count` with a `host=cassiopeia` filter and a one-day window. Notice just how many events one host emits in a single day — that's why you scope.

### Q18 — Several aggregates in one `stats`.
On the web logs (one day) get count + average/max/min response size together.
**Hint:** One `stats` can hold many functions side by side — `count`, `avg(bytes)`, `max(bytes)`, `min(bytes)`.

### Q19 — Distinct count (`dc`).
How many *unique* client IPs hit the web server that day?
**Hint:** `dc(clientip)` is your "how many *different*?" tool (a small, countable set here).

### Q20 — `timechart` split by a field.
Chart web requests per hour, split by HTTP status.
**Hint:** `timechart span=1h count by status` gives one line per status value — watch the `4xx` line for scanning spikes. Gate on `status=*` first, or the field-less rows skew it (see Stage 2).

---

**When Stage 1 feels automatic** (you reach for `tstats`/`metadata` without
thinking, and you *always* scope time), move to `02-intermediate-spl.md`.

➡️ [SOLUTIONS.md](SOLUTIONS.md)
