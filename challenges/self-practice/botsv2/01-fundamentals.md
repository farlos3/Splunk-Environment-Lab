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

> Solutions: [SOLUTIONS.md](SOLUTIONS.md) (Stage 1 section).

---

### Q1 — What sourcetypes exist, and which are biggest?
Use the *fast* path (metadata/tstats), not a raw search.
**Hint:** `| tstats count where index=botsv2 by sourcetype | sort - count`.

### Q2 — How many total events are in the index?
**Hint:** `| tstats count where index=botsv2`. Compare the speed vs. `index=botsv2 | stats count` (don't actually wait for the slow one).

### Q3 — How many *distinct* sourcetypes and hosts?
**Hint:** `| tstats dc(sourcetype) dc(host) where index=botsv2`.

### Q4 — What is the dataset's time span?
**Hint:** `| tstats min(_time) as first max(_time) as last where index=botsv2 | eval first=strftime(first,"%F %T"), last=strftime(last,"%F %T")`.

### Q5 — List the hosts, busiest first.
**Hint:** `| tstats count where index=botsv2 by host | sort - count`. Notice the naming: `wrk-*` = workstations, single words (`cassiopeia`, `venus`) = servers, `maclory-air13` = a Mac.

### Q6 — Which sourcetypes does one host emit?
Pick a workstation, e.g. `wrk-ghoppy`.
**Hint:** `| tstats count where index=botsv2 host=wrk-ghoppy by sourcetype | sort - count`.

### Q7 — Top client IPs hitting the web server (one day).
Scope to a single day and use `top`.
**Hint:** `index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00" | top limit=10 clientip`.

### Q8 — Break down web requests by HTTP status and method.
**Hint:** `… sourcetype=access_combined earliest=… latest=… | stats count by status method | sort - count`. Which statuses dominate? Any `4xx`/`5xx` spikes?

### Q9 — Chart events per day for one noisy sourcetype.
**Hint:** `index=botsv2 sourcetype=suricata | timechart span=1d count`. (Suricata is ~2M events — still set a window if it drags.)

### Q10 — Which host has the most Sysmon process-creation events?
**Hint:** `| tstats count where index=botsv2 sourcetype=*ysmon* by host | sort - count`. (Sysmon field extraction is supplied by the lab add-on, like v1.)

### Q11 — Show 10 raw web events as a clean table.
**Hint:** `… sourcetype=access_combined earliest=… latest=… | table _time clientip method uri status | head 10`.

### Q12 — Unique URIs requested on the web server (one day).
**Hint:** `… sourcetype=access_combined earliest=… latest=… | stats dc(uri) as unique_uris` then `| stats count by uri | sort - count` to see the popular ones. Or `| dedup uri | table uri`.

### Q13 — Sort & limit: the 5 rarest User-Agents.
**Hint:** `… sourcetype=access_combined earliest=… latest=… | stats count by useragent | sort count | head 5`. Rare UAs are where recon tools hide.

### Q14 — `eval`: bucket requests into success vs. error.
**Hint:** `… | eval class=if(status>=400,"error","ok") | stats count by class`. Then try `case()` for 2xx/3xx/4xx/5xx buckets.

### Q15 — `rex`: pull a field out of a raw string.
Extract the top-level path segment from the URI.
**Hint:** `… | rex field=uri "^/(?<section>[^/?]+)" | top section`. `rex` is the one regex you must own — everything else is optional.

---

**When Stage 1 feels automatic** (you reach for `tstats`/`metadata` without
thinking, and you *always* scope time), move to `02-intermediate-spl.md`.

➡️ [SOLUTIONS.md](SOLUTIONS.md)
