# BOTS v2 — Solutions

Reference answers, verified against the loaded `index=botsv2`. Fundamentals
are about *fluency*, so for many the "answer" is the query + the shape of the
result, not a single magic number.

> **Time picker.** v2 spans **all of August 2017** (`08/01/2017` → `08/31/2017`),
> but the activity is concentrated. Set the window to match what you're
> searching — a wrong picker returns *zero results* and fools you. For counting
> or discovery use `tstats`/`metadata` (no window needed — reads the index, not raw events).
>
> | What you're searching | Time picker (set "Between" in the UI) |
> |---|---|
> | Frothly web server (`access_combined`) | `08/23/2017 00:00:00` → `08/24/2017 00:00:00` |
> | brewertalk.com scan + SQLi (`stream:http`, Q40) | `08/11/2017 00:00:00` → `08/17/2017 00:00:00` |
> | Windows endpoint / Sysmon (4688, EID 1, Empire exec) | `08/24/2017 00:00:00` → `08/25/2017 00:00:00` |
> | APT artifacts (C2, phishing, FTP drop, registry, osquery) | `08/15/2017 00:00:00` → `08/26/2017 00:00:00` |
> | Counting / discovery (`tstats`, `metadata`) | any / All time — it's fast |
>
> Inline equivalent in SPL uses a colon between date and time:
> `earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"`.

---

## Stage 1 — Fundamentals

### Q1 Sourcetypes
```spl
| tstats count where index=botsv2 by sourcetype | sort - count
```
Biggest are `winregistry` (~55M), `perfmon:process` (~49M), `mysql:server:stats` (~27M), `collectd`, then security-relevant ones: `suricata`, `xmlwineventlog:…sysmon…`, `stream:*`, `pan:traffic` (Palo Alto), `access_combined` (Apache web), `wineventlog:security`, `symantec:ep:*`, `linux_secure`/`auditd`/`osquery_results`.

### Q2 Total events
```spl
| tstats count where index=botsv2
```
**226,337,681** events. (`tstats` returns instantly; a raw `… | stats count` would scan every event — don't.)

### Q3 Distinct sourcetypes / hosts
```spl
| tstats dc(sourcetype) as sourcetypes dc(host) as hosts where index=botsv2
```
**104 sourcetypes, 23 hosts.**

### Q4 Time span
```spl
| tstats min(_time) as first max(_time) as last where index=botsv2
| eval first=strftime(first,"%F %T"), last=strftime(last,"%F %T")
```
`%F` and `%T` are shorthand format codes: `%F` = `%Y-%m-%d` (e.g. `2017-08-23`), `%T` = `%H:%M:%S` (e.g. `14:30:00`) — `"%F %T"` together give the full `2017-08-23 14:30:00` style timestamp in fewer characters than spelling out `"%Y-%m-%d %H:%M:%S"`.
**2017-08-01 00:00 → 2017-08-31 23:59** (a full month).

### Q5 Hosts
```spl
| tstats count where index=botsv2 by host | sort - count
```
23 hosts. Busiest: `cassiopeia` (~63M), `maclory-air13`, then workstations `wrk-btun`, `wrk-ghoppy`, `wrk-aturing`, `wrk-klagerf`, `wrk-abungst`, `wrk-fmaltes`, `wrk-bgist`; servers `mercury`, `venus`, `jupiter`, `gacrux`, `growler`, `jabbah`, `eridanus`, `matar`, `uranus`, `altair`. Naming: `wrk-*` = user workstations, single-word = servers, `maclory-air13` = a MacBook.

### Q6 One host's sourcetypes
```spl
| tstats count where index=botsv2 host=wrk-ghoppy by sourcetype | sort - count
```
A workstation emits Sysmon, winregistry, wineventlog, perfmon, stream:*, etc. — the endpoint telemetry stack.

### Q7 Web top clients (1 day)
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| top limit=10 clientip
```
On 08/23, top talkers include `4.14.104.185`, `98.116.39.236`, `68.99.6.195`, … (mix of visitors — which ones are malicious is a Stage-4 hunt, not here).

### Q8 Status / method breakdown
```spl
index=botsv2 sourcetype=access_combined
  earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| stats count by status method
| sort - count
```
Verified result (08/23/2017):

| status | method | count |
|---|---|---|
| 200 | GET | 10,480 |
| 200 | POST | 879 |
| 403 | GET | 344 |
| 304 | GET | 327 |
| 404 | GET | 231 |
| 302 | GET | 30 |

Mostly normal `200 GET`, with a small tail of `403`/`404` (probing) and a few `POST`s (logins/form posts). The six rows sum to **12,291**.

⚠️ **Verified gotcha — `stats count by status` silently drops field-less rows.** `status` is extracted on only a *subset* of `access_combined`, so the table above is **not** the full day's traffic. Always sanity-check how many events lack the field:
```spl
index=botsv2 sourcetype=access_combined
  earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| stats count(status) as have count as total
| eval missing = total - have
```
Result: `have = 12,291`, `total = 54,033`, `missing = 41,742`. So **41,742 events — 77% of that day — have no `status`** and never appear in the breakdown; `12,291` (the table's sum) is all `stats count by status` ever saw. When a field drives a metric, gate on `status=*` or count the nulls first. (Stage 2 Q37 quantifies the same trap, and Q22's `case()`/`true()` catch-all is where it bites hardest.)

### Q9 Events per day
```spl
index=botsv2 sourcetype=suricata | timechart span=1d count
```
Verified noisiest IDS days: **08-19 (192,762)**, 08-26 (136,050), 08-24 (92,290), 08-18, 08-25. Note the attack-relevant activity spans **more than just 08-24** — a good reminder to widen your window when hunting an APT (much of the volume is the port-135 scan, but the spread of busy days is the point).

### Q10 Sysmon by host
```spl
| tstats count where index=botsv2 sourcetype=*ysmon* by host | sort - count
```
Returns the workstations with Sysmon coverage (the `wrk-*` hosts + the Mac). Sysmon fields (`EventCode`, `Image`, …) come from the lab add-on.

### Q11 — Raw web table
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| table _time clientip method uri status
| head 10
```
Verified first row: `196.52.39.2  GET  /images/smilies/sad.png  200` — a forum smiley image, part of the brewertalk.com traffic.

### Q12 — Unique URIs
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| stats dc(uri) as unique_uris
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| stats count by uri
| sort - count      /* popular URIs */
```
Verified 08/23: **219** unique URIs. Most popular: `/forumdisplay.php?fid=5` (390), `/` (352), `/xmlhttp.php?action=validate_captcha` (301), `/index.php` (287), `/favicon.ico` (231) — a phpBB-style forum's normal navigation pages.

### Q13 — Rarest User-Agents
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| stats count by useragent
| sort count
| head 5
```
Odd/automation UAs (scanners, scripts) surface at the bottom of the frequency list.

### Q14 — eval bucketing
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| eval class=if(status>=400,"error","ok")
| stats count by class
```
2-bucket version. For 2xx/3xx/4xx/5xx, swap the `eval` line for `case()`:
```spl
| eval class=case(status<300,"2xx",status<400,"3xx",status<500,"4xx",true(),"5xx")
| stats count by class
```
(Same `true()`-catch-all trap as Q22 — see that entry before you trust the 5xx count.)

### Q15 — rex path segment
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| rex field=uri "^/(?<section>[^/?]+)"
| top section
```
Extracts the first path segment (e.g. `product`, `cart`, `joomla`…) so you can profile what parts of the site are hit.

### Q16 Rarest sourcetypes
```spl
| tstats count where index=botsv2 by sourcetype | sort count | head 5
```
`sort count` (ascending) surfaces the 1-event sourcetypes: `stream:irc`, `symantec:ep:behavior:file`, `symantec:ep:security:file`, `unix:update`, `unix:uptime`. Rarity ≠ irrelevance — `symantec:ep:security:file` (1 event) is the single Host-Integrity alert.

### Q17 Scope to one host / one day
```spl
| tstats count where index=botsv2 host=cassiopeia earliest="08/24/2017:00:00:00" latest="08/25/2017:00:00:00"
```
**2,550,943** events — `cassiopeia` (the MySQL DB) in a *single day*. Proof of why a raw `index=botsv2` over All-time is a mistake.

### Q18 Multiple aggregates in one stats
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| stats count avg(bytes) max(bytes) min(bytes)
```
08/23: count **54,033**, avg ≈ **12,910** bytes, max **183,314**, min **6**. One `stats` carries many functions.

### Q19 Distinct clients
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| stats dc(clientip) as clients
```
**34** unique client IPs on 08/23 — small enough to eyeball each later.

### Q20 timechart split by status
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00" status=*
| timechart span=1h count by status
```
One column per status (200/302/304/403/404). The `4xx` line rises during scanning windows. `status=*` matters — ~41,742 field-less rows that day would otherwise distort the chart (see Q37).

---

## Stage 2 — Intermediate SPL

> These are technique exercises — the *query* is the answer. Specific numbers depend on your time window; run them with the lab up to see values.

### Q21 — Calculated field
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| eval kb=round(bytes/1024,1)
| sort - kb
| table _time clientip uri kb
```

### Q22 `case()` status classes — and a real trap
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| eval class=case(status<300,"2xx",status<400,"3xx",status<500,"4xx",true(),"5xx")
| stats count by class
```
Naive result: `2xx 11359 · 3xx 357 · 4xx 575 · 5xx 41742`. ⚠️ **That 5xx is a lie.** Verified: those 41,742 rows have **NULL `status`** (see Q8) — the `true()` catch-all swept every field-less event into "5xx". Real 5xx ≈ 0.
**Fix — filter to rows that actually have the field, and make the catch-all honest:**
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00" status=*
| eval class=case(status<300,"2xx",status<400,"3xx",status<500,"4xx",status<600,"5xx",true(),"other")
| stats count by class
```
Lesson: a `true()` branch silently absorbs nulls/unexpected values. Gate on `status=*` (or add an explicit `null`/`other` bucket) when the value drives a metric — same discipline as choosing `case()` over a blind `if()` else.

### Q23 — Conditional counting
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00" status=*
| stats count as total count(eval(status>=400)) as errors by clientip
| eval err_rate=round(errors/total*100,2)
| sort - err_rate
```
`count(eval(<cond>))` counts only rows matching the condition — one pass, no subsearch. The `2` in `round(...,2)` is the decimal-places argument — it rounds `err_rate` to 2 digits after the decimal point (e.g. `22.834...` → `22.83`), not a filter or threshold. Verified top error-rate clients on 08/23: `204.194.143.30` (22.83%), `71.39.18.121` (22.69%), `107.3.17.56` (20.31%). (Add `status=*` so null-status rows don't skew `total`.)

### Q24 — String functions
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| eval ua=lower(useragent)
| stats count by ua
```
`lower()` normalizes so `Mozilla` and `mozilla` group together; also useful: `len()`, `substr()`, `mvindex()`, `split()`.

### Q25 — Named groups from URI
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| rex field=uri "^/(?<section>[^/?]+)"
| rex field=uri "[?&]id=(?<id>[^&]+)"
| table uri section id
```
Verified rows with `id` populated: `/usercp.php?action=editlists` → `section=usercp.php`, `id=1`; `/xmlhttp.php?action=edit_post&do=get_post&pid=6&id=pid_6` → `section=xmlhttp.php`, `id=pid_6`. Most rows have `section` but no `id` (only URIs with an `id=` query param get one) — a reminder that `rex` leaves the field null, not absent, when a pattern doesn't match.

### Q26 — exe from Sysmon Image
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 earliest="08/24/2017:00:00:00" latest="08/25/2017:00:00:00"
| rex field=Image "\\\\(?<exe>[^\\\\]+)$"
| top exe
```
Windows path separators are `\`, which must be escaped (`\\\\` in the SPL string → `\\` regex → literal `\`).

⚠️ **Verified — the top result is Splunk's own agent, not attacker activity.** `top exe` on 08/24 is dominated by the Universal Forwarder's own helper processes: `splunk-powershell.exe` (4,497, 22%), `splunk-admon.exe` (2,457), `splunk-netmon.exe` (2,377), `splunk-winprintmon.exe` (2,283), `splunk-MonitorNoHandle.exe` (2,201), `splunk-winhostinfo.exe` (2,087) — six sourcetype-collection helpers Splunk itself spawns every few seconds. `conhost.exe` (1,217) and `cscript.exe` (791) round out the top 8. **Lesson:** a bare `top exe` on Sysmon EID 1 surfaces monitoring noise, not the interesting process — you have to filter it out (`NOT Image="*SplunkUniversalForwarder*"`) or search for a specific marker (`CommandLine="*-enc*"`, Q43) to find what actually matters.

### Q27 — sed-mode redaction
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| rex field=uri mode=sed "s/\?.*//"
| stats count by uri
```
Strips query strings so `/x?id=1` and `/x?id=2` collapse to `/x`. Verified effect on 08/23 — **before** (raw `uri`, query strings intact) the top rows are `/forumdisplay.php?fid=5` (390), `/xmlhttp.php?action=validate_captcha` (301), `/jscripts/jquery.js?ver=1800` (195), each fragmented by its query string; **after** the `sed` strip they collapse into `/showthread.php` (830), `/forumdisplay.php` (776), `/xmlhttp.php` (525) — the same forum page hit with dozens of different `fid=`/`tid=` values now counts as one URI.

### Q28 — tstats timechart
```spl
| tstats count where index=botsv2 sourcetype=suricata by _time span=1h
```
Reads indexed fields → fast on 226M events; use instead of raw `| timechart` when you only need counts over time. Verified first hourly buckets (whole month, since no time filter is set): `08-01 00:00` → 831, `01:00` → 1,039, `02:00` → 897, `03:00` → 1,068, `04:00` → 1,007 — steady baseline IDS traffic before the 08-19/08-24/08-26 spikes noted in Q9.

### Q29 — metadata recon
```spl
| metadata type=sourcetypes index=botsv2
| eval firstTime=strftime(firstTime,"%F %T"), lastTime=strftime(lastTime,"%F %T")
| table sourcetype totalCount firstTime lastTime
```
Same `%F %T` shorthand as Q4 — `%F` = `%Y-%m-%d`, `%T` = `%H:%M:%S` — turns `firstTime`/`lastTime`'s raw epoch numbers into readable timestamps. Verified, sorted by volume: `WinRegistry` (55,528,820 events), `Perfmon:Process` (49,343,467), `mysql:server:stats` (26,926,873), `mysql:transaction:details` (26,756,085), `collectd` (22,437,386) — all span the full `2017-08-01 00:00:01` → `2017-08-31 23:59:59` month, confirming the dataset's time span from Q4 down at the per-sourcetype level.

### Q30 — tstats by host+sourcetype
```spl
| tstats count where index=botsv2 by host sourcetype | sort - count
```
Shows which host owns which telemetry (e.g. `cassiopeia` heavy on perfmon/mysql; `wrk-*` on Sysmon/winregistry). Verified top rows: `cassiopeia`/`mysql:server:stats` (26,921,724), `cassiopeia`/`mysql:transaction:details` (26,756,085), `maclory-air13`/`collectd` (20,968,547), `wrk-ghoppy`/`winregistry` (7,731,147), `wrk-btun`/`winregistry` (7,580,213) — confirms `cassiopeia` as the DB server (Q50) and shows each host's telemetry fingerprint at a glance.

### Q31 — subsearch pivot
```spl
index=botsv2 sourcetype=stream:dns [
| tstats count where index=botsv2 sourcetype=*ysmon* by host
| sort - count
| head 1
| fields host ]
| stats count by query{}
```
Subsearch resolves first, returns `host=<top>`, injected as a filter. Keep it tiny (subsearches are row/time-capped).

⚠️ **Verified — this exact query returns zero results, and that's a real finding, not a broken query.** The subsearch resolves to `host=wrk-aturing` (top Sysmon host, 163,282 events — see Q10). But `stream:dns` in this lab is only captured on a handful of **servers** — `jupiter`, `cassiopeia`, `matar`, `eridanus`, `gacrux`, `altair`, `jabbah` — none of which are `wrk-*` workstations. `wrk-aturing` never appears as a `host` value in `stream:dns`, so the outer search legitimately matches nothing. Confirmed with `| tstats count where index=botsv2 sourcetype=*ysmon* by host` (all results are `venus` + `wrk-*`) vs. `index=botsv2 sourcetype=stream:dns earliest=0 | stats count by host` (all results are the server list above) — **zero host overlap** between the two sourcetypes. Lesson: a subsearch can be syntactically perfect and still return nothing because the pivot field's *value space* doesn't overlap between the two sourcetypes — check that before assuming your SPL is wrong (same "0 results ≠ broken query" principle as Q40's time-window trap).

### Q32 — stats→eval→where
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| stats count as total count(eval(status>=400)) as errors by clientip
| eval rate=errors/total
| where total>100 AND rate>0.2
```
`where` filters *after* aggregation (on the computed `total`/`rate` fields) — different from `search`, which filters raw events *before* `stats`. Returns the 3 clients with a >20% error rate on 08/23: `204.194.143.30` (42/184 = **0.228**), `71.39.18.121` (**0.227**), `107.3.17.56` (**0.203**).

⚠️ **The threshold is data-dependent — don't copy a round number.** A `rate>0.5` (50%) filter returns **zero rows** here: this dataset's *highest* client error rate is only ~23%, so nothing clears 50%. "High" is relative to the baseline — look at the spread first (`… | where total>100 | sort - rate`), then pick a cutoff that isolates the tail. (If your search shows *No results found* on a `where`, the query is fine; your threshold just didn't match the data.)

### Q33 — eventstats z-score
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| bin _time span=1m
| stats count by _time clientip
| eventstats avg(count) as avg stdev(count) as sd
| where count > avg + 3*sd
```
**What each step does and why:**
- **`bin _time span=1m`** — rounds every event's `_time` *down* to its 1-minute slot (`14:30:41` → `14:30:00`), so all events in the same minute now share one `_time` value. Without this you couldn't group "per minute" — raw `_time` is unique to the millisecond.
- **`stats count by _time clientip`** — one row per *(minute, client)* = "how many requests did this client make in this minute." This is the per-row metric you want to test for spikes.
- **`eventstats avg(count) stdev(count)`** — computes the average and standard deviation *across all those rows*, then — unlike `stats`, which collapses everything into one summary row — **writes those two numbers back onto every row as new columns** (`avg`, `sd`). That's the whole point of `eventstats`: each row now carries the global baseline next to its own value, so the next command can compare the two. (`stats` would give you the average but throw away the individual rows; you'd have nothing left to flag.)
- **`where count > avg + 3*sd`** — keeps only rows more than 3 standard deviations above the mean — the "3-sigma" / z-score rule. Statistically ~99.7% of normal minutes fall inside 3σ, so what's left is the genuinely abnormal bursts.

Verified on 08/23: **84** `(minute, client)` buckets clear the 3σ bar, the biggest a **25-requests-in-one-minute** spike — the seed of an automated anomaly detection (Stage 4).

### Q34 — transaction vs stats
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| transaction clientip maxpause=5m
| sort - eventcount
| eval duration=tostring(duration,"duration")
| table clientip duration eventcount
```
**The three pieces to know:**
- **`maxpause=5m`** — the session-gap rule: within one `clientip`, start a *new* transaction whenever two consecutive events are more than 5 minutes apart (the client went quiet, so the session ended). Siblings: `maxspan` (cap a session's total length), `maxevents` (cap its event count), `startswith`/`endswith` (begin/end a session on a marker event).
- **`duration`** and **`eventcount`** — fields `transaction` *auto-creates* on every output session: `duration` = seconds from the first to the last event in that session; `eventcount` = how many events it grouped. You don't define them — you just use them (here, `sort - eventcount` to surface the biggest bursts).
- **`tostring(duration,"duration")`** — `duration` comes back as raw seconds (e.g. `14620`), which is hard to read. The `"duration"` conversion type turns it into a readable `HH:MM:SS` clock (`14620` → `04:03:40`); overwriting the field in place (`eval duration=…`) keeps the column name tidy. (For values over a day it becomes `D+HH:MM:SS`.)

Verified on 08/23, the biggest burst session is **`98.116.39.236`** — **322 requests in one session lasting `04:03:40`** (14,620 s), then a second ~309-request session (`03:44:52`); `4.14.104.185` shows several ~100-request sessions of `00:24:21` each. Those tight bursts are exactly what a plain `stats count by clientip` would flatten into a single number.

**`stats` aggregates; `transaction` stitches.** `stats` collapses events into summary rows and discards the individual events and their order — cheap, distributable, scales to 226M events. `transaction` keeps events grouped *in order*, honours time rules (`maxpause`/`maxspan`/`startswith`/`endswith`), and derives `duration` + `eventcount` — but it runs on the search head, holds events in memory, and silently caps very large transactions, so it's far more expensive.

**Concrete difference (verified, client `204.194.143.30` on 08/23):**
- `| stats count by clientip` → **1 row**: 184 requests spanning one ~22-hour range.
- `| transaction clientip maxpause=5m` → **44 rows**: the same 184 requests split into 44 separate *sessions* (avg ~4 requests each) — the client kept returning in bursts with >5-minute gaps between them. That burst structure is exactly what `stats` throws away and `transaction` preserves.

**Rule of thumb:** default to `stats`; reach for `transaction` only when you need the session boundaries or the ordered events within a session. If you just want count + duration per group (no ordering), `stats` does it cheaper — one row per client, the whole day as a single span:
```spl
… | stats count as n range(_time) as duration by clientip
```

### Q35 iplocation enrichment
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| iplocation clientip
| stats count by Country
| sort - count
```
Verified 08/23: United States 11,399, **Mauritius 860**, Indonesia 17, Germany 15. The Mauritius cluster is an odd outlier for a US brewery — the kind of geo anomaly worth a second look.

**Adding City — `iplocation` returns more than `Country`.** The command enriches each event with `Country`, `City`, `Region`, `lat`, `lon`, etc., so you just add the fields you want to the `by` clause:
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| iplocation clientip
| stats count by Country City
| sort - count
```
Verified 08/23 top rows: `United States / San Francisco` (2,435), `New York` (1,318), `Chicago` (1,030), `Omaha` (1,017), `Edgewater` (922), then **`Mauritius / Ebene CyberCity` (860)**. Adding `City` is what makes the anomaly *actionable*: the Mauritius traffic doesn't just come from "somewhere in Mauritius" — it resolves to one city, and drilling in (`… | search Country=Mauritius | stats count by City clientip`) pins it to two IPs, `196.52.39.2` (554) and `196.52.10.34` (306).

> 💡 Two things to know when you add `City`:
> - Group `by Country City`, not `by City` alone — city names aren't unique (there's a Portland in Oregon *and* Maine), so the country keeps them distinct.
> - Not every IP resolves to a city — for some, `iplocation` fills `Country` but leaves `City` empty, and `stats … by City` silently drops those null-city rows. (This particular day happens to resolve *all* 54,033 rows to a city, but on other data gate with `eval City=coalesce(City,"(unknown)")` first so you don't lose events.)

### Q36 Busiest hour (`strftime`)
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| eval hour=strftime(_time,"%H")
| stats count by hour
| sort - count
```
Peak hour **09** (4,009), then **17** (3,819), **10** (3,817). `strftime(_time,"%H")` buckets by hour-of-day regardless of date; `strptime` is the inverse (string → epoch).

### Q37 Missing-status count (the trap, quantified)
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| stats count(status) as have count as total
| eval missing=total-have
```
08/23: have **12,291**, total **54,033**, **missing 41,742**. Those field-less rows are exactly what a `case()`/`true()` catch-all (Q22) mislabels "5xx". `count(field)` counts only rows where the field exists — gate on `status=*` whenever `status` drives a metric.

### Q38 `values()` + `dc()` scanner profile
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| stats dc(uri) as uris values(method) as methods count by clientip
| sort - uris
```
Top: `4.14.104.185` (102 distinct URIs, `GET`+`POST`, 2,005 hits), `98.116.39.236` (62), `68.99.6.195` (55). High `uris` + both methods = app crawling.

### Q39 — `streamstats` running total
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| bin _time span=1h
| stats count by _time
| streamstats sum(count) as running_total
```
*(format `_time` with `strftime(_time,"%H:%M")` to read the hours.)* Verified 08/23 — `count` is per-hour, `running_total` accumulates down the rows:

| _time | count | running_total |
|---|---|---|
| 00:00 | 793 | 793 |
| 01:00 | 1,001 | 1,794 |
| 02:00 | 828 | 2,622 |
| 03:00 | 1,043 | 3,665 |
| 04:00 | 974 | 4,639 |
| … | … | … |

**`stats` vs `eventstats` vs `streamstats` — same aggregate, different *timing*:**
- **`stats sum(count)`** → collapses to **one** row: the grand total, individual rows gone.
- **`eventstats sum(count)`** → keeps every row, stamps the **same** grand total on all of them (the baseline broadcast — Q33).
- **`streamstats sum(count)`** → keeps every row, each gets the total **so far**, growing row by row — the running total above.

⚠️ `streamstats` trusts the row order it's handed, so `sort` (or the `bin`+`stats` ordering) *before* it if the sequence matters. Add `by <field>` to run an independent stream per group — e.g. `streamstats count by clientip` numbers each client's requests 1, 2, 3, … separately.

### Q40 `match()` SQLi flag

> ⏱ **Window matters here — and it's NOT the same as the rest of Stage 2.** The brewertalk attack happens on **08/11 (the scan/crawl)** and **08/16 (the SQLi)** — *not* the 08/23 day the other web questions use. Set the picker to `08/11/2017 00:00:00` → `08/17/2017 00:00:00`. Search this on 08/23 and you get **zero results** (the scanner isn't active then) — a perfect example of "0 results = wrong time picker, not wrong SPL."

**First — how do you even know the scanner is `45.77.65.211`?** You don't assume it; you find it. The instinct to `| top src_ip` on brewertalk traffic **fails here** — by raw request count the busiest source is a legit-looking visitor (`4.14.104.185`), and `45.77.65.211` isn't even in the top 5. A scanner gives itself away not by *volume* but by **path diversity** — it crawls thousands of distinct URLs:
```spl
index=botsv2 sourcetype=stream:http www.brewertalk.com earliest="08/11/2017:00:00:00" latest="08/17/2017:00:00:00"
| stats dc(uri_path) as paths count by src_ip
| sort - paths
```
Verified: **`45.77.65.211` touched 4,022 distinct paths** — the next-highest source hit only **83**. That 50× gap is the scanner. (Two more confirmations: its User-Agent literally contains `w3af.org` (a web-attack framework) and a Shellshock probe string; and 100% of the `updatexml` injection requests come from it.) Its 8,965 requests are spread across two days: the bulk **path crawl on 08/11**, then the **136-request `updatexml` SQLi run on 08/16**.

Then the actual Q40 — flag and count the SQLi:
```spl
index=botsv2 sourcetype=stream:http src_ip="45.77.65.211" earliest="08/11/2017:00:00:00" latest="08/17/2017:00:00:00"
| eval sqli=if(match(form_data,"(?i)updatexml|union.*select"),1,0)
| stats sum(sqli) as sqli_hits count
```
**136** SQLi hits (of 8,966 events from that source) — the `updatexml` error-based injection on `/member.php`. ⚠️ Scope to the attacker `src_ip`: `match()` over the whole web index drowns in noise and can misfire on multivalue `form_data`.

---

## Stage 3 — Log Analysis

### Q41 Process creation (4688)
```spl
index=botsv2 sourcetype=wineventlog:security EventCode=4688 earliest="08/24/2017:00:00:00" latest="08/25/2017:00:00:00"
| stats count by ComputerName | sort - count
```
`ComputerName` carries the FQDN `<host>.frothly.local`. EventCode is auto-extracted (classic key=value log). Verified top hosts: `wrk-aturing.frothly.local` (2,849), `wrk-fmaltes.frothly.local` (2,832), `wrk-btun.frothly.local` (2,779), `wrk-abungst.frothly.local` (2,645), `wrk-ghoppy.frothly.local` (2,518), `venus.frothly.local` (2,239) — process-creation volume spread fairly evenly across workstations, with `venus` (a server) also in the mix.

### Q42 Logons (4624/4625)
```spl
index=botsv2 sourcetype=wineventlog:security (EventCode=4624 OR EventCode=4625) earliest="08/24/2017:00:00:00" latest="08/25/2017:00:00:00"
| stats count by EventCode ComputerName
```
4625 = failed logon; a spike on one host flags a credential attack. Verified 08/24: `mercury.frothly.local` dominates both — **14,303** successful (4624) and **577** failed (4625) logons, an order of magnitude above every other host (`wrk-abungst` next-highest on 4625 with only 24). `mercury` is a server (likely running scheduled/service auth), so read this as heavy *service-account* logon churn, not a targeted brute force — cross-check against Q48's actual SSH brute force on `eridanus`/`gacrux` for what a real credential attack's shape looks like.

### Q43 Sysmon detail — the narrowing funnel
Sysmon gives the `CommandLine`/hashes that 4688 lacks here (fields via the lab add-on). The whole point is that you can't get here by eyeballing a raw table — you narrow in steps:

**Step 1 — measure.**
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 host=wrk-* earliest="08/24/2017:00:00:00" latest="08/25/2017:00:00:00"
| stats count by host
```
Verified: **18,189** EID-1 events across the 7 `wrk-*` hosts that day (2,149–2,919 each). A raw `table … | sort _time` on that many rows is exactly the "needle in the ocean" this question is built to teach you out of.

**Step 2a — find the noise before you filter it.** Don't guess at `SplunkUniversalForwarder` — rank the field and let the data show you:
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 host=wrk-* earliest="08/24/2017:00:00:00" latest="08/25/2017:00:00:00"
| stats count by Image | sort - count | head 10
```
Verified:

| Image | count |
|---|---|
| `C:\Program Files\SplunkUniversalForwarder\bin\splunk-powershell.exe` | 3,932 |
| `C:\Program Files\SplunkUniversalForwarder\bin\splunk-admon.exe` | 2,126 |
| `C:\Program Files\SplunkUniversalForwarder\bin\splunk-netmon.exe` | 2,046 |
| `C:\Program Files\SplunkUniversalForwarder\bin\splunk-winprintmon.exe` | 1,998 |
| `C:\Program Files\SplunkUniversalForwarder\bin\splunk-MonitorNoHandle.exe` | 1,900 |
| `C:\Program Files\SplunkUniversalForwarder\bin\splunk-winhostinfo.exe` | 1,874 |
| `C:\Windows\System32\conhost.exe` | 1,217 |
| `C:\Windows\System32\cscript.exe` | 667 |
| `C:\Program Files (x86)\Google\Chrome\Application\chrome.exe` | 512 |
| `C:\Windows\SysWOW64\dllhost.exe` | 281 |

The **top 6 rows** all share one path prefix — `C:\Program Files\SplunkUniversalForwarder\bin\…` — and together account for **13,876** of the 18,189 events (76%, matching Step 2b's drop below). That shared prefix, not a guess, is where the `NOT Image="*SplunkUniversalForwarder*"` filter comes from: on this dataset one vendor's helper binaries dominate the frequency ranking by a wide margin (3,932 vs. the next non-Splunk entry at 1,217), so "what's most common" and "what's routine background noise" line up. This is the general move, not a one-off trick — `stats count by <field> | sort - count` before you filter is how you find *any* dominant-but-benign cluster, on any sourcetype, without already knowing the environment.

**Step 2b — confirm the cut.**
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 host=wrk-* earliest="08/24/2017:00:00:00" latest="08/25/2017:00:00:00"
  NOT Image="*SplunkUniversalForwarder*"
| stats count
```
Verified: **4,313** events remain — cuts the pile by 76%, but that's still far too much to scroll and read. (The excluded 76% is Splunk's own Universal Forwarder re-spawning its collection helpers — `splunk-admon.exe`, `splunk-winprintmon.exe`, `splunk-powershell.exe`, … all parented by `splunkd.exe` — the same noise family as Q26.)

**Step 3 — search for markers, not rows.**
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 host=wrk-* earliest="08/24/2017:00:00:00" latest="08/25/2017:00:00:00"
  (CommandLine="*-enc*" OR CommandLine="*FromBase64String*" OR CommandLine="*DownloadString*")
| table _time host CommandLine ParentImage
| sort _time
```
Verified: exactly **8** events, on just **2 hosts** (`wrk-btun` ×5, `wrk-klagerf` ×3) — small enough to read by hand.

⚠️ A bare `CommandLine="*IEX*"` added to that `OR` list looks tempting but is a trap: it also matches the substring inside `iexplore.exe`, pulling in ordinary Internet Explorer processes as false positives (verified — it adds 2 unrelated `iexplore.exe` hits on `wrk-aturing`). Anchor it (`"*IEX(*"`) or leave it out; `-enc`/`FromBase64String`/`DownloadString` alone are already precise here.

**Step 4 — read the parent.** The first hit, **`wrk-btun` at 03:29:08**, is `powershell -noP -sta -w 1 -enc …` parented by **`C:\Windows\System32\wbem\WmiPrvSE.exe`** — launched via WMI, not a user double-click (the lateral-movement tell used throughout Stage 4's Threat Hunting track). The remaining 7 rows are the follow-on chain on the same two hosts: more `-enc` PowerShell (03:32–03:56), then `schtasks.exe /Create /F /RU system …` (persistence) parented by that same PowerShell, then `taskeng.exe` re-running it. That WMI-spawned first hit is the odd parent→child chain the question is pointing at — 18,189 events narrowed to 1 signpost in four steps.

### Windows endpoint — case summary (Q41–Q43)

Three sources looked at the same day. Only the third one actually finds the compromise:

| Q | Source | What it showed | Verdict |
|---|---|---|---|
| Q41 | 4688 (process creation) | Volume spread evenly across every `wrk-*` host (2,149–2,919 each) | No standout — volume alone flags nothing |
| Q42 | 4624/4625 (logon) | `mercury.frothly.local` spikes to 14,303/577 — the "obvious" anomaly | ⚠️ **Red herring** — a server's routine service-account churn, not a credential attack |
| Q43 | Sysmon EID 1 (process detail) | Rank-and-exclude the noise, then filter on obfuscation markers | ✅ **The real finding** — a PowerShell Empire stager |

Q43's funnel resolves to a concrete, verified timeline on 08/24:

| Time | Host | Event |
|---|---|---|
| 03:29:08 | `wrk-btun` | `powershell -enc …` parented by `WmiPrvSE.exe` — the **initial WMI-launched stager** (foothold) |
| 03:32:00–01 | `wrk-btun` | Second `-enc` PowerShell invocation |
| 03:45:03 | `wrk-btun` | `schtasks /Create /F /RU system …` — **persistence** established |
| 03:55:13 | `wrk-klagerf` | Same WMI-spawned stager pattern on a **second host** — lateral movement, 26 min after the foothold |
| 03:56:00 | `wrk-btun` | `taskeng.exe` re-runs the scheduled task |
| 04:04:26 | `wrk-klagerf` | Same `schtasks` persistence, second host |
| 04:09:00 | `wrk-klagerf` | `taskeng.exe` re-runs it there too |

**Lesson:** the two "obvious" places to check — process-creation volume (Q41) and logon spikes (Q42) — come up empty or misleading; the actual compromise is invisible to both. It only surfaces in Q43 once you stop looking at *volume* and filter on *known markers* instead. `wrk-btun` is the foothold (03:29); it spreads to `wrk-klagerf` by the same WMI technique inside 26 minutes, and both hosts have working persistence by ~04:09 — a ~40-minute window from initial access to a second persistent foothold. This is a preview of Stage 4's Threat Hunting track ([`../../specialized/botsv2/01-threat-hunting.md`](../../specialized/botsv2/01-threat-hunting.md)), which follows this same C2 to a third host (`venus`) and names the accounts behind it (`billy.tun` foothold → `service3` lateral movement).

### Q44 — Web: proving the day is clean, the Q40 way

**Step 1 — measure.**
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| stats count by status method
| sort - count
```
Same query and result as Q8 — **12,291 rows** across `200/GET`, `200/POST`, `403/GET`, `304/GET`, `404/GET`, `302/GET` (see Q8's table and its missing-`status` gotcha).

**Step 2 — read the non-200 buckets.**
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00" (status=403 OR status=404)
| stats count by status uri | sort - count
```
`404`s are just `/favicon.ico` (231, harmless — every browser requests it). `403`s are almost entirely the *same three* cache-busted font requests, repeating: `/fonts/icomoon/icomoon.ttf?srf3rx` (120), `.woff?srf3rx` (89), `.woff?qtatmt` (82) — a CDN/theme asset blocked by a web-server rule, not a scanner probing distinct paths.

**Step 3 — apply Q40's yardstick.**
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| stats dc(uri_path) as paths count as reqs by clientip
| sort - paths | head 10
```
Verified top: `4.14.104.185` (**90** distinct paths, 2,005 requests), then `98.229.101.186` (46), `98.116.39.236` (43), `68.99.6.195` (42) — a smooth, gradual drop-off. Compare to Q40: the actual scanner (`45.77.65.211`, on 08/11) hit **4,022** distinct paths, 50× its nearest neighbor. Nothing here is remotely close to that shape.

**Step 4 — verdict.** No scanner, no attack signal in this day's web traffic — 90 paths from a normal visitor vs. Q40's 4,022-path outlier is not the same phenomenon, it's routine browsing. That's expected: the interesting web activity (Q40) lives on **08/11 and 08/16**, a different window entirely. "This day is clean" is the correct, defensible answer here — reached by measurement, not assumption.

### Q45 — DNS (JSON stream): filter it, then check what it ate

**Step 1 — measure, unfiltered.**
```spl
index=botsv2 sourcetype=stream:dns earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| stats count by query{}
| sort - count | head 5
```
Verified: **`FHFAEBEECACACACACACACACACACACAAA`** (6,276 — NetBIOS-encoded name, noise), `outlook.office365.com` (934), **`wpad`** (888, bare/dot-less), `manage.office.com` (737), `nexus.officeapps.live.com` (528).

**Step 2 — filter and re-run.**
```spl
index=botsv2 sourcetype=stream:dns earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| regex "query{}"="\."
| stats count by query{} | sort - count | head 10
```
Verified top 10: `outlook.office365.com` (934), `manage.office.com` (737), `nexus.officeapps.live.com` (528), `nexusrules.officeapps.live.com` (472), `logx.optimizely.com` (440), `wpad.frothly.local` (378), `15.1.168.192.in-addr.arpa` (364), `bea4.cnn.com` (302), `ocos-office365-s2s.msedge.net` (284), `b.scorecardresearch.com` (280) — the NetBIOS string is gone; real Office 365/CDN/analytics traffic.

**Step 3 — check the casualties.** The dot-filter dropped more than just the NetBIOS string: the bare `wpad` (888 hits) — the actual WPAD auto-discovery broadcast query — vanished too, while its resolved FQDN cousin `wpad.frothly.local` (378) survived, since it has dots. This is the filter's blind spot: it can't tell "NetBIOS junk" from "any other legitimately dot-less query," it just drops anything without a `.`. In this dataset that collateral happens to be benign (WPAD is expected, and its FQDN form still shows up), but a rigorous read checks the excluded side of a filter, not just what surfaced.

**Step 4 — conclusion.** The dot-filter is a fast, reusable first pass for killing NetBIOS noise on this dataset, not a perfect domain classifier — it also strips any other short, dot-less token, so double-check what it drops before trusting a "clean" list.

### Q46 — Suricata: from 5,000+ events of noise to a 4-event lead

**Step 1 — measure the raw signature list.**
```spl
index=botsv2 sourcetype=suricata alert.signature=* earliest=0
| stats count by alert.signature alert.category
| sort - count
```
Top: `ET SCAN … Port 135` (5,330), then TLS/TOR and `ET POLICY Vulnerable Java` signatures — high-volume, low-signal.

**Step 2 — zoom out to categories.**
```spl
index=botsv2 sourcetype=suricata alert.signature=* earliest=0
| stats count by alert.category | sort - count
```
Verified: **`Misc activity`** (5,344 — the scan + TOR/TLS + policy noise from Step 1, all lumped together), `Generic Protocol Command Decode` (44), `Potentially Bad Traffic` (12), `Misc Attack` (7), and **`A Network Trojan was detected`** (**5** — the smallest category by far).

**Step 3 — drill into the smallest category.**
```spl
index=botsv2 sourcetype=suricata "alert.category"="A Network Trojan was detected" earliest=0
| stats count by alert.signature
```
Verified: exactly two signatures — `ET TROJAN DNS Reply Sinkhole - Anubis - 195.22.26.192/26` (1) and **`ET TROJAN OSX Backdoor Quimitchin DNS Lookup`** (4). The second one names an OS Frothly's Windows-heavy environment shouldn't otherwise be talking about — the macOS malware pointer for Stage 4.

**Step 4 — identify the host.**
```spl
index=botsv2 sourcetype=suricata "alert.signature"="*Quimitchin*" earliest=0
| stats count by src_ip dest_ip
```
Verified: `src_ip=10.0.4.2 → dest_ip=10.0.1.100`, 4 events — 5,344 alerts of scanning/TOR/policy noise narrowed down to one internal host making DNS lookups tied to a known macOS backdoor. That host is the concrete lead Stage 4's threat-hunting track picks up.

### Q47 Palo Alto (CSV, needs rex)

**Step 1 — read the raw shape.**
```spl
sourcetype=pan:traffic | head 1
```
Verified `_raw`:
```
Aug 31 15:59:37 10.0.1.1  1,2017/08/31 15:59:36,009401015183,TRAFFIC,end,1,2017/08/31 15:59:36,10.0.2.101,10.0.1.100,0.0.0.0,0.0.0.0,Client-Server,frothly.local\amber.turing,,dns,vsys1,Inside,Inside,ethernet1/3,ethernet1/2,Jupiter,2017/08/31 15:59:36,63207,1,54896,53,0,0,0x19,udp,allow,531,395,136,6,2017/08/31 15:58:58,9,any,0,3349659,0x0,10.0.0.0-10.255.255.255,10.0.0.0-10.255.255.255,0,5,1
```
No auto-extracted fields at all — comma-separated, anchor on the literal `TRAFFIC` marker since the fields before it aren't fixed-width (a syslog header, then a leading sequence number and two timestamps come before it).

**Step 2 — carve `src_ip`/`dest_ip` positionally.**
```spl
index=botsv2 sourcetype=pan:traffic
| rex "TRAFFIC,\w+,\d+,[^,]+,(?<src_ip>[^,]+),(?<dest_ip>[^,]+)"
| stats count by src_ip dest_ip | sort - count
```
Verified top pairs (whole dataset): `10.0.1.100 → 8.8.8.8` (280,239 — DNS to Google), `10.0.1.200 → 52.40.10.231` (248,555 — an AWS-hosted endpoint), `10.0.2.101 → 10.0.1.100` (181,699), `10.0.2.107 → 10.0.1.100` (51,602), `10.0.2.109 → 10.0.1.100` (47,935) — the last three are internal-to-internal flows converging on `10.0.1.100`, worth a second look given that host's role elsewhere in the dataset.

**Step 3 — read before concluding.** The top two rows are unremarkable (public DNS, a cloud endpoint); the interesting shape is three *different* internal hosts all funneling traffic to the same fourth host.

**Step 4 — add `src_user`.** Extend the `rex` three more comma-fields past `dest_ip` to reach the user column:
```spl
index=botsv2 sourcetype=pan:traffic "10.0.2.101" "10.0.1.100"
| rex "TRAFFIC,\w+,\d+,[^,]+,(?<src_ip>[^,]+),(?<dest_ip>[^,]+),[^,]+,[^,]+,[^,]+,(?<src_user>[^,]*)"
| search src_ip=10.0.2.101 dest_ip=10.0.1.100
| stats count by src_user | sort - count
```
Verified: `frothly.local\amber.turing` (173,975) and its short-domain-form duplicate `frothly\amber.turing` (5,831) dominate this pair, with a much smaller `frothly.local\service3` (106) also present. Domain is `frothly.local`; users appear as `frothly.local\<user>` or the shorter `frothly\<user>`.

### Q48 SSH brute force (linux_secure, syslog → rex)

**Step 1 — isolate the signal.** `sourcetype=linux_secure "Failed password"` — the literal string is the whole filter.

**Step 2 — carve the source IP.**
```spl
index=botsv2 sourcetype=linux_secure "Failed password" earliest=0
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)" | stats count by src_ip | sort - count
```
**Verified top brute-forcers:** `58.242.83.20` (**26,174** fails), `116.31.116.17` (19,755), `58.242.83.11` (19,329), `218.65.30.126` (10,851), `116.31.116.52` (5,113) — internet SSH brute force.

**Step 3 — rank, then add `host` before you name a target.** `58.242.83.20` sits well above the rest — tens of thousands of failures from one IP is brute force, not a mistyped password. But `stats count by src_ip` alone tells you *who is knocking*, not *what they're knocking on* — the `host` field never appears in that output. Add it:
```spl
index=botsv2 sourcetype=linux_secure "Failed password" earliest=0
| stats count by host | sort - count
```
**No `rex` on this one** — `host` is a Splunk default metadata field, set at index time and always present on every event. Only `src_ip` needs carving out of the message text, because nothing in this lab extracts it for you (see Q47's note on why).

Verified — **two** Linux hosts are under attack, not one: **`eridanus` (67,467)** and **`gacrux` (40,162)**. Now cross-tabulate the two together — this one **does** need the `rex` back, since `src_ip` doesn't exist until you create it:
```spl
index=botsv2 sourcetype=linux_secure "Failed password" earliest=0
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip host | sort - count
```
They're not even the same attackers:

| src_ip | host | count |
|---|---|---|
| `58.242.83.20` | **`eridanus`** | 26,174 |
| `58.242.83.11` | **`eridanus`** | 19,329 |
| `116.31.116.17` | `eridanus` | 11,944 |
| `218.65.30.126` | **`gacrux`** | 10,851 |
| `116.31.116.17` | `gacrux` | 7,811 |
| `116.31.116.52` | **`gacrux`** | 5,113 |

The single loudest source, `58.242.83.20`, is hammering **`eridanus`** — and `116.31.116.17` splits its traffic across *both* hosts, which is why its 19,755 total from Step 2 doesn't belong to either host alone. Reading Step 2's `src_ip` ranking and assuming one target is exactly the mistake this step exists to prevent.

**Step 4 — sanity-check against a real login.** Check **both** hosts, not just the one you happened to look at:
```spl
index=botsv2 sourcetype=linux_secure "Accepted password" earliest=0
| stats count by host
```
Verified: **`gacrux` = 5, `eridanus` = 0.** Reading the 5 raw events, all are `Accepted password for klager from 71.39.18.125` — a completely different IP from every brute-force source above.

**Verdict.** The brute force never landed on either host. `eridanus` absorbed the heaviest attack (67k attempts, including the top two sources) and yielded **nothing**. `gacrux` had 5 successful logins, but from an unrelated legitimate user (`klager`) on an IP that appears nowhere in the attacker list — so it's not a brute-force success either. Loud ≠ successful: had you stopped at Step 2's ranking, you'd have reported the wrong target host *and* implied a compromise that never happened.

### Q49 — auditd / osquery

**Step 1 — look before you parse.**
```spl
index=botsv2 sourcetype=auditd earliest=0 | head 20
index=botsv2 sourcetype=osquery_results earliest=0 | head 5
```
Verified raw samples:
```
auditd:          type=USER_AUTH msg=audit(08/31/2017 22:59:50.870:756395) : user pid=32288 uid=root auid=unset ses=unset subj=system_u:system_r:sshd_t:s0-s0:c0.c1023 msg='op=password acct=(unknown) exe=/usr/sbin/sshd hostname=? addr=58.56.184.242 terminal=ssh res=failed'
osquery_results:  {"name":"pack_incident-response_listening_ports","hostIdentifier":"MACLORY-AIR13S.local","calendarTime":"Thu Aug 31 22:55:48 2017 UTC","unixTime":"1504220148","decorations":{"host_uuid":"564D4B96-D1CC…
```
`auditd` is space-separated `key=value` pairs (with an embedded quoted `msg='...'` sub-message). `osquery_results` is one nested JSON object per line.

**Step 2 — check what's already extracted before writing any parser.** The naive read is "`auditd` → `rex`, `osquery_results` → `spath`." Test it instead of assuming:
```spl
index=botsv2 sourcetype=auditd earliest=0 | head 1 | fields - _* | table *
```
Verified — **`auditd` needs no `rex` at all** for its key=value pairs. Splunk's automatic KV extraction already produced `type=USER_AUTH`, `acct=(unknown)`, `addr=58.56.184.242`, `exe=/usr/sbin/sshd`, `res=failed`, `op=password`, `pid`, `uid`, `auid`, `ses`, `subj`, `terminal`, `hostname` — including the pairs *inside* the quoted `msg='...'` sub-message. And there is **no `[auditd]` props.conf stanza anywhere on this instance** (verified by grepping every app's `props.conf`) — this is pure Splunk core behavior, not a lab add-on.

Same check on `osquery_results` returns `columns.path`, `columns.pid`, `columns.port`, `decorations.username`, `decorations.host_uuid`, `name`, `action`, `hostIdentifier`, … — **no `spath` needed either**; Splunk auto-detects JSON and flattens it to dotted field names. (The dataset app *does* ship an `[osquery_results]` stanza, but it only adds CIM `FIELDALIAS`/`EVAL` conveniences — `columns.path as process`, a combined `file_hash` — on top of fields JSON auto-parsing already created.)

**Step 3 — so what actually needs manual parsing?** The deliverable is the parsing *decision*, and the verified answer is: for everyday fields on these two sourcetypes, **neither** — automatic extraction covers both a JSON format and a key=value format for free. `rex` only earns its keep on sub-structure *inside* a single value that auto-KV can't see into — e.g. pulling the audit serial `756395` out of `msg=audit(08/31/2017 22:59:50.870:756395)`.

That's the real lesson, and it's the mirror image of Q47: `pan:traffic` genuinely needs `rex` because positional CSV carries **no key names and no JSON structure** — nothing for automatic extraction to latch onto. Check the field sidebar first; only reach for `rex`/`spath` when it's actually empty.

*(Content note: the `auditd` line above is the same kind of SSH brute-force noise as Q48 — a different source IP, `58.56.184.242`, but the same `res=failed` pattern — surfaced through Linux's audit subsystem instead of `linux_secure`.)*

### Q50 MySQL

**Step 1 — find the DB server.**
```spl
| tstats count where index=botsv2 sourcetype=mysql:* by host | sort - count
```
DB server = **`cassiopeia`** (~61M MySQL events — it dominates the whole index).

**Step 2 — read the raw shape.**
```spl
index=botsv2 sourcetype=mysql:* earliest=0
| head 5
| table _raw
```
Verified `_raw` — fields already named, no parser needed:
```
2017-08-31 22:59:59 hostname="gacrux", port="3306", database_name="mysql", EVENT_ID="5", Duration="0.000149", SQL_TEXT="SELECT title,cache FROM mybb_datacache"
```
key="value" (quoted), not JSON — read `SQL_TEXT` directly, no `spath`/`rex`.

**Step 3 — don't go looking in the wrong place.** It's tempting to assume the on-wire SQL lives in `stream:mysql` (it's JSON like the other `stream:*` sourcetypes). Test it instead of assuming:
```spl
index=botsv2 sourcetype=stream:mysql earliest=0 | stats count
index=botsv2 sourcetype=stream:mysql query{}=* earliest=0 | stats count
```
Verified: **711,727** vs **0** — not one `stream:mysql` event carries a `query{}` field. It's connection/flow metadata only (bytes, ports, timing). The query text is directly in `mysql:transaction:details`'s own `SQL_TEXT`, as shown in Step 2.

### Q51 — Two views of one event
`sourcetype=wineventlog:security EventCode=4688` extracts `Account_Name`, `New_Process_Name`, `Process_Command_Line` — clean account/session context, but no hashes and only a truncated command line view. Sysmon `EventCode=1` (same process-creation moment) extracts `Image`, `CommandLine`, `Hashes`, `ParentImage` — the full command line and file hashes, but weaker account/logon context. Verified on a concrete pair: a `conhost.exe` launch on `wrk-btun` at `2017-08-24 03:29:11` shows up as 4688 with `Account_Name=WRK-BTUN$` (the machine account) and separately as Sysmon EID 1 with the same `Image` plus `ParentImage`/`Hashes` that 4688 doesn't carry at all. Real triage uses both, matching each pair up by host + timestamp + `Image`/`New_Process_Name`.

### Q52 — Correlate a host

**Step 1 — pull all three at once.**
```spl
index=botsv2 host=wrk-bgist (sourcetype=*ysmon* OR sourcetype=wineventlog:security OR sourcetype=stream:dns) earliest="08/24/2017:00:00:00" latest="08/25/2017:00:00:00"
| sort _time
| table _time sourcetype EventCode Image query{}
```

**Step 2 — read it as a timeline.** Verified 08/24 09:22:07 — `wrk-bgist` fires a tight cluster within the same second: `WinEventLog:Security` EventCode `4688` (×2), then `XmlWinEventLog:…Sysmon…` EventCode `5` (process-terminate) and `1` (process-create) for `C:\Windows\System32\conhost.exe`, followed by a `schtasks.exe` process-create — a console-host + scheduled-task-tool sequence worth reading top-to-bottom in the actual table.

**Step 3 — notice what's missing.** **Zero `stream:dns` rows appear** for this host in this window — consistent with Q31's finding that `stream:dns` is only captured on server hosts (`jupiter`, `cassiopeia`, `matar`, …), not on `wrk-*` workstations. That's a real gap in this host's telemetry, not a query bug: correlating a workstation across "all three" sourcetypes in practice means two (Sysmon + WinEventLog), with DNS visibility coming only from whichever server resolved the request on its behalf.

### Q53 Asset picture

**Step 1 — one command, whole picture.**
```spl
| tstats count where index=botsv2 by host sourcetype
```

**Step 2 — read sourcetype as a fingerprint.** Servers: `cassiopeia` (MySQL/DB), `venus`/`jupiter`/`mercury` (perfmon/pan). Workstations: `wrk-*` (Sysmon/winregistry). `gacrux` + `eridanus` (Linux/SSH — `linux_secure`/`auditd`; both are the SSH brute-force targets from Q48).

**Step 3 — count the Macs, then cross-reference.** Exactly two hosts carry `osquery_results`: `maclory-air13` and `kutekitten`. Cross-referencing against Q46's Suricata drill-down: **`kutekitten`** is `10.0.4.2`, the same internal host that made the Quimitchin backdoor DNS lookup — the asset inventory and the IDS finding are pointing at the same machine.

### Q54 Email attachments (`stream:smtp`)

**Step 1 — list what got attached.**
```spl
sourcetype=stream:smtp "attach_filename{}"=* | stats count by "attach_filename{}" | sort - count
```
Verified full list: `Malware Alert Text.txt` (4), `invoice.zip` (4), `image.png` (2), `GoT.S7E2.BOTS.BOTS.BOTS.mkv.torrent` (1), `Office2016_Patcher_For_OSX.torrent` (1), `Saccharomyces_cerevisiae_patent.docx` (1).

**Step 2 — separate signal from noise.** The torrents and `image.png` are clearly irrelevant. That leaves two real threads: `invoice.zip` (generic-sounding archive, appears 4×) and `Saccharomyces_cerevisiae_patent.docx` (a specific, real-sounding document, appears once).

**Step 3 — follow each thread.** `invoice.zip` is the Taedonggang password-protected phishing lure, sent 4 times (a blast, not a one-off). `Saccharomyces_cerevisiae_patent.docx` is Amber Turing emailing a brewing patent to competitor *Berk Beer* — a one-off, insider-driven leak. Same sourcetype, two unrelated incidents. (Skip `sender_email` — it's populated on only a handful of events.)

### Q55 Symantec EP (`symantec:ep:*`)

**Step 1 — enumerate first.**
```spl
| tstats count where index=botsv2 sourcetype=symantec:ep:* by sourcetype | sort - count
```
Verified, all eight: `packet:file` (316,571), `traffic:file` (67,090), `agent:file` (15,835), `agt_system:file` (14,201), `scm_system:file` (357), `scan:file` (30), `behavior:file` (1), `security:file` (1).

**Step 2 — split by volume.** The top four are bulk network/telemetry noise (hundreds to tens of thousands of events). `scan:file` (30) is a middle tier. `behavior:file` and `security:file` sit alone at **1 event each** — the rare, high-signal ones.

**Step 3 — read the rare ones.** The `:security:file` `_raw` is comma-separated, not field-extracted — a Host-Integrity check on `wrk-aturing` (`User: amber.turing, Domain: FROTHLY`).

### Q56 FTP tooling drop (`stream:ftp`)

**Step 1 — scope to downloads.** `sourcetype=stream:ftp loadway=Download` — an FTP `RETR`, a client pulling a file.

**Step 2 — list what moved.**
```spl
sourcetype=stream:ftp loadway=Download | stats count by filename src_ip dest_ip
```
FTP server **`160.153.91.7`** served an attacker toolkit to `10.0.2.107` + `10.0.2.109` (one copy to each): `psexec.exe`, `nc.exe`, `wget64.exe`, `winsys64.dll`, `python-2.7.6.amd64.msi`, `dns.py` — plus **`나는_데이비드를_사랑한다.hwp`**, a Korean Hangul-word-processor file.

**Step 3 — read the filenames as a toolkit.** `psexec`/`nc`/`wget`/a Python runtime/a custom `dns.py` script is a classic dual-use lateral-movement kit. The `.hwp` file is the odd one out — a Korean document format with no business at an American brewery, a strong nationality/origin tell for whoever staged this FTP server.

### Q57 TLS issuer of the C2 (`stream:tcp`)

**Step 1 — scope to the indicator.** `sourcetype=stream:tcp "45.77.65.211"` — the same IP flagged as a scanner back in Q44's step 3 comparison.

**Step 2 — read the handshake field.**
```spl
sourcetype=stream:tcp "45.77.65.211" | stats count by ssl_issuer
```
`ssl_issuer` = **`C = US`** (14,189 flows; a further 9,868 flows have no `ssl_issuer` at all, i.e. no completed TLS handshake) — a bare country-only cert with no organization or CN, the self-signed look typical of Empire's default TLS. You read this from the handshake metadata even though the C2 payload itself is encrypted.

### Q58 Registry persistence blob (`winregistry`)

**Step 1 — pick keywords.** `sourcetype=winregistry "Network" "debug"` — not a full scan of 55M events.

**Step 2 — count paths.**
```spl
sourcetype=winregistry "Network" "debug" | stats count by key_path
```
`HKLM\software\microsoft\network\debug` — 4 events, on **four different hosts**: `wrk-btun`, `wrk-klagerf`, `venus`, and `mercury` (i.e. not just the two workstations from Q43's funnel — the same persistence blob also landed on two servers).

**Step 3 — pull the value and decode it.** `data` is base64; decoding it (UTF-16LE, the standard PowerShell `-enc` encoding) reveals a PowerShell **AMSI-bypass + WebClient downloader**: it disables `AmsiUtils`, spoofs an old-IE `User-Agent`, sets a session cookie, and pulls a second-stage payload from `https://45.77.65.211/...` — the same C2 IP referenced throughout Q44/Q57/Q60. This is the classic PowerShell-Empire stager, stored *in a registry value* instead of a file on disk (the "fileless" trick), which the scheduled task (Stage 4's `Updater` task) re-reads at run time.

### Q59 macOS confirmation (`osquery_results`)

**Step 1 — enumerate the query packs.**
```spl
| tstats count where index=botsv2 sourcetype=osquery_results host=kutekitten by name | sort - count
```
`kutekitten` reports through more than a dozen different osquery packs (`process_env`, `open_files`, `kextstat`, `listening_ports`, …) — most are hardware/process noise with no hash fields at all. The one that actually carries file hashes is a separate pack: `name=file_events` (only 5 events for this host).

**Step 2 — filter to rows with a real hash.**
```spl
sourcetype=osquery_results host=kutekitten name=file_events "columns.hashed"="1"
| table columns.target_path columns.md5 columns.sha1 columns.sha256
```
Verified: `/Users/mkraeusen/Downloads/Important_HR_INFO_for_mkraeusen` — `md5=72d4d364ed91dd9418d144a2db837a6d`, `sha1=794bcba867307bdbd5f947f6c939eb4df1d2c9b8`, `sha256=befa9bfe488244c64db096522b4fad73fc01ea8c4cd0323f1cbdee81ba008271`, mode `0777` (executable), 13,494 bytes.

**Step 3 — read it as a lure.** No file extension, executable permissions, an HR-themed filename designed to get a user to double-click it — a classic social-engineering delivery for the `fpsaud`/FruitFly (Quimitchin) backdoor. (Note: a plain `"columns.path"="/Users/mkraeusen*"` filter across *all* osquery packs, as an earlier version of this hint suggested, returns 117 rows but **none** of them carry a hash — you have to land on `file_events` specifically.)

**Step 4 — connect it back.** IDS *alerted* on this host's Quimitchin DNS lookups (Q46); osquery *confirms* the actual dropped file and its hash. The Mac has osquery but no real-time EDR — IDS alerts, osquery confirms.

### Q60 One indicator, six sources

**Step 1 — search unscoped.**
```spl
index=botsv2 "45.77.65.211" earliest="08/01/2017:00:00:00" latest="09/01/2017:00:00:00"
| stats count by sourcetype
| sort - count
```

**Step 2 — read the breakdown.** The C2 IP appears in **`pan:traffic`** (48,397), **`suricata`** (38,313), **`stream:tcp`** (29,069), `stream:ip` (29,060), `stream:http` (9,712), `access_combined` (4,854) — six genuinely independent technology layers. (A handful of incidental hits also show up elsewhere — Sysmon command-line references, `apache_error`, `netstat`, `stream:dns`, a CSP violation log — but the six above are the real, independent corroboration.)

**Step 3 — state the finding.** One indicator confirmed by six independent telemetry sources = the report-grade backbone you build on in Stage 4.

---

*Stage 4 (specialized) solutions live under [`../../specialized/botsv2/`](../../specialized/botsv2/) — the froth.ly APT hunted end-to-end (8 tracks + capstone).*
