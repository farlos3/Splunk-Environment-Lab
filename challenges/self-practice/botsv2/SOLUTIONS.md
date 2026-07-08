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
> | Web / brewertalk (`access_combined`, SQLi, scan) | `08/23/2017 00:00:00` → `08/24/2017 00:00:00` |
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

### Q12 — Unique URIs
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| stats dc(uri) as unique_uris
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| stats count by uri
| sort - count      /* popular URIs */
```

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

### Q26 — exe from Sysmon Image
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 earliest="08/24/2017:00:00:00" latest="08/25/2017:00:00:00"
| rex field=Image "\\\\(?<exe>[^\\\\]+)$"
| top exe
```
Windows path separators are `\`, which must be escaped (`\\\\` in the SPL string → `\\` regex → literal `\`).

### Q27 — sed-mode redaction
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| rex field=uri mode=sed "s/\?.*//"
| stats count by uri
```
Strips query strings so `/x?id=1` and `/x?id=2` collapse to `/x`.

### Q28 — tstats timechart
```spl
| tstats count where index=botsv2 sourcetype=suricata by _time span=1h
```
Reads indexed fields → fast on 226M events; use instead of raw `| timechart` when you only need counts over time.

### Q29 — metadata recon
```spl
| metadata type=sourcetypes index=botsv2
| eval firstTime=strftime(firstTime,"%F %T"), lastTime=strftime(lastTime,"%F %T")
| table sourcetype totalCount firstTime lastTime recentTime
```

### Q30 — tstats by host+sourcetype
```spl
| tstats count where index=botsv2 by host sourcetype | sort - count
```
Shows which host owns which telemetry (e.g. `cassiopeia` heavy on perfmon/mysql; `wrk-*` on Sysmon/winregistry).

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

### Q32 — stats→eval→where
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| stats count as total count(eval(status>=400)) as errors by clientip
| eval rate=errors/total
| where total>100 AND rate>0.5
```
`where` filters *after* aggregation (on computed fields) — different from `search`, which filters raw events.

### Q33 — eventstats z-score
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| bin _time span=1m
| stats count by _time clientip
| eventstats avg(count) as avg stdev(count) as sd
| where count > avg + 3*sd
```
`eventstats` adds the aggregate back onto every row (unlike `stats`, which collapses) — that's what lets you compare each row to the baseline. Seed of an anomaly detection.

### Q34 — transaction vs stats
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| transaction clientip maxpause=5m
| eval dur=duration, n=eventcount
```
Use `transaction` only when you need grouped/ordered events or duration; for plain counts `stats by clientip` is far cheaper.

### Q35 iplocation enrichment
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| iplocation clientip
| stats count by Country
| sort - count
```
Verified 08/23: United States 11,399, **Mauritius 860**, Indonesia 17, Germany 15. The Mauritius cluster is an odd outlier for a US brewery — the kind of geo anomaly worth a second look.

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
`streamstats` adds a cumulative column *as it walks the rows* — unlike `eventstats`, which broadcasts one global aggregate to every row. Use it for running totals and "Nth-so-far" logic.

### Q40 `match()` SQLi flag
```spl
index=botsv2 sourcetype=stream:http src_ip="45.77.65.211" earliest="08/23/2017:00:00:00" latest="08/26/2017:00:00:00"
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
`ComputerName` carries the FQDN `<host>.frothly.local`. EventCode is auto-extracted (classic key=value log).

### Q42 Logons (4624/4625)
```spl
index=botsv2 sourcetype=wineventlog:security (EventCode=4624 OR EventCode=4625) earliest="08/24/2017:00:00:00" latest="08/25/2017:00:00:00"
| stats count by EventCode ComputerName
```
4625 = failed logon; a spike on one host flags a credential attack.

### Q43 Sysmon detail
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 host=wrk-* earliest="08/24/2017:00:00:00" latest="08/25/2017:00:00:00"
| table _time host Image CommandLine ParentImage
| sort _time
```
Sysmon gives the `CommandLine`/hashes that 4688 lacks here (fields via the lab add-on).

### Q44 — Web
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| stats count by status method
| sort - count
```

### Q45 DNS (JSON stream)
```spl
index=botsv2 sourcetype=stream:dns earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| stats count by query{}
| sort - count
```
Group by `query{}` (always-present question field). Verified 08/23 top: **`FHFAEBEECACACACACACACACACACACAAA`** (6,276 — a **NetBIOS-encoded** name, i.e. noise), then real domains `outlook.office365.com`, `wpad`, `manage.office.com`, `nexus.officeapps.live.com`. Lesson: the noisiest `query{}` is often NetBIOS/WPAD junk — filter it (`| regex "query{}"="\."` drops dot-less NetBIOS names) before hunting.

### Q46 Suricata
```spl
index=botsv2 sourcetype=suricata alert.signature=* earliest=0
| stats count by alert.signature alert.category
| sort - count
```
Top: `ET SCAN … Port 135` (5,330), TLS/TOR, `ET POLICY Vulnerable Java`, and **`ET TROJAN OSX Backdoor Quimitchin DNS Lookup`** — the macOS malware pointer for Stage 4.

### Q47 Palo Alto (CSV, needs rex)
No auto-fields. Read `_raw` (comma-separated), then extract. Example raw:
`… ,TRAFFIC,end,1,…,10.0.2.101,10.0.1.100,…,frothly.local\amber.turing,,dns,…`
```spl
index=botsv2 sourcetype=pan:traffic
| rex "TRAFFIC,\w+,\d+,[^,]+,(?<src_ip>[^,]+),(?<dest_ip>[^,]+)"
| stats count by src_ip dest_ip
```
Domain is `frothly.local`; users appear as `frothly.local\<user>` (e.g. `amber.turing`).

### Q48 SSH brute force (linux_secure, syslog → rex)
```spl
index=botsv2 sourcetype=linux_secure "Failed password" earliest=0
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)" | stats count by src_ip | sort - count
```
**Verified top brute-forcers:** `58.242.83.20` (**26,174** fails), `116.31.116.17` (19,755), `58.242.83.11` (19,329), `218.65.30.126`, `116.31.116.52` — internet SSH brute force (mostly hitting `gacrux`). Classic external noise; note it and distinguish from any *successful* logon.

### Q49 — auditd / osquery
`sourcetype=osquery_results` is JSON → use `spath`; `sourcetype=auditd` is `key=value`-ish → inspect `_raw` then `rex`. Deliverable = knowing which parser fits.

### Q50 MySQL
```spl
| tstats count where index=botsv2 sourcetype=mysql:* by host | sort - count
```
DB server = **`cassiopeia`** (~61M MySQL events — it dominates the whole index). `stream:mysql` carries the on-wire SQL.

### Q51 — Two views of one event
4688 (WinEventLog) gives account/logon context; Sysmon EID 1 gives `CommandLine` + hashes. Real triage uses both.

### Q52 — Correlate a host
```spl
index=botsv2 host=wrk-bgist (sourcetype=*ysmon* OR sourcetype=wineventlog:security OR sourcetype=stream:dns) earliest="08/24/2017:00:00:00" latest="08/25/2017:00:00:00"
| sort _time
| table _time sourcetype EventCode Image query{}
```

### Q53 Asset picture
```spl
| tstats count where index=botsv2 by host sourcetype
```
Servers: `cassiopeia` (MySQL/DB), `venus`/`jupiter`/`mercury` (perfmon/pan), `gacrux` (Linux/SSH). Workstations: `wrk-*` (Sysmon/winregistry). Two Macs — `maclory-air13` and `kutekitten` (both carry `osquery_results`); **`kutekitten`** is the `10.0.4.2` host that made the Quimitchin backdoor lookup.

### Q54 Email attachments (`stream:smtp`)
```spl
sourcetype=stream:smtp "attach_filename{}"=* | stats count by "attach_filename{}"
```
Two incidents in one field: **`invoice.zip`** (×4 — the Taedonggang password-protected phishing lure) and **`Saccharomyces_cerevisiae_patent.docx`** (Amber Turing emailing a brewing patent to competitor *Berk Beer* — the insider thread). Also present: GoT/Office torrents, `Malware Alert Text.txt`. (Skip `sender_email` — it's populated on only a handful of events.)

### Q55 Symantec EP (`symantec:ep:*`)
```spl
| tstats count where index=botsv2 sourcetype=symantec:ep:* by sourcetype
```
Eight sourcetypes: `packet:file` (316,571) and `traffic:file` (67,090) dominate (network), `agent:file`/`agt_system:file` (~15k), then the high-signal singletons **`behavior:file`** and **`security:file`** (1 event each). The `:security:file` `_raw` is comma-separated — e.g. a Host-Integrity check on `wrk-aturing` (`User: amber.turing, Domain: FROTHLY`).

### Q56 FTP tooling drop (`stream:ftp`)
```spl
sourcetype=stream:ftp loadway=Download | stats count by filename src_ip dest_ip
```
FTP server **`160.153.91.7`** served an attacker toolkit to `10.0.2.107` + `10.0.2.109`: `psexec.exe`, `nc.exe`, `wget64.exe`, `winsys64.dll`, `python-2.7.6.amd64.msi`, `dns.py` — plus **`나는_데이비드를_사랑한다.hwp`**, a Korean Hangul-word-processor file (the "unusual file for an American company"). `filename` / `method_parameter` carry the name; `loadway=Download` = an FTP `RETR`.

### Q57 TLS issuer of the C2 (`stream:tcp`)
```spl
sourcetype=stream:tcp "45.77.65.211" | stats count by ssl_issuer
```
`ssl_issuer` = **`C = US`** (14,189 flows) — a bare country-only cert (no O/CN), the self-signed look of Empire's default TLS. You read this from the handshake metadata even though the C2 payload is encrypted.

### Q58 Registry persistence blob (`winregistry`)
```spl
sourcetype=winregistry "Network" "debug" | stats count by key_path
```
`HKLM\software\microsoft\network\debug` (4 events) — a base64 PowerShell-Empire payload stored *in the registry*; the `Updater` scheduled task (Stage 4) reads it back at run time. "Fileless" persistence: the malware lives in a registry value, not a file. Pull `data` to see the blob.

### Q59 macOS confirmation (`osquery_results`)
```spl
sourcetype=osquery_results host=kutekitten "columns.path"="/Users/mkraeusen*" | stats count
```
**117** file records under Mallory's home (`mkraeusen`). osquery snapshots carry `columns.sha256`/`columns.path`, so you can lift the suspicious file's hash and check it externally — this is how the incident IDs the `fpsaud`/FruitFly (Quimitchin) backdoor. The Mac has osquery but no real-time EDR: IDS *alerts*, osquery *confirms*.

### Q60 One indicator, six sources
```spl
index=botsv2 "45.77.65.211" earliest="08/01/2017:00:00:00" latest="09/01/2017:00:00:00"
| stats count by sourcetype
| sort - count
```
The C2 IP appears in **`pan:traffic`** (48,397), **`suricata`** (38,313), **`stream:tcp`** (29,069), `stream:ip` (29,060), `stream:http` (9,712), `access_combined` (4,854). One indicator confirmed by six independent telemetry sources = the report-grade backbone you build on in Stage 4.

---

*Stage 4 (specialized) solutions live under [`../../specialized/botsv2/`](../../specialized/botsv2/) — the froth.ly APT hunted end-to-end (8 tracks + capstone).*
