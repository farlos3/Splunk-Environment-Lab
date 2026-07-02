# BOTS v2 — Solutions

Reference answers, verified against the loaded `index=botsv2`. ✅ = confirmed
value. Fundamentals are about *fluency*, so for many the "answer" is the query
+ the shape of the result, not a single magic number.

> Time picker: v2 spans **all of August 2017**. Scope raw searches to a day.

---

## Stage 1 — Fundamentals

### Q1 ✅ Sourcetypes
```spl
| tstats count where index=botsv2 by sourcetype | sort - count
```
Biggest are `winregistry` (~55M), `perfmon:process` (~49M), `mysql:server:stats` (~27M), `collectd`, then security-relevant ones: `suricata`, `xmlwineventlog:…sysmon…`, `stream:*`, `pan:traffic` (Palo Alto), `access_combined` (Apache web), `wineventlog:security`, `symantec:ep:*`, `linux_secure`/`auditd`/`osquery_results`.

### Q2 ✅ Total events
```spl
| tstats count where index=botsv2
```
**226,337,681** events. (`tstats` returns instantly; a raw `… | stats count` would scan every event — don't.)

### Q3 ✅ Distinct sourcetypes / hosts
```spl
| tstats dc(sourcetype) as sourcetypes dc(host) as hosts where index=botsv2
```
**104 sourcetypes, 23 hosts.**

### Q4 ✅ Time span
```spl
| tstats min(_time) as first max(_time) as last where index=botsv2
| eval first=strftime(first,"%F %T"), last=strftime(last,"%F %T")
```
**2017-08-01 00:00 → 2017-08-31 23:59** (a full month).

### Q5 ✅ Hosts
```spl
| tstats count where index=botsv2 by host | sort - count
```
23 hosts. Busiest: `cassiopeia` (~63M), `maclory-air13`, then workstations `wrk-btun`, `wrk-ghoppy`, `wrk-aturing`, `wrk-klagerf`, `wrk-abungst`, `wrk-fmaltes`, `wrk-bgist`; servers `mercury`, `venus`, `jupiter`, `gacrux`, `growler`, `jabbah`, `eridanus`, `matar`, `uranus`, `altair`. Naming: `wrk-*` = user workstations, single-word = servers, `maclory-air13` = a MacBook.

### Q6 ✅ One host's sourcetypes
```spl
| tstats count where index=botsv2 host=wrk-ghoppy by sourcetype | sort - count
```
A workstation emits Sysmon, winregistry, wineventlog, perfmon, stream:*, etc. — the endpoint telemetry stack.

### Q7 ✅ Web top clients (1 day)
```spl
index=botsv2 sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| top limit=10 clientip
```
On 08/23, top talkers include `4.14.104.185`, `98.116.39.236`, `68.99.6.195`, … (mix of visitors — which ones are malicious is a Stage-4 hunt, not here).

### Q8 ✅ Status / method breakdown
```spl
… sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00" | stats count by status method | sort - count
```
On 08/23: `200 GET` 10,480 · `200 POST` 879 · `403 GET` 344 · `304 GET` 327 · `404 GET` 231 · `302 GET` 30.
⚠️ **Verified gotcha:** `status` is only extracted on a *subset* of `access_combined` — ~**41,742 events that day have no `status`** and simply don't appear in this table. `stats count by status` silently drops them. Always sanity-check how many events lack the field (`… | stats count(status) as have count as total`).

### Q9 ✅ Events per day
```spl
index=botsv2 sourcetype=suricata | timechart span=1d count
```
Verified noisiest IDS days: **08-19 (192,762)**, 08-26 (136,050), 08-24 (92,290), 08-18, 08-25. Note the attack-relevant activity spans **more than just 08-24** — a good reminder to widen your window when hunting an APT (much of the volume is the port-135 scan, but the spread of busy days is the point).

### Q10 ✅ Sysmon by host
```spl
| tstats count where index=botsv2 sourcetype=*ysmon* by host | sort - count
```
Returns the workstations with Sysmon coverage (the `wrk-*` hosts + the Mac). Sysmon fields (`EventCode`, `Image`, …) come from the lab add-on.

### Q11 — Raw web table
```spl
… sourcetype=access_combined earliest=… latest=… | table _time clientip method uri status | head 10
```

### Q12 — Unique URIs
```spl
… sourcetype=access_combined earliest=… latest=… | stats dc(uri) as unique_uris
… | stats count by uri | sort - count      /* popular URIs */
```

### Q13 — Rarest User-Agents
```spl
… sourcetype=access_combined earliest=… latest=… | stats count by useragent | sort count | head 5
```
Odd/automation UAs (scanners, scripts) surface at the bottom of the frequency list.

### Q14 — eval bucketing
```spl
… | eval class=if(status>=400,"error","ok") | stats count by class
… | eval class=case(status<300,"2xx",status<400,"3xx",status<500,"4xx",true(),"5xx") | stats count by class
```

### Q15 — rex path segment
```spl
… | rex field=uri "^/(?<section>[^/?]+)" | top section
```
Extracts the first path segment (e.g. `product`, `cart`, `joomla`…) so you can profile what parts of the site are hit.

---

## Stage 2 — Intermediate SPL

> These are technique exercises — the *query* is the answer. Specific numbers depend on your time window; run them with the lab up to see values.

### Q16 — Calculated field
```spl
… sourcetype=access_combined earliest=… latest=… | eval kb=round(bytes/1024,1) | sort - kb | table _time clientip uri kb
```

### Q17 ✅ `case()` status classes — and a real trap
```spl
… sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00"
| eval class=case(status<300,"2xx",status<400,"3xx",status<500,"4xx",true(),"5xx") | stats count by class
```
Naive result: `2xx 11359 · 3xx 357 · 4xx 575 · 5xx 41742`. ⚠️ **That 5xx is a lie.** Verified: those 41,742 rows have **NULL `status`** (see Q8) — the `true()` catch-all swept every field-less event into "5xx". Real 5xx ≈ 0.
**Fix — filter to rows that actually have the field, and make the catch-all honest:**
```spl
… status=* | eval class=case(status<300,"2xx",status<400,"3xx",status<500,"4xx",status<600,"5xx",true(),"other") | stats count by class
```
Lesson: a `true()` branch silently absorbs nulls/unexpected values. Gate on `status=*` (or add an explicit `null`/`other` bucket) when the value drives a metric — same discipline as choosing `case()` over a blind `if()` else.

### Q18 — Conditional counting
```spl
… sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00" status=*
| stats count as total count(eval(status>=400)) as errors by clientip | eval err_rate=round(errors/total*100,1) | sort - err_rate
```
`count(eval(<cond>))` counts only rows matching the condition — one pass, no subsearch. Verified top error-rate clients on 08/23: `204.194.143.30` (22.8%), `71.39.18.121` (22.7%), `107.3.17.56` (20.3%). (Add `status=*` so null-status rows don't skew `total`.)

### Q19 — String functions
```spl
… | eval ua=lower(useragent) | stats count by ua
```
`lower()` normalizes so `Mozilla` and `mozilla` group together; also useful: `len()`, `substr()`, `mvindex()`, `split()`.

### Q20 — Named groups from URI
```spl
… | rex field=uri "^/(?<section>[^/?]+)" | rex field=uri "[?&]id=(?<id>[^&]+)" | table uri section id
```

### Q21 — exe from Sysmon Image
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 earliest=… latest=… | rex field=Image "\\\\(?<exe>[^\\\\]+)$" | top exe
```
Windows path separators are `\`, which must be escaped (`\\\\` in the SPL string → `\\` regex → literal `\`).

### Q22 — sed-mode redaction
```spl
… | rex field=uri mode=sed "s/\?.*//" | stats count by uri
```
Strips query strings so `/x?id=1` and `/x?id=2` collapse to `/x`.

### Q23 — tstats timechart
```spl
| tstats count where index=botsv2 sourcetype=suricata by _time span=1h
```
Reads indexed fields → fast on 226M events; use instead of raw `| timechart` when you only need counts over time.

### Q24 — metadata recon
```spl
| metadata type=sourcetypes index=botsv2 | eval firstTime=strftime(firstTime,"%F %T"), lastTime=strftime(lastTime,"%F %T") | table sourcetype totalCount firstTime lastTime recentTime
```

### Q25 — tstats by host+sourcetype
```spl
| tstats count where index=botsv2 by host sourcetype | sort - count
```
Shows which host owns which telemetry (e.g. `cassiopeia` heavy on perfmon/mysql; `wrk-*` on Sysmon/winregistry).

### Q26 — subsearch pivot
```spl
index=botsv2 sourcetype=stream:dns [ | tstats count where index=botsv2 sourcetype=*ysmon* by host | sort - count | head 1 | fields host ]
| stats count by query{}
```
Subsearch resolves first, returns `host=<top>`, injected as a filter. Keep it tiny (subsearches are row/time-capped).

### Q27 — stats→eval→where
```spl
… | stats count as total count(eval(status>=400)) as errors by clientip | eval rate=errors/total | where total>100 AND rate>0.5
```
`where` filters *after* aggregation (on computed fields) — different from `search`, which filters raw events.

### Q28 — eventstats z-score
```spl
… | bin _time span=1m | stats count by _time clientip | eventstats avg(count) as avg stdev(count) as sd | where count > avg + 3*sd
```
`eventstats` adds the aggregate back onto every row (unlike `stats`, which collapses) — that's what lets you compare each row to the baseline. Seed of an anomaly detection.

### Q29 — transaction vs stats
```spl
… | transaction clientip maxpause=5m | eval dur=duration, n=eventcount
```
Use `transaction` only when you need grouped/ordered events or duration; for plain counts `stats by clientip` is far cheaper.

### Q30 ✅ iplocation enrichment
```spl
… sourcetype=access_combined earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00" | iplocation clientip | stats count by Country | sort - count
```
Verified 08/23: United States 11,399, **Mauritius 860**, Indonesia 17, Germany 15. The Mauritius cluster is an odd outlier for a US brewery — the kind of geo anomaly worth a second look.

---

## Stage 3 — Log Analysis

### Q31 ✅ Process creation (4688)
```spl
index=botsv2 sourcetype=wineventlog:security EventCode=4688 earliest="08/24/2017:00:00:00" latest="08/25/2017:00:00:00"
| stats count by ComputerName | sort - count
```
`ComputerName` carries the FQDN `<host>.frothly.local`. EventCode is auto-extracted (classic key=value log).

### Q32 ✅ Logons (4624/4625)
```spl
… sourcetype=wineventlog:security (EventCode=4624 OR EventCode=4625) | stats count by EventCode ComputerName
```
4625 = failed logon; a spike on one host flags a credential attack.

### Q33 ✅ Sysmon detail
```spl
… sourcetype=*ysmon* EventCode=1 host=wrk-* earliest=… latest=… | table _time host Image CommandLine ParentImage | sort _time
```
Sysmon gives the `CommandLine`/hashes that 4688 lacks here (fields via the lab add-on).

### Q34 — Web
```spl
… sourcetype=access_combined earliest=… latest=… | stats count by status method | sort - count
```

### Q35 ✅ DNS (JSON stream)
```spl
… sourcetype=stream:dns earliest="08/23/2017:00:00:00" latest="08/24/2017:00:00:00" | stats count by query{} | sort - count
```
Group by `query{}` (always-present question field). Verified 08/23 top: **`FHFAEBEECACACACACACACACACACACAAA`** (6,276 — a **NetBIOS-encoded** name, i.e. noise), then real domains `outlook.office365.com`, `wpad`, `manage.office.com`, `nexus.officeapps.live.com`. Lesson: the noisiest `query{}` is often NetBIOS/WPAD junk — filter it (`| regex "query{}"="\."` drops dot-less NetBIOS names) before hunting.

### Q36 ✅ Suricata
```spl
… sourcetype=suricata alert.signature=* | stats count by alert.signature alert.category | sort - count
```
Top: `ET SCAN … Port 135` (5,330), TLS/TOR, `ET POLICY Vulnerable Java`, and **`ET TROJAN OSX Backdoor Quimitchin DNS Lookup`** — the macOS malware pointer for Stage 4.

### Q37 ✅ Palo Alto (CSV, needs rex)
No auto-fields. Read `_raw` (comma-separated), then extract. Example raw:
`… ,TRAFFIC,end,1,…,10.0.2.101,10.0.1.100,…,frothly.local\amber.turing,,dns,…`
```spl
… sourcetype=pan:traffic | rex "TRAFFIC,\w+,\d+,[^,]+,(?<src_ip>[^,]+),(?<dest_ip>[^,]+)" | stats count by src_ip dest_ip
```
Domain is `frothly.local`; users appear as `frothly.local\<user>` (e.g. `amber.turing`).

### Q38 ✅ SSH brute force (linux_secure, syslog → rex)
```spl
… sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)" | stats count by src_ip | sort - count
```
**Verified top brute-forcers:** `58.242.83.20` (**26,174** fails), `116.31.116.17` (19,755), `58.242.83.11` (19,329), `218.65.30.126`, `116.31.116.52` — internet SSH brute force (mostly hitting `gacrux`). Classic external noise; note it and distinguish from any *successful* logon.

### Q39 — auditd / osquery
`sourcetype=osquery_results` is JSON → use `spath`; `sourcetype=auditd` is `key=value`-ish → inspect `_raw` then `rex`. Deliverable = knowing which parser fits.

### Q40 ✅ MySQL
```spl
| tstats count where index=botsv2 sourcetype=mysql:* by host | sort - count
```
DB server = **`cassiopeia`** (~61M MySQL events — it dominates the whole index). `stream:mysql` carries the on-wire SQL.

### Q41 — Two views of one event
4688 (WinEventLog) gives account/logon context; Sysmon EID 1 gives `CommandLine` + hashes. Real triage uses both.

### Q42 — Correlate a host
```spl
index=botsv2 host=wrk-bgist (sourcetype=*ysmon* OR sourcetype=wineventlog:security OR sourcetype=stream:dns) earliest=… latest=… | sort _time | table _time sourcetype EventCode Image query{}
```

### Q43 ✅ Asset picture
```spl
| tstats count where index=botsv2 by host sourcetype
```
Servers: `cassiopeia` (MySQL/DB), `venus`/`jupiter`/`mercury` (perfmon/pan), `gacrux` (Linux/SSH). Workstations: `wrk-*` (Sysmon/winregistry). `maclory-air13` = the Mac (the `10.0.4.2` host that made the Quimitchin backdoor lookup).

---

*Stage 4 (specialized) solutions live under `../../specialized/botsv2/` — being built next, with full incident discovery.*
