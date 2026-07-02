# BOTS v2 — Stage 2: Intermediate SPL

Stage 1 got you moving; Stage 2 makes you *shape* data — derive fields with
`eval`, extract with `rex`, count fast with `tstats`, and combine searches
with subsearches. These are the building blocks every hunt in Stage 4 leans on.

**Still scope your time** (v2 = 226M events). Use a single August-2017 day
for raw searches; use `tstats`/`metadata` when you only need counts.

> Solutions: [SOLUTIONS.md](SOLUTIONS.md) (Stage 2 section).

---

## `eval` — derive and transform

### Q16 — Calculated field + rounding
On the web logs, turn `bytes` into KB and show the biggest responses.
**Hint:** `… sourcetype=access_combined earliest=… latest=… | eval kb=round(bytes/1024,1) | sort - kb | table _time clientip uri kb`.

### Q17 — `case()` to classify HTTP status
Bucket every request into 2xx/3xx/4xx/5xx and count each.
**Hint:** `| eval class=case(status<300,"2xx",status<400,"3xx",status<500,"4xx",true(),"5xx") | stats count by class`. `case()` beats nested `if()` once you have 3+ buckets.

### Q18 — Conditional counting with `eval` inside `stats`
Count errors vs. total per client in one pass.
**Hint:** `| stats count as total count(eval(status>=400)) as errors by clientip | eval err_rate=round(errors/total*100,1) | sort - err_rate`. A high error rate from one IP = scanning/brute force.

### Q19 — String functions
Extract the host portion of the `Referer`/`useragent`, or lowercase a field for consistent grouping.
**Hint:** `| eval ua=lower(useragent) | stats count by ua`. Explore `len()`, `substr()`, `lower()`, `mvindex()`.

## `rex` — extract what isn't a field yet

### Q20 — Named-group extraction from a URI
Pull the first path segment and any query parameter.
**Hint:** `| rex field=uri "^/(?<section>[^/?]+)"` then `| rex field=uri "[?&]id=(?<id>[^&]+)"`. Own this pattern — it's how you field-ify raw logs.

### Q21 — `rex` on Sysmon CommandLine
On `sourcetype=*ysmon*` EventCode=1, extract the executable name out of `Image`.
**Hint:** `| rex field=Image "\\\\(?<exe>[^\\\\]+)$" | top exe`. (Backslashes in Windows paths need escaping in the regex.)

### Q22 — `rex` mode=sed to redact/normalize
Mask everything after `?` in a URI for cleaner grouping.
**Hint:** `| rex field=uri mode=sed "s/\?.*//" | stats count by uri`.

## `tstats` / `metadata` — fast at scale

### Q23 — `tstats` with a time chart
Count events per hour for a sourcetype *without* a slow raw search.
**Hint:** `| tstats count where index=botsv2 sourcetype=suricata by _time span=1h`. `tstats` reads the indexed fields — orders of magnitude faster on 226M events.

### Q24 — `metadata` for recon
When did each sourcetype first and last appear?
**Hint:** `| metadata type=sourcetypes index=botsv2 | eval firstTime=strftime(firstTime,"%F %T"), lastTime=strftime(lastTime,"%F %T") | table sourcetype totalCount firstTime lastTime recentTime`.

### Q25 — `tstats` grouped by two fields
Events by host **and** sourcetype, to see which host owns which telemetry.
**Hint:** `| tstats count where index=botsv2 by host sourcetype | sort - count`.

## Chaining & combining

### Q26 — Subsearch: pivot from one sourcetype to another
Find DNS queries made by whatever host was noisiest in Sysmon.
**Hint:**
```spl
index=botsv2 sourcetype=stream:dns [
  | tstats count where index=botsv2 sourcetype=*ysmon* by host
  | sort - count | head 1 | fields host ]
| stats count by query{}
```
The subsearch returns the top host and injects it as a filter. Keep subsearches small (they're capped).

### Q27 — `stats` then `eval` then `where`
Find clients whose error rate is high **and** volume is non-trivial.
**Hint:** `… | stats count as total count(eval(status>=400)) as errors by clientip | eval rate=errors/total | where total>100 AND rate>0.5`.

### Q28 — `eventstats` / `streamstats` for baselining
Flag requests from a client whose per-minute rate is far above the average.
**Hint:** `… | bin _time span=1m | stats count by _time clientip | eventstats avg(count) as avg stdev(count) as sd | where count > avg + 3*sd`. This z-score pattern is the seed of an anomaly detection (Stage 4).

### Q29 — `transaction` vs `stats` (know when to use which)
Group a client's requests into sessions by a 5-minute gap.
**Hint:** `… | transaction clientip maxpause=5m | eval dur=duration, n=eventcount`. Then reflect: `stats` is faster/cheaper — use `transaction` only when you truly need event grouping/ordering.

### Q30 — `lookup`-style enrichment with `iplocation`
Geo-locate the top external web clients.
**Hint:** `… sourcetype=access_combined earliest=… latest=… | iplocation clientip | stats count by clientip Country City | sort - count`. Foreign, high-volume clients are worth a second look.

---

**When Stage 2 is comfortable** (you reach for `eval`/`rex`/`tstats` without
looking them up), move to `03-log-analysis.md` — reading each v2 sourcetype
in depth.

➡️ [SOLUTIONS.md](SOLUTIONS.md)
