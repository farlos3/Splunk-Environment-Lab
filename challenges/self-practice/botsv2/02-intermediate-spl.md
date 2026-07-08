# BOTS v2 — Stage 2: Intermediate SPL

Stage 1 got you moving; Stage 2 makes you *shape* data — derive fields with
`eval`, extract with `rex`, count fast with `tstats`, and combine searches
with subsearches. These are the building blocks every hunt in Stage 4 leans on.

**Still scope your time** (v2 = 226M events). Use a single August-2017 day
for raw searches; use `tstats`/`metadata` when you only need counts.

⏱ **Time picker — Stage 2**

| Questions | Time picker |
|---|---|
| Q28–Q31 (`tstats` / `metadata` / subsearch) | **All time** (fast) |
| Q26 (Sysmon `rex` on `Image`) | `08/24/2017 00:00:00` → `08/25/2017 00:00:00` |
| Q21–Q25, Q27, Q32–Q39 (web logs) | `08/23/2017 00:00:00` → `08/24/2017 00:00:00` |
| Q40 (SQLi flag — spans the attack) | `08/23/2017 00:00:00` → `08/26/2017 00:00:00` |

> **Hints are nudges, not answers** — they point at the commands and shape.
> Write the SPL yourself; the full query + verified result is in
> [SOLUTIONS.md](SOLUTIONS.md) (Stage 2), for a last resort.

---

## `eval` — derive and transform

### Q21 — Calculated field + rounding
On `sourcetype=access_combined`, turn `bytes` into KB and show the biggest responses.
**Hint:** `eval` a new `kb` field with `round(bytes/1024,1)`, `sort` descending on it, then `table` the columns you want.

### Q22 — `case()` to classify HTTP status
On `sourcetype=access_combined`, bucket every request into 2xx/3xx/4xx/5xx and count each.
**Hint:** `eval` a `class` field with `case(status<300,"2xx", status<400,"3xx", …)`, then `stats count by class`. `case()` beats nested `if()` once you have 3+ buckets. ⚠️ The `true()` catch-all silently swallows null `status` — see Q37.

### Q23 — Conditional counting with `eval` inside `stats`
On `sourcetype=access_combined`, count errors vs. total per client in one pass.
**Hint:** Inside one `stats`, put a plain `count` (total) next to `count(eval(status>=400))` (just the errors), grouped by `clientip`; then `eval` an `err_rate`. One pass, no subsearch. A high error rate from one IP = scanning/brute force.

### Q24 — String functions
On `sourcetype=access_combined`, extract the host portion of the `Referer`/`useragent`, or lowercase a field for consistent grouping.
**Hint:** `eval` with `lower(useragent)` normalizes case before you `stats count by` it. Explore `len()`, `substr()`, `lower()`, `mvindex()`.

## `rex` — extract what isn't a field yet

### Q25 — Named-group extraction from a URI
On `sourcetype=access_combined`, pull the first path segment and any query parameter out of `uri`.
**Hint:** Two `rex field=uri` passes — one named group capturing the first `/segment`, one capturing the value after `id=`. Own this pattern — it's how you field-ify raw logs.

### Q26 — `rex` on Sysmon CommandLine
On `sourcetype=*ysmon*` EventCode=1, extract the executable name out of `Image`.
**Hint:** `rex field=Image` capturing everything after the last backslash, then `top` the result. The gotcha: backslashes are regex-special *and* SPL-string-special, so they need double-escaping.

### Q27 — `rex` mode=sed to redact/normalize
On `sourcetype=access_combined`, mask everything after `?` in `uri` for cleaner grouping.
**Hint:** `rex ... mode=sed` with a substitution that deletes from `?` to end, then `stats count by uri` — collapses `/x?id=1` and `/x?id=2` into `/x`.

## `tstats` / `metadata` — fast at scale

### Q28 — `tstats` with a time chart
Count events per hour for `sourcetype=suricata`, *without* a slow raw search.
**Hint:** `tstats count … by _time span=1h`. `tstats` reads the indexed fields — orders of magnitude faster than a raw `timechart` on 226M events.

### Q29 — `metadata` for recon
When did each sourcetype first and last appear?
**Hint:** `metadata type=sourcetypes index=botsv2`, then `strftime` the `firstTime`/`lastTime` epoch fields so they're readable.

### Q30 — `tstats` grouped by two fields
Events by host **and** sourcetype, to see which host owns which telemetry.
**Hint:** `tstats count … by host sourcetype`, `sort` descending.

## Chaining & combining

### Q31 — Subsearch: pivot from one sourcetype to another
Find DNS queries made by whatever host was noisiest in Sysmon.
**Hint:** A subsearch in `[ … ]` runs *first* and returns a filter. Put a `tstats … by host | sort - count | head 1 | fields host` inside so it resolves the top Sysmon host and injects it into the outer `stream:dns` search. Keep subsearches small — they're row/time-capped.

### Q32 — `stats` then `eval` then `where`
On `sourcetype=access_combined`, find clients whose error rate is high **and** volume is non-trivial.
**Hint:** Build the same error-rate `stats` as Q23, then `where` filters *after* aggregation on the computed fields (e.g. `total>100 AND rate>0.5`) — different from `search`, which filters raw events before `stats`.

### Q33 — `eventstats` / `streamstats` for baselining
On `sourcetype=access_combined`, flag requests from a client whose per-minute rate is far above the average.
**Hint:** `bin _time span=1m`, `stats count by _time clientip`, then `eventstats avg`/`stdev` to add the baseline onto *every* row so you can `where count > avg + 3*sd`. That z-score is the seed of an anomaly detection (Stage 4).

### Q34 — `transaction` vs `stats` (know when to use which)
On `sourcetype=access_combined`, group a client's requests into sessions by a 5-minute gap.
**Hint:** `transaction clientip maxpause=5m` groups events into sessions with `duration`/`eventcount`. Then reflect: `stats` is faster/cheaper — reach for `transaction` only when you truly need event grouping/ordering.

### Q35 — `lookup`-style enrichment with `iplocation`
On `sourcetype=access_combined`, geo-locate the top external web clients.
**Hint:** `iplocation clientip` adds `Country`/`City` fields; `stats count by` them and `sort`. Foreign, high-volume clients are worth a second look.

## More `eval` / aggregation drills

### Q36 — Time-of-day with `strftime`
Which hour of the day is busiest on the web server? Use `08/23/2017 00:00:00` → `08/24/2017 00:00:00` and derive the hour from `_time`.
**Hint:** `eval hour=strftime(_time,"%H")`, then `stats count by hour | sort - count`. (`strptime` is the inverse — string → epoch.)

### Q37 — Null-field awareness (a real v2 trap)
Not every `access_combined` event has a `status`. On the same `08/23/2017` window, count how many are **missing** it.
**Hint:** `count(status)` counts only rows where the field exists; a plain `count` counts all — subtract to get the missing total. That gap (~41,742 on 08/23) is exactly why `stats count by status` and a `case()`/`true()` catch-all (Q22) silently mislead — gate on `status=*` when the value drives a metric.

### Q38 — `values()` + `dc()` together
On `sourcetype=access_combined`, for each web client, list the HTTP methods it used and how many distinct URIs it touched — a one-line scanner profile.
**Hint:** One `stats` by `clientip` carrying `dc(uri)`, `values(method)`, and `count`; `sort` by the distinct-URI count. A client with high `uris` and both `GET`+`POST` is crawling the app.

### Q39 — `streamstats` running total
On `sourcetype=access_combined`, add a cumulative event count over time (unlike `eventstats`, which adds one global aggregate to every row).
**Hint:** `bin` into hourly buckets, `stats count by _time`, then `streamstats sum(count)` for a cumulative column. `streamstats` computes *as it walks the rows* — great for running totals / "first N so far" logic.

### Q40 — `match()` to build a boolean flag
Flag SQL-injection-looking requests to `www.brewertalk.com` from the scanner and count them.
**Hint:** ⚠️ **Different sourcetype from the rest of this stage** — use `sourcetype=stream:http`, not `access_combined`. `brewertalk.com` is an external site, not Frothly's own hosted app, so it never shows up in `access_combined` (that sourcetype only covers Frothly's own web server's request log); Stream's wire-level capture is what actually saw the traffic. Scope to the scanner's `src_ip` first, then `eval` a flag with `if(match(form_data,"(?i)updatexml|union.*select"),1,0)` and `sum()` it. `match(field,"regex")` returns true/false. Scope to the attacker IP — `match()` over the whole web index drowns in noise and can misfire on a multivalue `form_data`. (~136 hits — the `updatexml` error-based injection on `/member.php`.)

---

**When Stage 2 is comfortable** (you reach for `eval`/`rex`/`tstats` without
looking them up), move to `03-log-analysis.md` — reading each v2 sourcetype
in depth.

➡️ [SOLUTIONS.md](SOLUTIONS.md)
