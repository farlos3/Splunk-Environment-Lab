# Solutions — Section 1 (Q1–Q14)

⚠️ **Last resort.** Try every problem honestly first.

> SPL below is written for **readability**, not maximum efficiency. The workshop dataset's "active window" depends on which date range the instructor uploaded — keep the time picker on **All time** if numbers don't match.

---

## Q1 — Explore the index with stats
```spl
index=* | stats count by index sourcetype, source
```
You should see `index=botsv1` rows for sourcetypes like `XmlWinEventLog`, `stream:http`, `mscs:azure:eventhub`, `o365`, etc. The number of distinct sourcetypes equals the row count in the result.

---

## Q2 — Compare speed with tstats
```spl
| tstats count WHERE index=* sourcetype=* BY index sourcetype summariesonly=true
```
Should run in **milliseconds** vs Q1's seconds. `summariesonly=true` queries indexed metadata only — no raw event scan. Returns the same per-(index, sourcetype) counts as Q1 minus the `source` dimension.

---

## Q3 — Inventory hosts with metadata
```spl
| metadata type=hosts index=botsv1
| eval firstTime = strftime(firstTime, "%F %T"),
       lastTime  = strftime(lastTime,  "%F %T"),
       recentTime= strftime(recentTime,"%F %T")
| table host firstTime lastTime recentTime totalCount
```
Variants: replace `type=hosts` with `type=sources` or `type=sourcetypes` for the other two inventories. `metadata` is the *fastest* way to enumerate these — faster than `stats values()`.

---

## Q4 — Timechart event volume
```spl
sourcetype=stream:http
| timechart span=1h count by status
```
Each color band = one HTTP status code over time. Spikes in `404` or `500` are immediate visual cues.

---

## Q5 — Top N
```spl
sourcetype=stream:http
| top limit=10 src_ip showperc=f
```
`showperc=f` removes the `percent` column. `useother=f` (not asked, but useful) removes the "OTHER" aggregate row.

---

## Q6 — Rare
```spl
sourcetype=stream:http
| rare limit=5 status
```
You'll likely see status codes like `301`, `403`, `503` — rare codes are excellent anomaly seeds.

---

## Q7 — Distinct count
```spl
source=XmlWinEventLog
| stats dc(EventCode) as unique_event_codes
```
Typically 30–80 unique codes depending on the workshop data subset. Common ones to expect: 4624, 4625, 4688, 4720, 4768, 4769.

---

## Q8 — Multiple aggregations
```spl
sourcetype=stream:http
| stats count, dc(dest_ip) as dc_dest_ip,
        sum(bytes) as total_bytes,
        avg(bytes) as avg_bytes
    by src_ip
| sort - count | head 10
```
One `stats` block, multiple functions — much faster than chaining 4 separate stats commands.

---

## Q9 — Sort ascending
```spl
sourcetype=stream:http
| stats count, dc(dest_ip) as dc_dest_ip,
        sum(bytes) as total_bytes,
        avg(bytes) as avg_bytes
    by src_ip
| sort + dc_dest_ip | head 5
```
Sources at the *bottom* of the ranking (few distinct destinations) are often single-purpose endpoints (proxies, gateways, internal services). High dc = scanner or normal user.

---

## Q10 — Reverse
```spl
sourcetype=stream:http
| head 20
| reverse
| table _time url status
```
Default Splunk order is newest → oldest. `| reverse` flips the *current set in the pipeline*, not the source data.

---

## Q11 — Table
```spl
source=XmlWinEventLog EventCode=4624
| table _time Computer TargetUserName IpAddress LogonType
```
`LogonType=2` = interactive, `=3` = network, `=10` = remote interactive — analysts memorize the common ones.

---

## Q12 — Dedup
```spl
source=XmlWinEventLog EventCode=4624
| dedup TargetUserName sortby +_time
| table _time TargetUserName Computer IpAddress
```
`sortby +_time` ensures you keep the *earliest* event per user, not the default last-event-seen.

---

## Q13 — iplocation
```spl
sourcetype="mscs:azure:eventhub"
| iplocation callerIpAddress
| stats count by Country City
| sort - count
```
`iplocation` ships with a built-in MaxMind GeoLite2 database in Splunk. No external API call.

---

## Q14 — Combine everything
```spl
index=botsv1
| stats count as total_events,
        dc(sourcetype) as unique_sourcetypes
    by host
| sort - total_events | head 5
| table host total_events unique_sourcetypes
```
This is the "host hot list" pattern — analysts run it daily to see which hosts produced the most telemetry overnight.

---

End Section 1 solutions
