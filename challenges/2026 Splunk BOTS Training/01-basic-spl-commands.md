# Section 1 — Basic SPL Commands (Q1–Q14)

🟢 **Level:** Beginner
🎯 **Goal:** Drill each basic command in isolation (one+ exercise per command) so the syntax is automatic before you combine them in Section 2.

> **Time picker:** start with **All time**. If a search is slow, narrow `earliest` / `latest` to the active window of the workshop dataset.

---

## Q1 — Explore the index with stats

In `index=botsv1`, how many sourcetypes and sources exist? Show the result as a 3-column table: `index`, `sourcetype`, `source`, each with its event count.

**Hint:** Use the example from the slide deck — `index=* | stats count by index sourcetype, source`.
**Skill:** `stats count by <multi-fields>`

---

## Q2 — Compare speed with tstats

Write the same query as Q1 (event count grouped by `index` and `sourcetype`), but using `tstats` so it runs on indexed metadata only.

**Hint:** `| tstats count WHERE index=* sourcetype=* BY index sourcetype summariesonly=true`. Compare its runtime against Q1.
**Skill:** `tstats`, `summariesonly`

---

## Q3 — Inventory hosts and sourcetypes with metadata

Use `| metadata` to list every host sending logs into `botsv1`, including the `firstTime` and `lastTime` each host was seen.

**Hint:** `| metadata type=hosts index=botsv1`. Swap `type=` to `sources` or `sourcetypes` to inventory those too.
**Skill:** `metadata` command

---

## Q4 — Timechart event volume

Draw a time-series chart of `sourcetype=stream:http` event counts, broken down by `status`, with one bucket per hour.

**Hint:** `| timechart span=1h count by status`
**Skill:** `timechart` + `span` + `by`

---

## Q5 — Top N most frequent values

In `sourcetype=stream:http`, find the top 10 `src_ip` values by request count, with the percent column hidden.

**Hint:** `| top limit=10 src_ip showperc=f`
**Skill:** `top` command + arguments

---

## Q6 — Rare to surface anomalies

In `sourcetype=stream:http`, find the 5 least frequent HTTP `status` codes (these often hint at errors or unusual behavior).

**Hint:** `| rare limit=5 status`
**Skill:** `rare` command

---

## Q7 — Distinct count with stats

In `source=XmlWinEventLog`, how many distinct `EventCode` values exist in total?

**Hint:** `stats` has a `dc()` function — distinct count.
**Skill:** `stats dc(<field>)`

---

## Q8 — Multiple aggregations in one stats

In `sourcetype=stream:http`, for each `src_ip` compute: total request count (`count`), distinct destinations (`dc`), total bytes (`sum`), and average bytes (`avg`). Show the top 10 by count.

**Hint:** Put `count`, `dc()`, `sum()`, `avg()` inside one `stats` (separated by spaces), then add `by src_ip`, then `| sort - count | head 10`.
**Skill:** multi-function `stats`

---

## Q9 — Sort ascending vs descending

Using the result of Q8, sort by `dc_dest_ip` (the alias you set) from low to high, and show only the bottom 5.

**Hint:** `| sort + dc_dest_ip | head 5` — `+` is ascending, `-` is descending.
**Skill:** `sort` direction

---

## Q10 — Reverse the event order

In `sourcetype=stream:http`, take the 20 most recent events and flip the order so the oldest of those 20 appears first.

**Hint:** Splunk's default order is newest → oldest. `| head 20 | reverse` flips it.
**Skill:** `reverse`

---

## Q11 — Pick columns with table

In `source=XmlWinEventLog EventCode=4624` (successful logon), display only the columns `_time`, `Computer`, `TargetUserName`, `IpAddress`, `LogonType`.

**Hint:** `| table _time Computer TargetUserName IpAddress LogonType`
**Skill:** `table` command

---

## Q12 — Dedup to drop repeats

In `source=XmlWinEventLog EventCode=4624`, show a list of unique `TargetUserName` values along with the `_time` of the first logon seen for each.

**Hint:** `| dedup TargetUserName` keeps the first event by default. Try adding `sortby +_time` and observe how the result changes.
**Skill:** `dedup` + `sortby`

---

## Q13 — iplocation: IP → country

In `sourcetype="mscs:azure:eventhub"` events that have a `callerIpAddress` field, map the IP to country and city, then count sign-ins per country.

**Hint:** `| iplocation callerIpAddress | stats count by Country City`
**Skill:** `iplocation`

---

## Q14 — Combine the basic commands

Find the top 5 hosts in `botsv1` by total event count, and for each show how many distinct sourcetypes it produced. Return a table sorted by `total_events` descending.

**Hint:** `stats count as total_events, dc(sourcetype) as unique_sourcetypes by host | sort - total_events | head 5 | table host total_events unique_sourcetypes`
**Skill:** multi-function `stats` + `sort` + `head` + `table`

---

✅ End of Section 1 — if you can write all 14 without peeking at the cheat sheet, the basics are wired in. Continue to [Section 2 →](02-intermediate-spl.md)
