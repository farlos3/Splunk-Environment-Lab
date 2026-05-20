# Section 1 — Splunk Fundamentals (Q1–Q15)

🟢 **Level:** Beginner
🎯 **Goal:** Get comfortable with core SPL syntax, navigation in Splunk Web, and basic filtering / counting / display.

> **Time picker:** `8/10/2016 00:00:00` → `8/11/2016 00:00:00` (24 hours)
>
> One day of BOTS v1 already contains hundreds of thousands of events —
> more than enough to practice every SPL pattern in this section, and
> searches return in seconds instead of minutes.

---

## Q1 — Explore the index

How many distinct sourcetypes exist in the `botsv1` index, and what are they?

**Hint:** `| stats count by sourcetype` or `| top sourcetype`
**Skill:** basic search + stats

---

## Q2 — Total event count

How many events are in the `botsv1` index in total?

**Hint:** `| stats count`
**Skill:** stats count

---

## Q3 — Source diversity

Inside sourcetype `stream:http`, how many distinct `source` values are there?

**Hint:** `| stats dc(source)` — `dc` stands for *distinct count*
**Skill:** distinct count

---

## Q4 — Dataset time bounds

What are the earliest and latest event timestamps in `botsv1`?

> ⚠️ **For this question only**, temporarily widen the time picker to
> `8/10/2016 00:00:00` → `8/27/2016 00:00:00` (so you actually see the
> dataset bounds, not just the bounds of your current window).
> Reset back to the 1-day window after.

**Hint:** `| stats earliest(_time) latest(_time)`, then convert with `eval ... strftime(...)`
**Skill:** time functions, eval + strftime

---

## Q5 — Top source IPs

Find the top 5 source IPs (`src_ip`) by HTTP traffic volume.

**Hint:** `sourcetype=stream:http | top limit=5 src_ip`
**Skill:** the `top` command

---

## Q6 — Unique destinations

How many unique `dest_ip` values appear in `stream:http`?

**Hint:** `| stats dc(dest_ip)`
**Skill:** distinct count

---

## Q7 — HTTP errors

How many HTTP requests returned status `404`?

**Hint:** `sourcetype=stream:http status=404 | stats count`
**Skill:** field filtering

---

## Q8 — Events per hour

Plot the count of `stream:http` events bucketed per hour.

**Hint:** `| timechart span=1h count`
**Skill:** timechart

---

## Q9 — Top User-Agents

What are the top 5 `http_user_agent` strings in `stream:http`?

**Hint:** `| top limit=5 http_user_agent`
**Skill:** field analysis

---

## Q10 — Path substring search

How many HTTP requests have `uri_path` that contains the word `admin` (any case)?

**Hint:** wildcard match — `uri_path="*admin*"`
**Skill:** wildcard search

---

## Q11 — Regex extraction with `rex`

From `sourcetype=stream:http`, extract just the **first path segment** of
`uri_path` (the part before the second `/`). For example,
`/admin/login.php` → extract `admin`. Show the top 10 first-segments.

**Hint:**
```spl
| rex field=uri_path "^/(?<first_dir>[^/]+)"
| top first_dir
```
**Skill:** `rex` (regex field extraction)

---

## Q12 — Distinct values

What HTTP methods are present (GET, POST, ...) and how often does each appear?

**Hint:** `| stats count by http_method`
**Skill:** stats count by

---

## Q13 — Sort and limit

Show the 10 HTTP requests with the highest `bytes_out`. Display
`src_ip`, `dest_ip`, `bytes_out`, and `uri_path`.

**Hint:** `| sort - bytes_out | head 10 | table ...`
**Skill:** sort, head, table

---

## Q14 — `eval` with aggregation

Create a new field `total_bytes = bytes_in + bytes_out`, then find the 5
source IPs with the highest combined traffic.

**Hint:**
```spl
| eval total_bytes=bytes_in+bytes_out
| stats sum(total_bytes) as total by src_ip
| sort - total | head 5
```
**Skill:** eval + aggregation

---

## Q15 — Compound filter

Find HTTP requests that match **all** of these conditions:
- `http_method = POST`
- `status = 200`
- `uri_path` contains `login`

Display: `_time`, `src_ip`, `dest_ip`, `uri_path`.

**Hint:**
```spl
sourcetype=stream:http http_method=POST status=200 uri_path="*login*"
| table _time src_ip dest_ip uri_path
```
**Skill:** compound filtering + table

---

✅ Finished all 15? Continue to → [02-security-log-analysis.md](02-security-log-analysis.md)
