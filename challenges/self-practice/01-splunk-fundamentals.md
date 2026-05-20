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

**Hint:** Splunk tags every event with a `sourcetype`. To enumerate the values of any field and see how many events fall under each, reach for `stats count by ...` or the `top` command.
**Skill:** basic search + stats

---

## Q2 — Total event count

How many events are in the `botsv1` index in total?

**Hint:** `stats count` without a `by` clause aggregates over every event the search returns.
**Skill:** stats count

---

## Q3 — Source diversity

Inside sourcetype `stream:http`, how many distinct `source` values are there?

**Hint:** `stats` exposes a family of aggregation functions. The one for "how many unique values" is `dc(...)` — short for *distinct count*.
**Skill:** distinct count

---

## Q4 — Dataset time bounds

What are the earliest and latest event timestamps in `botsv1`?

> ⚠️ **For this question only**, temporarily widen the time picker to
> `8/10/2016 00:00:00` → `8/27/2016 00:00:00` (so you actually see the
> dataset bounds, not just the bounds of your current window).
> Reset back to the 1-day window after.

**Hint:** `earliest()` and `latest()` are stats functions that work on any field, including `_time`. The result is a Unix epoch — convert it to a readable string with `strftime()` inside `eval`.
**Skill:** time functions, eval + strftime

---

## Q5 — Top source IPs

Find the top 5 source IPs (`src_ip`) by HTTP traffic volume.

**Hint:** The `top` command ranks a field's values by frequency. It accepts a `limit=` argument for the cutoff.
**Skill:** the `top` command

---

## Q6 — Unique destinations

How many unique `dest_ip` values appear in `stream:http`?

**Hint:** Same idea as Q3 — different field.
**Skill:** distinct count

---

## Q7 — HTTP errors

How many HTTP requests returned status `404`?

**Hint:** Splunk treats space-separated `key=value` tokens in the search bar as implicit field filters — combine that with a count.
**Skill:** field filtering

---

## Q8 — Events per hour

Plot the count of `stream:http` events bucketed per hour.

**Hint:** `timechart` plots a metric over `_time`. The bucket size is controlled by `span=`.
**Skill:** timechart

---

## Q9 — Top User-Agents

What are the top 5 `http_user_agent` strings in `stream:http`?

**Hint:** Same shape as Q5.
**Skill:** field analysis

---

## Q10 — Path substring search

How many HTTP requests have `uri_path` that contains the word `admin` (any case)?

**Hint:** Splunk treats `*` inside a quoted field value as a wildcard. Splunk's default matching is case-insensitive, so you don't need to do anything extra for that.
**Skill:** wildcard search

---

## Q11 — Regex extraction with `rex`

From `sourcetype=stream:http`, extract just the **first path segment** of
`uri_path` (the part before the second `/`). For example,
`/admin/login.php` → extract `admin`. Show the top 10 first-segments.

**Hint:** Use `rex field=<...>` with a named capture group `(?<name>...)`. The regex needs to anchor on the leading `/` and capture everything up to (but not including) the next `/`.
**Skill:** `rex` (regex field extraction)

---

## Q12 — Distinct values

What HTTP methods are present (GET, POST, ...) and how often does each appear?

**Hint:** "How often does each value appear" is the canonical use of `stats count by <field>`.
**Skill:** stats count by

---

## Q13 — Sort and limit

Show the 10 HTTP requests with the highest `bytes_out`. Display
`src_ip`, `dest_ip`, `bytes_out`, and `uri_path`.

**Hint:** Three commands chained: sort the events (a `-` prefix on the field means descending), trim to 10, then pick the columns to display.
**Skill:** sort, head, table

---

## Q14 — `eval` with aggregation

Create a new field `total_bytes = bytes_in + bytes_out`, then find the 5
source IPs with the highest combined traffic.

**Hint:** Three stages — derive the new field with `eval`, aggregate the sum per source IP, then rank and trim. `stats` supports `as <alias>` to rename outputs, which makes the next `sort` easier.
**Skill:** eval + aggregation

---

## Q15 — Compound filter

Find HTTP requests that match **all** of these conditions:
- `http_method = POST`
- `status = 200`
- `uri_path` contains `login`

Display: `_time`, `src_ip`, `dest_ip`, `uri_path`.

**Hint:** Stack the three filters in the search bar — space between filters is implicit AND. Then pipe to `table` for the columns you want.
**Skill:** compound filtering + table

---

✅ Finished all 15? Continue to → [02-security-log-analysis.md](02-security-log-analysis.md)
