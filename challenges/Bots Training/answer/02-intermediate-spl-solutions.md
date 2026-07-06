# Solutions — Section 2 (Q15–Q21)

⚠️ **Last resort.** Try every problem honestly first.

---

## Q15 — eval expression
```spl
sourcetype=stream:http
| eval kb = bytes/1024
| stats sum(kb) as total_kb by src_ip
| sort - total_kb | head 10
```
`eval` runs on every event before aggregation. The order matters: if you put `stats sum(bytes)` first then `eval kb = bytes/1024` after, you'd be dividing the aggregated bytes — same answer here, but in other cases this difference is the bug.

---

## Q16 — eval + if
```spl
sourcetype=stream:http
| eval is_error = if(status>=400, "yes", "no")
| stats count by is_error
```
`if(<cond>, <true_val>, <false_val>)`. Returns 2 rows. Add `| eval pct = round(count/sum(count)*100, 1)` (after a streamstats) to compute error percentage — useful exercise.

---

## Q17 — eval + case
```spl
sourcetype=stream:http
| eval category = case(
    status<200, "informational",
    status<300, "success",
    status<400, "redirect",
    status<500, "client_error",
    true(), "server_error")
| stats count by category
```
`case()` evaluates conditions in order, top-to-bottom — first match wins. The final `true(), <default>` is the **catch-all** — omitting it is a common bug (events that match no condition get NULL).

---

## Q18 — rex username
```spl
source=XmlWinEventLog EventCode=4625
| rex field=_raw "Account Name:\s+(?<extracted_user>\S+)"
| where isnotnull(extracted_user)
| top limit=10 extracted_user
```
The 4625 event has *two* "Account Name" lines (subject + target). `rex` by default returns only the **first** match. If you want the target, use `rex max_match=2` and `mvindex(extracted_user, 1)`.

---

## Q19 — rex URL path
```spl
sourcetype=stream:http
| rex field=url "^(?<path>[^?]+)"
| top limit=10 path
```
The character class `[^?]+` matches "one or more characters that are not `?`". For URLs without a query string the pattern just consumes the whole URL — that's fine, you get the URL itself as `path`.

---

## Q20 — Chain eval + rex
```spl
source=XmlWinEventLog EventCode=4688
| rex field=NewProcessName "\\\\(?<process_name>[^\\\\]+)$"
| eval cmd_len = len(CommandLine)
| sort - cmd_len | head 20
| table _time Computer process_name cmd_len CommandLine
```
The `\\\\` in SPL = literal `\\` in regex = single backslash in the text being matched. Splunk's escaping levels are: SPL → regex → string. Hence 4 backslashes in source to match one in a Windows path.

---

## Q21 — Risk score
```spl
source=XmlWinEventLog EventCode=4625
| stats count as fails, dc(TargetUserName) as users by IpAddress
| eval score = fails + (users * 5)
| sort - score | head 10
```
**Why weight `users` heavier:** 200 failures from one IP against one user = a misconfigured script or forgotten password. 200 failures spread across 50 users = password spraying — a deliberate, more-dangerous attack pattern (one password tried against many accounts, evading per-account lockout policies).

---

End Section 2 solutions
