# Section 2 — Intermediate SPL: `eval` & `rex` (Q15–Q21)

🟡 **Level:** Intermediate
🎯 **Goal:** Use `eval` (in all three forms: plain expression, `if`, `case`) and `rex` to create and transform fields for analysis.

> These two commands are the glue between Section 1's basic commands and real security questions — every exercise in Section 3 leans on them.

---

## Q15 — Plain eval expression

In `sourcetype=stream:http`, create a new field `kb = bytes / 1024` (convert bytes to KB), then show the top 10 `src_ip` by `sum(kb)`.

**Hint:** `| eval kb = bytes/1024 | stats sum(kb) as total_kb by src_ip | sort - total_kb | head 10`
**Skill:** `eval <new> = <expression>`

---

## Q16 — eval + if to classify

In `sourcetype=stream:http`, create a field `is_error` that is `"yes"` when `status >= 400`, otherwise `"no"`. Count events per `is_error`.

**Hint:** `| eval is_error = if(status>=400, "yes", "no") | stats count by is_error`
**Skill:** `eval ... = if(<cond>, <a>, <b>)`

---

## Q17 — eval + case to bucket HTTP status

In `sourcetype=stream:http`, use `case()` to bucket `status` codes:
- 1xx → `"informational"`
- 2xx → `"success"`
- 3xx → `"redirect"`
- 4xx → `"client_error"`
- 5xx → `"server_error"`

Then count events per category.

**Hint:** `| eval category = case(status<200,"informational", status<300,"success", status<400,"redirect", status<500,"client_error", true(),"server_error") | stats count by category`
**Skill:** `eval ... = case(...)` (always close with `true(), <default>`)

---

## Q18 — rex to extract a username

In `source=XmlWinEventLog EventCode=4625` (failed logon), some events do not surface a clean `TargetUserName` field, but the raw message contains a line like `Account Name: bob.smith`. Use `rex` to extract that name as a new field `extracted_user`, then show the top 10 users by failed-logon count.

**Hint:** `| rex field=_raw "Account Name:\s+(?<extracted_user>\S+)" | top limit=10 extracted_user`
**Skill:** `rex field=<f> "<regex with a named capture group>"`

---

## Q19 — rex to split URL → path + query

In `sourcetype=stream:http`, use `rex` to extract just the path portion (everything before the `?`) from the `url` field, then find the top 10 most-requested paths.

**Hint:** `| rex field=url "^(?<path>[^?]+)" | top limit=10 path`
**Skill:** `rex` with the `[^?]+` negation character class

---

## Q20 — Chain eval and rex

In `source=XmlWinEventLog EventCode=4688` (process create):
1. Use `rex` to extract just the *file name* from `NewProcessName` (e.g. `C:\Windows\System32\cmd.exe` → `cmd.exe`).
2. Use `eval` to compute the length of `CommandLine` as `cmd_len`.
3. Show the 20 processes with the longest command lines, with columns `_time`, `Computer`, `process_name`, `cmd_len`, `CommandLine`.

**Hint:**
```spl
| rex field=NewProcessName "\\\\(?<process_name>[^\\\\]+)$"
| eval cmd_len = len(CommandLine)
| sort - cmd_len | head 20
| table _time Computer process_name cmd_len CommandLine
```
**Skill:** chain `rex` → `eval` → `sort` → `table`

---

## Q21 — eval as a simple risk score

In `source=XmlWinEventLog EventCode=4625` (failed logon), for every `src_ip` compute a score:
- count of failures
- + (distinct usernames × 5)

Return the top 10 source IPs by score.

**Hint:**
```spl
source=XmlWinEventLog EventCode=4625
| stats count as fails, dc(TargetUserName) as users by IpAddress
| eval score = fails + (users * 5)
| sort - score | head 10
```
Ask yourself: *why* is user-spray weighted heavier than a flat failure count?
**Skill:** designing a risk metric with `eval`

---

✅ End of Section 2 — at this point you can use SPL to tell a multi-step "story" about the data. Continue to [Section 3 →](03-detection-scenarios.md)
