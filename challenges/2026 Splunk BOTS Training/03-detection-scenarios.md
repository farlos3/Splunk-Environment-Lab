# Section 3 — Detection Scenarios (Q22–Q28)

🔴 **Level:** Applied
🎯 **Goal:** Combine the basic and intermediate SPL from Sections 1–2 into real detection logic.
Every scenario builds on (or extends) the two worked examples in the MD101 deck — Suspicious PowerShell and Impossible Travel.

---

## Scenario A — Suspicious PowerShell Execution

> 📖 *Reference: Example 1 in MD101*
> Assume host `WEBSERVER-01` was compromised and PowerShell is being launched with abnormally long command lines (encoded payload).

### Q22 — Find PowerShell with abnormally long command lines

In `source=XmlWinEventLog EventCode=4688`, find every event where `NewProcessName` ends in `powershell.exe` and `CommandLine` is longer than 150 characters. Return a table sorted by command-line length, descending, with `_time`, `Computer`, `SubjectUserName`, `cmd_length`, `CommandLine`.

**Hint:** Start with the SPL from the MD101 example, then try thresholds of 200 and 300 — observe how the result set changes.
**Skill:** filter + `eval len()` + `where` + `sort` + `table`

---

## Q23 — Pivot: find the parent processes of suspicious PowerShell

Extend Q22 by including `ParentProcessName` in the table, then answer: how many distinct parents launched those PowerShell instances, and which ones are interesting (e.g. `w3wp.exe`, `winword.exe`, `services.exe`)?

**Hint:** After the filter, pipe into `stats count by ParentProcessName | sort - count`.
**Skill:** pivot from raw events → aggregation to discover patterns

---

## Q24 — Add indicators: encoded command / base64 keywords

Extend Q22 to keep only PowerShell launches whose command line contains an obfuscation indicator — any of `-enc`, `-EncodedCommand`, `FromBase64String`, `IEX`, `DownloadString` (case-insensitive).

**Hint:** Put keywords directly in the search head (no eval needed):
```spl
source=XmlWinEventLog EventCode=4688 NewProcessName="*powershell.exe"
  (CommandLine="*-enc*" OR CommandLine="*EncodedCommand*"
   OR CommandLine="*FromBase64String*" OR CommandLine="*IEX*"
   OR CommandLine="*DownloadString*")
```
Then aggregate by `Computer` and `SubjectUserName`.
**Skill:** OR + wildcard + aggregation

---

## Scenario B — Impossible Travel (Cloud Identity)

> 📖 *Reference: Example 2 in MD101*
> A Microsoft 365 / Azure AD user logs in from two countries within the same minute → physically impossible → likely account compromise.

### Q25 — Successful sign-ins from multiple countries in one minute

In `sourcetype="mscs:azure:eventhub"` where `operationName="Sign-in activity"` and `status="Success"`:
1. Map `callerIpAddress` to a country via `iplocation`.
2. Bucket time into 1-minute windows with `bin span=1m _time`.
3. Find any identity that has logins from ≥ 2 countries in a single bucket.

Show `_time`, `identity`, `Unique_Countries`, `Login_Locations`, `Source_IPs`.

**Hint:** Start from the SPL in the MD101 example verbatim:
```spl
sourcetype="mscs:azure:eventhub" operationName="Sign-in activity" status="Success"
| iplocation callerIpAddress
| bin span=1m _time
| stats dc(Country) as Unique_Countries,
        values(Country) as Login_Locations,
        values(callerIpAddress) as Source_IPs
        by _time identity
| where Unique_Countries > 1
```
**Skill:** `iplocation` + `bin` + `stats values()` + threshold filter

---

## Q26 — Extend: compute the time gap between the two-country logins

For each user surfaced in Q25, compute `min(_time)` and `max(_time)` across all logins in scope, then `time_gap_seconds = max - min`. Return the top 10 users with the *smallest* gap (most "impossible" travel).

**Hint:**
```spl
... (continues from Q25) ...
| stats min(_time) as first, max(_time) as last,
        values(Country) as countries by identity
| eval gap_sec = last - first
| where mvcount(countries) > 1
| sort + gap_sec | head 10
```
**Skill:** `min/max(_time)` + `eval` arithmetic + `mvcount`

---

## Scenario C — Free-form IOC Hunting

### Q27 — Quick triage from a threat-intel IOC

Threat intel reports a suspicious IP `45.77.65.211` (example). Find which sourcetypes in `botsv1` reference that IP, with an event count per sourcetype.

**Hint:** Search the IP as a free-text literal (no `field=`) so Splunk hits every indexed field:
```spl
index=botsv1 45.77.65.211
| stats count by sourcetype
| sort - count
```
Then interpret the result: if you see 100 events in `stream:http` but only 5 in `stream:ip`, what does that imply?
**Skill:** free-text search + aggregation for triage

---

## Q28 — Correlate and summarize

Pick one suspicious host from Q22–Q24 (e.g. `WEBSERVER-01`, or whichever you surfaced). Build a **mini timeline** that mixes three sourcetypes for that host:
- `source=XmlWinEventLog` (process / logon)
- `sourcetype=stream:http` (network)
- `sourcetype="Script:InstalledApps"` (program install)

Order events oldest → newest with columns `_time`, `sourcetype`, `EventCode_or_status`, `summary`.

**Hint:** Use `eval summary = coalesce(CommandLine, url, AppName)` to fold heterogeneous fields into one column, then `| sort + _time`.
**Skill:** cross-sourcetype correlation + `coalesce` + timeline ordering

---

🎓 **End of workshop!**
If you completed all 28 without re-reading the MD101 examples, the full deck now lives in your head.
Next steps: try the [BOTS official walkthroughs](../splunk-bots/) or the [50-question self-practice pack](../self-practice/) for BOTS v1.
