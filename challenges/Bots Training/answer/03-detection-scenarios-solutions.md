# Solutions — Section 3 (Q22–Q28)

⚠️ **Last resort.** Try every problem honestly first.

> Section 3 is scenario-driven — multiple SPL paths can reach a valid answer. The queries below are *one* idiomatic shape per question.

---

## Scenario A — Suspicious PowerShell Execution

### Q22 — Long-command-line PowerShell
```spl
source=XmlWinEventLog EventCode=4688 NewProcessName="*powershell.exe"
| eval cmd_length = len(CommandLine)
| where cmd_length > 150
| sort - cmd_length
| table _time Computer SubjectUserName cmd_length CommandLine
```
The MD101 deck uses 150 as the threshold. In production, baseline your own environment — legitimate management scripts can be 300+ chars. The signal is *unusual length*, not *any length*.

---

### Q23 — Parent process pivot
```spl
source=XmlWinEventLog EventCode=4688 NewProcessName="*powershell.exe"
| eval cmd_length = len(CommandLine)
| where cmd_length > 150
| stats count by ParentProcessName
| sort - count
```
Interesting parents to look for:
- `w3wp.exe` → web shell on IIS
- `winword.exe` / `excel.exe` → macro-based phishing
- `services.exe` → scheduled task / service abuse
- `cmd.exe` → manual operator
- `explorer.exe` → direct user execution (least suspicious)

---

### Q24 — Encoded command indicators
```spl
source=XmlWinEventLog EventCode=4688 NewProcessName="*powershell.exe"
  (CommandLine="*-enc*" OR CommandLine="*EncodedCommand*"
   OR CommandLine="*FromBase64String*" OR CommandLine="*IEX*"
   OR CommandLine="*DownloadString*")
| stats count, values(CommandLine) as cmds
    by Computer SubjectUserName
| sort - count
```
Splunk wildcard search is case-insensitive by default — `*-enc*` matches `-EncodedCommand`, `-EncodedCommand`, `-Enc`, etc. (`match()` regex inside `where` is case-sensitive — different beast.)

---

## Scenario B — Impossible Travel

### Q25 — Multi-country sign-in in 1 minute
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
`bin span=1m _time` rounds each event's `_time` to the start of its 1-minute window. After that `stats by _time identity` aggregates per-user-per-minute. Without `bin`, every event has its own unique timestamp and the `stats` returns one row per event = useless.

---

### Q26 — Compute travel time gap
```spl
sourcetype="mscs:azure:eventhub" operationName="Sign-in activity" status="Success"
| iplocation callerIpAddress
| stats min(_time) as first, max(_time) as last,
        values(Country) as countries by identity
| eval gap_sec = last - first
| where mvcount(countries) > 1
| sort + gap_sec | head 10
| eval first = strftime(first, "%F %T"),
       last  = strftime(last,  "%F %T")
| table identity countries gap_sec first last
```
`mvcount(countries)` counts the number of values in the multivalue `countries` field — equivalent to `dc(Country)` from Q25. Smaller `gap_sec` = more impossible.

---

## Scenario C — IOC Hunting

### Q27 — Quick IOC triage
```spl
index=botsv1 45.77.65.211
| stats count by sourcetype
| sort - count
```
**Interpretation:** if `stream:http` has 100 hits and `stream:ip` has only 5 → the IOC saw most of its traffic on HTTP (web traffic). If `stream:dns` is also non-zero → at some point this IP was looked up by name. The sourcetype breakdown tells you *what kind* of communication the attacker had with your environment.

---

### Q28 — Mini timeline
```spl
(source=XmlWinEventLog Computer=WEBSERVER-01)
OR (sourcetype=stream:http host=WEBSERVER-01)
OR (sourcetype="Script:InstalledApps" host=WEBSERVER-01)
| eval sourcetype_or_source = coalesce(sourcetype, source),
       summary = coalesce(CommandLine, url, AppName, "(no summary field)"),
       event_id = coalesce(EventCode, status, "")
| sort + _time
| table _time sourcetype_or_source event_id summary
```
`coalesce()` returns the first non-null value among its arguments — a clean way to fold differently-named fields from heterogeneous sources into one display column. The result is a single chronological story across process / network / install events.

---

End Section 3 solutions
