# BOTS v2 — Stage 3: Log Analysis (Reading Every Sourcetype)

Now you read the actual security logs. v2 has **104 sourcetypes** across many
technologies — the skill is knowing *what each one tells you* and *how to get
fields out of it*. Crucial lesson up front:

> 🔑 **Not every sourcetype is field-extracted.** This lab ships no vendor
> TAs, so some sources give you clean fields and some are raw text you must
> `rex`. **Always check first:** `… sourcetype=X | head 1` and look at
> `_raw` vs. the field sidebar. Verified state below.

| Sourcetype | Format | Fields extracted? | How you read it |
|---|---|---|---|
| `access_combined` | Apache combined | ✅ yes | `clientip method uri status bytes useragent` |
| `wineventlog:security` | key=value | ✅ yes | `EventCode`, `ComputerName`, `Message` (e.g. 4688/4624/4625) |
| `xmlwineventlog:…sysmon…` | XML | ✅ via lab add-on | `EventCode`, `Image`, `CommandLine`, … |
| `stream:*` (dns/http/smb/…) | JSON | ✅ yes | JSON keys, e.g. `query{}`, `src_ip`, `dest_ip` |
| `suricata` | JSON | ✅ yes | `alert.signature`, `alert.category`, `src_ip` |
| `winregistry` | key=value | ✅ yes | `key_path`, `registry_type`, `data` |
| `pan:traffic` | **CSV** | ❌ no (no PAN TA) | **`rex`/positional** — comma-separated |
| `linux_secure`, `auditd` | syslog text | ❌ no | **`rex`** the message |
| `mysql:*`, `symantec:ep:*` | mixed | ❌ mostly no | inspect `_raw`, then `rex` |

> Solutions: [SOLUTIONS.md](SOLUTIONS.md) (Stage 3). Scope to a day (e.g. `08/24/2017`) — v2 is 226M events.

---

## Windows endpoint

### Q31 — Process creation (Windows 4688)
`wineventlog:security` logs process creation as EventCode 4688.
**Hint:** `index=botsv2 sourcetype=wineventlog:security EventCode=4688 earliest="08/24/2017:00:00:00" latest="08/25/2017:00:00:00" | stats count by ComputerName | sort - count`. Note `ComputerName` carries the `…frothly.local` FQDN.

### Q32 — Logon success/failure (4624 / 4625)
**Hint:** `sourcetype=wineventlog:security (EventCode=4624 OR EventCode=4625) | stats count by EventCode, ComputerName`. A 4625 spike on one host = credential attack.

### Q33 — Sysmon process detail
Sysmon (`*ysmon*`) gives you the `CommandLine` that 4688 often lacks here.
**Hint:** `sourcetype=*ysmon* EventCode=1 host=wrk-* | table _time host Image CommandLine ParentImage | sort _time`. Hunt scripting hosts / odd parents.

## Web & network (extracted)

### Q34 — Web request analysis
**Hint:** `sourcetype=access_combined earliest=… latest=… | stats count by status method | sort - count`; then look at `uri` for odd paths.

### Q35 — DNS via Splunk Stream (JSON)
**Hint:** `sourcetype=stream:dns | stats count by query{} | sort - count`. Group by `query{}` (the question, always present) — same rule as v1.

### Q36 — Suricata IDS alerts
**Hint:** `sourcetype=suricata alert.signature=* | stats count by alert.signature alert.category | sort - count`. You'll see scanning (port 135), TOR, and an **OSX backdoor** signature — pointers for Stage 4.

## The sources that need `rex` (no TA)

### Q37 — Palo Alto firewall (`pan:traffic`, CSV)
The log is raw CSV: `… ,TRAFFIC,end,…,<src_ip>,<dest_ip>,…,<src_user>,…,<app>,…`. There are no auto-fields.
**Hint:** read `_raw` first, then extract what you need, e.g. the source user and app:
`sourcetype=pan:traffic | rex "TRAFFIC,\w+,\d+,[^,]+,(?<src_ip>[^,]+),(?<dest_ip>[^,]+),[^,]+,[^,]+,[^,]+,(?<src_user>[^,]+)" | stats count by src_user`. Note the domain `frothly.local`.

### Q38 — Linux SSH brute force (`linux_secure`, syslog)
Raw syslog like `Failed password for root from 116.31.116.52 port 23301 ssh2`.
**Hint:** `sourcetype=linux_secure "Failed password" | rex "Failed password for (?:invalid user )?(?<user>\S+) from (?<src_ip>\S+)" | stats count by src_ip user | sort - count`. One external IP with hundreds of failures = brute force (verified: `116.31.116.52` hammering `gacrux`).

### Q39 — Linux auditd / osquery
**Hint:** `sourcetype=auditd | head 20` and `sourcetype=osquery_results | head 5` — inspect the shape, then decide what to `rex`/`spath`. `osquery_results` is JSON (use `spath`); `auditd` is key=value-ish.

### Q40 — MySQL activity
**Hint:** `sourcetype=stream:mysql | head 20` — DB queries on the wire. Look for the `query` field / raw SQL. Which host is the DB server? (`| tstats count where index=botsv2 sourcetype=mysql:* by host`).

## Putting sources together

### Q41 — Same event, two sources
Pick a process-creation moment on a workstation and view it from *both* `wineventlog:security` (4688) and Sysmon (EID 1). What does each give you that the other doesn't? (Sysmon → hashes/CommandLine; WinEventLog → account/logon context.)

### Q42 — Correlate a host across telemetry
For `wrk-bgist`, pull a slice of Sysmon + wineventlog + stream:dns in one window and read the story. **Hint:** `index=botsv2 host=wrk-bgist (sourcetype=*ysmon* OR sourcetype=wineventlog:security OR sourcetype=stream:dns) earliest=… latest=… | sort _time | table _time sourcetype EventCode Image query{}`.

### Q43 — Which host is which? Build an asset picture
**Hint:** `| tstats count where index=botsv2 by host sourcetype`, then infer roles: `cassiopeia`/`venus`/`jupiter` (servers — perfmon/mysql/pan), `wrk-*` (workstations — Sysmon), and two Macs `maclory-air13` + `kutekitten` (both carry `osquery_results`) — `kutekitten` (`10.0.4.2`) is the OSX-backdoor host.

---

**When you can open any v2 sourcetype and know how to read it** (and which
need `rex`), you're ready for **Stage 4** → [`../../specialized/botsv2/`](../../specialized/botsv2/): the froth.ly APT, hunted end-to-end.

➡️ [SOLUTIONS.md](SOLUTIONS.md)
