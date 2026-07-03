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
| `stream:*` (dns/http/smb/smtp/ftp/tcp) | JSON | ✅ yes | JSON keys, e.g. `query{}`, `src_ip`, `dest_ip`, `filename` |
| `suricata` | JSON | ✅ yes | `alert.signature`, `alert.category`, `src_ip` |
| `winregistry` | key=value | ✅ yes | `key_path`, `registry_type`, `data` |
| `symantec:ep:*` | CSV-ish | ✅ mostly | comma fields; inspect `_raw` |
| `pan:traffic` | **CSV** | ❌ no (no PAN TA) | **`rex`/positional** — comma-separated |
| `linux_secure`, `auditd` | syslog text | ❌ no | **`rex`** the message |
| `mysql:*`, `osquery_results` | JSON/mixed | ⚠️ JSON → `spath` | `spath`, or read `_raw` then `rex` |

> Solutions: [SOLUTIONS.md](SOLUTIONS.md) (Stage 3). Scope to a day (e.g. `08/24/2017`) — v2 is 226M events.

---

## Windows endpoint

### Q41 — Process creation (Windows 4688)
`wineventlog:security` logs process creation as EventCode 4688.
**Hint:** `index=botsv2 sourcetype=wineventlog:security EventCode=4688 earliest="08/24/2017:00:00:00" latest="08/25/2017:00:00:00" | stats count by ComputerName | sort - count`. Note `ComputerName` carries the `…frothly.local` FQDN.

### Q42 — Logon success/failure (4624 / 4625)
**Hint:** `sourcetype=wineventlog:security (EventCode=4624 OR EventCode=4625) | stats count by EventCode, ComputerName`. A 4625 spike on one host = credential attack.

### Q43 — Sysmon process detail
Sysmon (`*ysmon*`) gives you the `CommandLine` that 4688 often lacks here.
**Hint:** `sourcetype=*ysmon* EventCode=1 host=wrk-* | table _time host Image CommandLine ParentImage | sort _time`. Hunt scripting hosts / odd parents.

## Web & network (extracted)

### Q44 — Web request analysis
**Hint:** `sourcetype=access_combined earliest=… latest=… | stats count by status method | sort - count`; then look at `uri` for odd paths.

### Q45 — DNS via Splunk Stream (JSON)
**Hint:** `sourcetype=stream:dns | stats count by query{} | sort - count`. Group by `query{}` (the question, always present) — same rule as v1.

### Q46 — Suricata IDS alerts
**Hint:** `sourcetype=suricata alert.signature=* | stats count by alert.signature alert.category | sort - count`. You'll see scanning (port 135), TOR, and an **OSX backdoor** signature — pointers for Stage 4.

## The sources that need `rex` (no TA)

### Q47 — Palo Alto firewall (`pan:traffic`, CSV)
The log is raw CSV: `… ,TRAFFIC,end,…,<src_ip>,<dest_ip>,…,<src_user>,…,<app>,…`. There are no auto-fields.
**Hint:** read `_raw` first, then extract what you need, e.g. the source user and app:
`sourcetype=pan:traffic | rex "TRAFFIC,\w+,\d+,[^,]+,(?<src_ip>[^,]+),(?<dest_ip>[^,]+),[^,]+,[^,]+,[^,]+,(?<src_user>[^,]+)" | stats count by src_user`. Note the domain `frothly.local`.

### Q48 — Linux SSH brute force (`linux_secure`, syslog)
Raw syslog like `Failed password for root from 116.31.116.52 port 23301 ssh2`.
**Hint:** `sourcetype=linux_secure "Failed password" | rex "Failed password for (?:invalid user )?(?<user>\S+) from (?<src_ip>\S+)" | stats count by src_ip user | sort - count`. One external IP with tens of thousands of failures = brute force (verified: `58.242.83.20` hammering `gacrux`).

### Q49 — Linux auditd / osquery
**Hint:** `sourcetype=auditd | head 20` and `sourcetype=osquery_results | head 5` — inspect the shape, then decide what to `rex`/`spath`. `osquery_results` is JSON (use `spath`); `auditd` is key=value-ish.

### Q50 — MySQL activity
**Hint:** `sourcetype=stream:mysql | head 20` — DB queries on the wire. Look for the `query` field / raw SQL. Which host is the DB server? (`| tstats count where index=botsv2 sourcetype=mysql:* by host`).

## Putting sources together

### Q51 — Same event, two sources
Pick a process-creation moment on a workstation and view it from *both* `wineventlog:security` (4688) and Sysmon (EID 1). What does each give you that the other doesn't? (Sysmon → hashes/CommandLine; WinEventLog → account/logon context.)

### Q52 — Correlate a host across telemetry
For `wrk-bgist`, pull a slice of Sysmon + wineventlog + stream:dns in one window and read the story. **Hint:** `index=botsv2 host=wrk-bgist (sourcetype=*ysmon* OR sourcetype=wineventlog:security OR sourcetype=stream:dns) earliest=… latest=… | sort _time | table _time sourcetype EventCode Image query{}`.

### Q53 — Which host is which? Build an asset picture
**Hint:** `| tstats count where index=botsv2 by host sourcetype`, then infer roles: `cassiopeia`/`venus`/`jupiter` (servers — perfmon/mysql/pan), `wrk-*` (workstations — Sysmon), and two Macs `maclory-air13` + `kutekitten` (both carry `osquery_results`) — `kutekitten` (`10.0.4.2`) is the OSX-backdoor host.

## Email, endpoint AV & file transfer

### Q54 — Email (`stream:smtp`) — attachments tell the story
Mail flows through `stream:smtp`. Skip the sparse `sender_email` and go straight to what was *attached*.
**Hint:** `sourcetype=stream:smtp "attach_filename{}"=* | stats count by "attach_filename{}"`. You'll see two very different threats: `invoice.zip` (the Taedonggang phishing lure) and `Saccharomyces_cerevisiae_patent.docx` (an *insider* sending IP to a competitor). Same sourcetype, two incidents.

### Q55 — Endpoint AV (`symantec:ep:*`)
Symantec Endpoint Protection lands as several `symantec:ep:*` sourcetypes.
**Hint:** enumerate them first — `| tstats count where index=botsv2 sourcetype=symantec:ep:* by sourcetype` — then read one: `symantec:ep:packet:file` / `:traffic:file` dominate (network), while `:security:file` and `:behavior:file` have just **1** event each (the rare, high-signal ones). Read a `:security:file` event's `_raw` (comma-separated: host, event, `Local:`/`Remote:` IPs, `User:`, `Domain:`).

### Q56 — File transfer (`stream:ftp`) — the tooling drop
FTP carries file names in the `filename` field; `loadway` says Download vs Upload.
**Hint:** `sourcetype=stream:ftp loadway=Download | stats count by filename src_ip dest_ip`. From one FTP server (`160.153.91.7`) the attacker pulled a whole toolkit onto the beaching hosts (`10.0.2.107`/`10.0.2.109`): `psexec.exe`, `nc.exe`, `wget64.exe`, `winsys64.dll`, `python-2.7.6.amd64.msi`, `dns.py` — plus one **unusual file for an American company**: a Korean-named `.hwp` (Hangul word-processor) document.

### Q57 — TLS metadata (`stream:tcp`) — SSL issuer of the C2
When C2 is HTTPS you can't read the payload, but the TLS handshake metadata is still in `stream:tcp`.
**Hint:** `sourcetype=stream:tcp "45.77.65.211" | stats count by ssl_issuer`. The C2's certificate issuer is a suspiciously bare **`C = US`** (no org/CN) — a self-signed-looking cert is itself an indicator.

### Q58 — Registry persistence (`winregistry`)
`winregistry` is huge (~55M events) but the APT's persistence blob is findable by keyword.
**Hint:** `sourcetype=winregistry "Network" "debug" | stats count by key_path`. The value lives at `HKLM\software\microsoft\network\debug` — a base64 PowerShell-Empire payload the scheduled task re-reads at run time (a "fileless" persistence trick). Pull `data` to see the blob.

### Q59 — macOS endpoint (`osquery_results`) — confirm the Mac malware
The Mac (`kutekitten`) has no real-time EDR, but `osquery_results` snapshots its files — enough to confirm the backdoor on-host.
**Hint:** `sourcetype=osquery_results host=kutekitten "columns.path"="/Users/mkraeusen*" | stats count`. Mallory's user is `mkraeusen`; the results carry `columns.sha256`/`columns.path`, so you can pull the suspicious file's hash and check it externally (this is exactly how the incident IDs the `fpsaud`/FruitFly malware — IDS *alerts*, osquery *confirms*).

### Q60 — One indicator, every view (Stage-4 warm-up)
Take the C2 IP `45.77.65.211` and count how many *different* sourcetypes saw it.
**Hint:** `index=botsv2 "45.77.65.211" earliest="08/01/2017:00:00:00" latest="09/01/2017:00:00:00" | stats count by sourcetype | sort - count`. It appears across `pan:traffic`, `suricata`, `stream:tcp/ip/http`, and `access_combined` — **one indicator confirmed by six independent sources** is the report-grade finding you'll build on in Stage 4.

---

**When you can open any v2 sourcetype and know how to read it** (and which
need `rex`), you're ready for **Stage 4** → [`../../specialized/botsv2/`](../../specialized/botsv2/): the froth.ly APT, hunted end-to-end.

➡️ [SOLUTIONS.md](SOLUTIONS.md)
