# BOTS v2 — Stage 3: Log Analysis (Reading Every Sourcetype)

Now you read the actual security logs. v2 has **104 sourcetypes** across many
technologies — the skill is knowing *what each one tells you* and *how to get
fields out of it*. Crucial lesson up front:

> 🔑 **Not every sourcetype is field-extracted.** This lab ships no vendor
> TAs, so some sources give you clean fields and some are raw text you must
> `rex`. **Always check first:** `… sourcetype=X | head 1` and look at
> `_raw` vs. the field sidebar. Verified state below.

| Sourcetype | Format | How you read it |
|---|---|---|
| `access_combined` | Apache combined | `clientip method uri status bytes useragent` |
| `wineventlog:security` | key=value | `EventCode`, `ComputerName`, `Message` (e.g. 4688/4624/4625) |
| `xmlwineventlog:…sysmon…` | XML | `EventCode`, `Image`, `CommandLine`, … |
| `stream:*` (dns/http/smb/smtp/ftp/tcp) | JSON | JSON keys, e.g. `query{}`, `src_ip`, `dest_ip`, `filename` |
| `suricata` | JSON | `alert.signature`, `alert.category`, `src_ip` |
| `winregistry` | key=value | `key_path`, `registry_type`, `data` |
| `symantec:ep:*` | CSV-ish | comma fields; inspect `_raw` |
| `pan:traffic` | **CSV** | **`rex`/positional** — comma-separated |
| `linux_secure` | syslog text | **`rex`** the message |
| `auditd` | key=value-ish (syslog-wrapped) | **`rex`** the message |
| `osquery_results` | JSON | **`spath`** |
| `mysql:*` (`mysql:server:stats`, `mysql:transaction:details`) | key="value" (quoted) | fields already named in `_raw` — `hostname`, `database_name`, `Duration`, `SQL_TEXT` carries the query text directly |

⏱ **Time picker — Stage 3** (depends on the source you're reading)

| Questions | Time picker |
|---|---|
| Q41–Q43, Q51–Q52 (Windows endpoint / Sysmon / correlation) | `08/24/2017 00:00:00` → `08/25/2017 00:00:00` |
| Q44–Q45 (web / DNS) | `08/23/2017 00:00:00` → `08/24/2017 00:00:00` |
| Q46–Q50, Q53 (IDS / PAN / SSH / MySQL / asset — whole-dataset) | **All time** (these counts are dataset-wide) |
| Q54–Q60 (APT artifacts: SMTP / FTP / registry / osquery / C2) | `08/15/2017 00:00:00` → `08/26/2017 00:00:00` |

> **Each question leads with what to *find*, then a `Hint:` on how.** Hints are
> nudges, not answers — write the SPL yourself; the full query + verified result
> is in [SOLUTIONS.md](SOLUTIONS.md) (Stage 3), for a last resort. v2 is 226M
> events — always scope, or use `tstats`/keyword searches.

---

## Windows endpoint

### Q41 — Process creation (Windows 4688)
**Find:** which hosts spawned the most processes — a quick map of where Windows endpoint activity is concentrated. (`wineventlog:security` logs process creation as EventCode 4688.)
**Hint:** Filter to `EventCode=4688`, then `stats count by ComputerName` and `sort` descending. Note `ComputerName` carries the `…frothly.local` FQDN.

### Q42 — Logon success/failure (4624 / 4625)
**Find:** which host has a **failed-logon (4625) spike** — the classic credential-attack tell — versus normal successful (4624) logon volume. (Same `sourcetype=wineventlog:security`.)
**Hint:** Filter to `EventCode=4624 OR EventCode=4625`, then `stats count by EventCode ComputerName`. One host should stand out on 4625.

### Q43 — Sysmon process detail: find the process that shouldn't be there
**Find:** one PowerShell process on the workstations that's hiding what it's doing. Sysmon's `CommandLine` shows it (4688 doesn't). But `EventCode=1 host=wrk-*` on 08/24 is already **thousands of events** — you can't just `table` it and scroll. This question is about the *narrowing* technique, not the scrolling.

**Step 1 — measure first.**
`EventCode=1 host=wrk-*` → `stats count by host`. The total is why "just read the command lines" doesn't work.

**Step 2 — find the noise; don't guess it.**
- Run `stats count by Image | sort - count | head 10` on those same rows.
- Whatever sits at the top is almost always noise — real attacker activity is rare, so a process name that dominates the count is routine background activity, not a targeted action.
- Here the top 6 rows all share one path: `C:\Program Files\SplunkUniversalForwarder\bin\…`. That shared prefix *is* your exclusion filter: `NOT Image="*SplunkUniversalForwarder*"`.
- The move — *rank the field, exclude what dominates* — works on any dataset, even one you've never seen before; only the noisy vendor path changes.
- It thins the pile a lot, but what's left is still too much to eyeball.

**Step 3 — search for markers, not rows.**
- Attackers hiding a PowerShell payload lean on a few well-known tells: `-enc` (base64-encoded script), `FromBase64String`, `DownloadString` (fileless download-and-execute).
- Search `CommandLine` for any of those (`OR` them together) — same "known-bad marker" idea as `match()` in Q40.
- That alone should collapse the whole day, both hosts combined, down to single digits.

**Step 4 — read the parent.**
- What actually launched that PowerShell? Check `ParentImage`.
- A parent you don't expect — not a shell the user opened by hand — is the real red flag. That's the "odd parent→child chain" this question is pointing at.

⚠️ **Watch out for a bare `IEX`.** It's tempting to add `IEX` (short for `Invoke-Expression`, a common Empire alias) to your marker list. Don't — `CommandLine="*IEX*"` also matches the substring inside `iexplore.exe` (Internet Explorer) and pulls in ordinary browser processes as false positives. Anchor it tighter (`"*IEX(*"`) or just skip it; `-enc`/`FromBase64String`/`DownloadString` alone are precise enough here.

## Web & network (extracted)

### Q44 — Web request analysis: prove the day is clean, don't just assume it
**Find:** whether Frothly's web server saw anything suspicious on 08/23 — but back the verdict with the *same* technique Q40 used to actually catch a scanner, not a guess.

**Step 1 — measure.** `08/23/2017 00:00:00` → `08/24/2017 00:00:00` on `access_combined`. `stats count by status method`, `sort` descending. You'll get a handful of buckets across a few thousand rows — small enough to read, but don't stop here.

**Step 2 — read the non-200 buckets.** Pull the `uri` behind the `404` and `403` rows specifically (`stats count by uri` filtered to each status). Are these one-off odd paths, or the *same* couple of URIs repeating with different query strings?

**Step 3 — apply Q40's yardstick to this day.** Q40 didn't spot its scanner by request volume — it used **path diversity**: `stats dc(uri_path) as paths count by clientip`, `sort - paths`. Run that same measure here. What's the highest `paths` count you see, and how does it compare to the 4,022-path / 50× gap that flagged `45.77.65.211` on 08/11?

**Step 4 — write the verdict.** Given Step 2's URIs and Step 3's diversity numbers, is there a scanner hiding in this day's traffic, or not? A "no" backed by a specific comparison to Q40's numbers is a real, defensible finding — not a shrug.

### Q45 — DNS via Splunk Stream (JSON): filter it, then check what the filter ate
**Find:** the real domains the environment is resolving — and confirm your filter isn't quietly throwing away something legitimate along with the noise.

**Step 1 — measure, unfiltered.** `stats count by query{}` on `stream:dns` (same day window), `sort` descending. Look at the top few rows: one will dwarf the rest and won't look like a domain at all (no dots, fixed-width, odd character mix). Two more will be short, bare, dot-less words.

**Step 2 — name the pattern.** The dwarfing entry is **NetBIOS name-encoding**, not a real lookup. Write a filter that excludes anything shaped that way (real domains contain a literal `.`) and re-run — what corporate/SaaS domains rise to the top once it's gone?

**Step 3 — check the casualties.** Your dot-filter didn't only remove the NetBIOS string — it also caught a *different*, legitimate-looking `query{}` value that's short and dot-less too. Diff the unfiltered Step-1 top 10 against the filtered Step-2 top 10: what dropped out that you didn't intend to drop, and why does it make sense that this particular hostname is queried both with and without a domain suffix?

**Step 4 — conclude.** State, in one line, what your filter is actually good for (and not good for) based on Step 3 — that's the real deliverable, not the domain list itself.

### Q46 — Suricata IDS alerts: from 5,000+ events of noise to a 4-event lead
**Find:** the single host and signature worth carrying into Stage 4 — reached by narrowing down from the whole alert volume, not by scrolling for it.

**Step 1 — measure the raw signature list.** `stats count by alert.signature alert.category` on `suricata` (**all time** — dataset-wide), `sort` descending. One scanning signature dwarfs everything.

**Step 2 — zoom out to categories.** Collapse to just `stats count by alert.category`, `sort` descending. One category should account for the overwhelming majority of all alerts (that's Step 1's scan, plus TOR/TLS and policy noise, all lumped together) — and at least one category should be barely-there, in the single digits.

**Step 3 — drill into the smallest category.** Filter to just that near-empty `alert.category` and list its `alert.signature` values with counts. You should land on exactly two distinct signatures, a handful of events total — one is a DNS sinkhole reply, the other names an operating system Frothly's Windows-heavy environment shouldn't otherwise be talking about.

**Step 4 — identify the host.** `stats count by src_ip dest_ip` filtered to that OS-naming signature. Which internal host triggered it, and what did it talk to? That pairing is your concrete Stage-4 starting point.

## The sources that need `rex` (no TA)

### Q47 — Palo Alto firewall (`pan:traffic`, CSV)
**Find:** who's talking to whom through the firewall — but `pan:traffic` ships with **no extracted fields**, so first you have to carve `src_ip`/`dest_ip`/`src_user` out of the raw CSV yourself.
The log is raw CSV: `… ,TRAFFIC,end,…,<src_ip>,<dest_ip>,…,<src_user>,…,<app>,…`.
**Hint:** Read `_raw` first to count the comma positions, then `rex` positionally to pull the fields, and `stats count by` them. The domain is `frothly.local`; users appear as `frothly.local\<user>`.

### Q48 — Linux SSH brute force (`linux_secure`, syslog)
**Find:** whether anyone is brute-forcing SSH — the top source IPs by failed-password count, and the host they're hammering.
Raw syslog like `Failed password for root from 116.31.116.52 port 23301 ssh2`.
**Hint:** Search `linux_secure` for `"Failed password"`, `rex` the source IP (and user) out of the message, `stats count by src_ip`, `sort`. One external IP with tens of thousands of failures = brute force (verified: `58.242.83.20` hammering `gacrux`).

### Q49 — Linux auditd / osquery
**Find:** the *right parser* for two more endpoint sources — which of `auditd` / `osquery_results` is JSON, and which is key=value-ish? (The deliverable is the parsing decision, not a count.)
**Hint:** Inspect the shape first (`sourcetype=auditd | head 20`, `sourcetype=osquery_results | head 5`): `osquery_results` is JSON → `spath`; `auditd` is key=value-ish → `rex`.

### Q50 — MySQL activity
**Find:** which host is the database server, and what the on-wire SQL looks like.
**Hint:** For "which host is the DB server?", `tstats count by host` on `mysql:*` — one host dominates the whole index. For the on-wire SQL itself, read `sourcetype=mysql:transaction:details | head` — the query text is right there in `SQL_TEXT` (verified: `stream:mysql` is connection/flow metadata only — bytes, ports, timing — it carries no query field at all, despite what you might expect from the other `stream:*` sourcetypes).

## Putting sources together

### Q51 — Same event, two sources
**Find:** what each Windows source uniquely gives you. Pick one process-creation moment on a workstation and view it from *both* `wineventlog:security` (4688) and Sysmon (EID 1) — what does each show that the other doesn't? (Sysmon → hashes/CommandLine; WinEventLog → account/logon context.)

### Q52 — Correlate a host across telemetry
**Find:** the story of one host over time. For `wrk-bgist`, pull a slice of Sysmon + wineventlog + stream:dns in one window and read it top-to-bottom.
**Hint:** Search the host across all three sourcetypes at once (an `OR` of the three), `sort` by `_time`, and `table` the key columns (`sourcetype`, `EventCode`, `Image`, `query{}`).

### Q53 — Which host is which? Build an asset picture
**Find:** every host's role — server vs workstation vs Mac — inferred from the telemetry it emits.
**Hint:** `tstats count by host sourcetype`, then infer: `cassiopeia`/`venus`/`jupiter` (servers — perfmon/mysql/pan), `wrk-*` (workstations — Sysmon), and two Macs `maclory-air13` + `kutekitten` (both carry `osquery_results`) — `kutekitten` (`10.0.4.2`) is the OSX-backdoor host.

## Email, endpoint AV & file transfer

### Q54 — Email (`stream:smtp`) — attachments tell the story
**Find:** the suspicious email attachments — there are *two* very different threats hiding in `stream:smtp`. (Skip the sparse `sender_email`; go straight to what was attached.)
**Hint:** `stats count by "attach_filename{}"` (mind the `{}` — it's a multivalue JSON field, quote it). You'll surface `invoice.zip` (the Taedonggang phishing lure) and `Saccharomyces_cerevisiae_patent.docx` (an *insider* sending IP to a competitor). Same sourcetype, two incidents.

### Q55 — Endpoint AV (`symantec:ep:*`)
**Find:** the rare, high-signal Symantec events — enumerate the several `symantec:ep:*` sourcetypes, then zero in on the ones with almost no volume.
**Hint:** `tstats count … by sourcetype` first. `packet:file`/`traffic:file` dominate (network); `:security:file` and `:behavior:file` have just **1** event each — the interesting ones. Read a `:security:file` `_raw` (comma-separated: host, event, `Local:`/`Remote:` IPs, `User:`, `Domain:`).

### Q56 — File transfer (`stream:ftp`) — the tooling drop
**Find:** what the attacker pulled down over FTP — list the downloaded files and spot the one that has no business at an American brewery.
**Hint:** Filter `stream:ftp` to `loadway=Download`, then `stats count by filename src_ip dest_ip`. From one FTP server (`160.153.91.7`) the attacker pulled a toolkit onto `10.0.2.107`/`10.0.2.109`: `psexec.exe`, `nc.exe`, `wget64.exe`, `winsys64.dll`, `python-2.7.6.amd64.msi`, `dns.py` — plus a Korean-named **`.hwp`** (Hangul word-processor) document.

### Q57 — TLS metadata (`stream:tcp`) — SSL issuer of the C2
**Find:** what the C2's TLS certificate issuer looks like — you can't read the encrypted payload, but the handshake metadata is still there.
**Hint:** Scope `stream:tcp` to the C2 IP, then `stats count by ssl_issuer`. The issuer is a suspiciously bare **`C = US`** (no org/CN) — a self-signed-looking cert is itself an indicator.

### Q58 — Registry persistence (`winregistry`)
**Find:** the APT's persistence blob hidden in the registry. `winregistry` is huge (~55M events), so search by keyword, not by scanning.
**Hint:** Keyword-search `Network` + `debug`, then `stats count by key_path`. The value lives at `HKLM\software\microsoft\network\debug` — a base64 PowerShell-Empire payload the scheduled task re-reads at run time (a "fileless" trick). Pull `data` to see the blob.

### Q59 — macOS endpoint (`osquery_results`) — confirm the Mac malware
**Find:** the backdoor file on the Mac and its hash. The Mac (`kutekitten`) has no real-time EDR, but `osquery_results` snapshots its files — enough to confirm the malware on-host.
**Hint:** Scope `osquery_results` to `host=kutekitten` and Mallory's home (`columns.path="/Users/mkraeusen*"`). The rows carry `columns.sha256`/`columns.path`, so you can lift the suspicious file's hash and check it externally — how the incident IDs the `fpsaud`/FruitFly malware. IDS *alerts*, osquery *confirms*.

### Q60 — One indicator, every view (Stage-4 warm-up)
**Find:** how many *different* sourcetypes saw the C2 IP `45.77.65.211` — proof of how many independent angles you have on one indicator.
**Hint:** Search the bare IP across the whole index (wide window) and `stats count by sourcetype`, `sort` descending. It appears across `pan:traffic`, `suricata`, `stream:tcp/ip/http`, and `access_combined` — **one indicator confirmed by six independent sources** is the report-grade finding you'll build on in Stage 4.

---

**When you can open any v2 sourcetype and know how to read it** (and which
need `rex`), you're ready for **Stage 4** → [`../../specialized/botsv2/`](../../specialized/botsv2/): the froth.ly APT, hunted end-to-end.

➡️ [SOLUTIONS.md](SOLUTIONS.md)
