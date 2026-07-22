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

**Step 1 — read one raw event before writing any SPL.** `sourcetype=pan:traffic | head 1`. The log is comma-separated: `… ,TRAFFIC,end,…,<src_ip>,<dest_ip>,…,<src_user>,…,<app>,…`. Count positions from the literal `TRAFFIC` marker onward — that anchor doesn't move, even though earlier fields sometimes do.

**Step 2 — carve the fields positionally.** `rex` off that `TRAFFIC,...` anchor to pull `src_ip` and `dest_ip` as named groups.

**Step 3 — count the pairs, then read before concluding.** `stats count by src_ip dest_ip`, `sort` descending. Some of what dominates will be unremarkable (DNS to a public resolver, telemetry to a cloud endpoint) — the more interesting rows are *internal-to-internal* pairs converging on one host. Does that host match anything you already know its role to be from Stage 2?

**Step 4 — add the username.** Extend the same `rex` to also capture `src_user` (`frothly.local\<user>`), then re-run scoped to one of the internal pairs from Step 3. Whose account is behind it, and does that account make sense for that host?

### Q48 — Linux SSH brute force (`linux_secure`, syslog)
**Find:** whether anyone is brute-forcing SSH — the top source IPs by failed-password count, and which host they're hammering.

**Step 1 — isolate the signal, don't parse everything.** `sourcetype=linux_secure "Failed password"` — the literal string is the entire filter you need.

**Step 2 — carve the source IP.** Raw lines look like `Failed password for root from 116.31.116.52 port 23301 ssh2` — `rex` the IP out from right after `from`. Grab the attempted username too, right before `from`.

**Step 3 — rank and compare.** `stats count by src_ip`, `sort` descending. One external IP should sit an order of magnitude above the rest — tens of thousands of failures is brute force, not a mistyped password. Which internal host (`host` field) is catching all this noise?

**Step 4 — sanity-check against a real login.** Search the same host for a *successful* login (`Accepted password`) around the same window — did the brute force ever actually land, or does it just bounce off?

### Q49 — Linux auditd / osquery
**Find:** the *right parser* for two more endpoint sources — which of `auditd` / `osquery_results` is JSON, and which is key=value-ish? (The deliverable is the parsing decision, not a count.)

**Step 1 — look before you parse.** `sourcetype=auditd | head 20` and `sourcetype=osquery_results | head 5`. Read `_raw` for both before writing a single `rex` or `spath`.

**Step 2 — name the shape.** `osquery_results` is one (nested) JSON object per event — `spath` territory, which gives you dotted field names like `columns.path`, not flat ones. `auditd` is space-separated `key=value` pairs with an embedded quoted sub-message (`msg='...'`) — `rex` territory, `spath` won't help here.

**Step 3 — prove it on real content.** Pull one `auditd` event that looks like SSH activity — it's the *same* kind of noise Q48 found, just surfaced through the Linux audit subsystem instead of syslog. Correctly identifying the parser is what lets you cross-reference one real event across two different sourcetypes.

### Q50 — MySQL activity
**Find:** which host is the database server, and what the on-wire SQL looks like.

**Step 1 — find the DB server by volume.** `tstats count where index=botsv2 sourcetype=mysql:* by host`, `sort` descending — one host dominates the entire index by a wide margin.

**Step 2 — read the raw shape.** `sourcetype=mysql:* | head 5`. The fields are already named for you right in `_raw` (`hostname=`, `database_name=`, `Duration=`, `SQL_TEXT=`) — no `spath`/`rex` needed for this one.

**Step 3 — don't go looking in the wrong place.** It's tempting to assume the on-wire SQL lives in `stream:mysql` (it's JSON, like the other `stream:*` sourcetypes) — check for yourself: `sourcetype=stream:mysql query{}=*` and see how many results come back. The real query text is sitting in `SQL_TEXT`, directly on `mysql:transaction:details`.

## Putting sources together

### Q51 — Same event, two sources
**Find:** what each Windows source uniquely gives you.

**Step 1 — anchor on one moment.** Pick any workstation and an `EventCode=1` (Sysmon process-create) event with an interesting `Image`.

**Step 2 — find its sibling.** Search the same host, the same rough second, for `sourcetype=wineventlog:security EventCode=4688` — same process, a different lens on it.

**Step 3 — diff the fields.** `table` both events side by side. One source carries `CommandLine`/hashes/`ParentImage`; the other carries account/logon context the first one doesn't have at all. Neither alone tells the full story — that's the point.

### Q52 — Correlate a host across telemetry
**Find:** the story of one host over time. For `wrk-bgist`, pull a slice of Sysmon + wineventlog + stream:dns in one window and read it top-to-bottom.

**Step 1 — pull all three at once.** `host=wrk-bgist (sourcetype=*ysmon* OR sourcetype=wineventlog:security OR sourcetype=stream:dns)`, scoped to the Windows-endpoint time window from the table above.

**Step 2 — sort and read it as a timeline.** `sort` by `_time`, `table sourcetype EventCode Image query{}` — read top-to-bottom like an analyst reconstructing what happened, not a table you filter and forget.

**Step 3 — notice what's *missing*.** If one of the three sourcetypes never shows up for this host, that's not a broken query — think back to what you learned about which hosts carry which telemetry earlier in Stage 3, and work out why that gap makes sense here rather than assuming it's an error.

### Q53 — Which host is which? Build an asset picture
**Find:** every host's role — server vs workstation vs Mac — inferred from the telemetry it emits.

**Step 1 — one command, whole picture.** `tstats count where index=botsv2 by host sourcetype` — this alone gets you almost all the way there; you don't need per-host drill-downs yet.

**Step 2 — read sourcetype as a fingerprint.** A host throwing `perfmon:*`/`mysql:*`/`pan:traffic` is a server. A host throwing Sysmon + `winregistry` is a Windows workstation. A host with `osquery_results` and nothing Windows-specific is a Mac.

**Step 3 — count the Macs, then cross-reference.** How many distinct hosts carry `osquery_results`? You should find exactly two. Does either one line up with an indicator you've already run into earlier in Stage 3 (Q46's Suricata drill-down, for instance)?

## Email, endpoint AV & file transfer

### Q54 — Email (`stream:smtp`) — attachments tell the story
**Find:** the suspicious email attachments — there are *two* very different threats hiding in `stream:smtp`. (Skip the sparse `sender_email`; go straight to what was attached.)

**Step 1 — list what got attached.** `stats count by "attach_filename{}"` (mind the `{}` — it's a multivalue JSON field, quote the whole field name). You'll get a short, readable list.

**Step 2 — separate signal from noise.** Some entries are obviously irrelevant (torrents, generic images) — set those aside. What's left should split into two distinct flavors: one shaped like a generic-sounding business archive (a classic phishing-lure naming pattern), and one that reads like a real, specific internal document.

**Step 3 — follow each thread separately.** For the archive: how many times does it appear, and is that one-off or a blast to multiple recipients? For the document: read its actual filename closely — does the subject matter sound like something that should be leaving the company, and who's it addressed to? These are two unrelated incidents sharing one sourcetype, not one story.

### Q55 — Endpoint AV (`symantec:ep:*`)
**Find:** the rare, high-signal Symantec events — enumerate the several `symantec:ep:*` sourcetypes, then zero in on the ones with almost no volume.

**Step 1 — enumerate first.** `tstats count where index=botsv2 sourcetype=symantec:ep:* by sourcetype`, `sort` descending. You'll get a handful of sourcetypes spanning several orders of magnitude in volume.

**Step 2 — split by volume, not by name.** The top two or three are bulk network/telemetry noise (hundreds of thousands of events) — set those aside. What's left at the very bottom, in the single digits?

**Step 3 — read the rare ones.** Pull `_raw` for whichever sourcetype(s) sit at 1-2 events — it's comma-separated, not field-extracted. What host is it on, and what does the message actually say (look for `Local:`/`Remote:` IP fields, `User:`, `Domain:`)?

### Q56 — File transfer (`stream:ftp`) — the tooling drop
**Find:** what the attacker pulled down over FTP — list the downloaded files and spot the one that has no business at an American brewery.

**Step 1 — scope to downloads.** `sourcetype=stream:ftp loadway=Download` — this is an FTP `RETR`, a client pulling a file, not pushing one.

**Step 2 — list what moved.** `stats count by filename src_ip dest_ip`. One external FTP server should stand out as the source for a small cluster of files landing on one or two internal hosts.

**Step 3 — read the filenames as a toolkit, not a random list.** Several are recognizable dual-use admin/attacker tools (remote execution, a netcat-style utility, a downloader, a scripting runtime). One filename is written in a non-Latin script — what does that tell you about who staged this infrastructure, or at minimum, that it doesn't belong at this company?

### Q57 — TLS metadata (`stream:tcp`) — SSL issuer of the C2
**Find:** what the C2's TLS certificate issuer looks like — you can't read the encrypted payload, but the handshake metadata is still there.

**Step 1 — scope to the indicator.** Filter `stream:tcp` to `45.77.65.211` — the same IP that flagged as a scanner back in Q44's step 3 comparison.

**Step 2 — read the handshake field.** `stats count by ssl_issuer`. A legitimate service's certificate usually shows a real organization/CN. What does this one show instead, and what does the *absence* of an org name usually suggest about how a certificate was generated?

### Q58 — Registry persistence (`winregistry`)
**Find:** the APT's persistence blob hidden in the registry. `winregistry` is huge (~55M events), so search by keyword, not by scanning.

**Step 1 — pick keywords, not a scan.** You already know this is a Windows environment under active attack. Search `sourcetype=winregistry` for a couple of terms you'd expect near a network-related logging/debug key — that's a common naming pattern for a registry value nobody would think to check.

**Step 2 — count, don't read blind.** `stats count by key_path` on your keyword-filtered results. You should land on a single distinct path, with only a handful of events — something that looks out of place for a stock Windows install.

**Step 3 — pull the value and think about *why*.** Read `data` for that key. It won't look like plaintext — what encoding does it resemble, and why would an attacker stash a payload in a registry *value* instead of a file on disk? (Hint: think about what "fileless" is trying to evade.)

### Q59 — macOS endpoint (`osquery_results`) — confirm the Mac malware
**Find:** the backdoor file on the Mac and its hash. The Mac (`kutekitten`) has no real-time EDR, but `osquery_results` snapshots its files — enough to confirm the malware on-host.

**Step 1 — scope tight, and pick the right query pack.** `sourcetype=osquery_results host=kutekitten` spans over a dozen different osquery query packs (`stats count by name` shows the split) — most are process/hardware noise with no hash info at all. The one that actually carries file hashes is `name=file_events`; don't assume every pack has the same fields.

**Step 2 — filter to rows that actually have a hash.** Not every `file_events` row is hashed — some are just permission/attribute-change duplicates of the same file with blank hash fields. Filter to the rows where the hash fields are populated.

**Step 3 — read what got flagged.** A small number of events remain, all pointing at the same file sitting in the Mac owner's `Downloads` folder. Read the filename itself: does it look like a normal download, or a social-engineering lure (no file extension, executable permissions, an HR-themed name designed to get opened)?

**Step 4 — pull the hash and connect it back.** Grab the MD5/SHA1/SHA256 from that event and check it externally. IDS *alerted* you to suspicious traffic from this host earlier (Q46); osquery *confirms* what's actually sitting on disk, permissions and all. Same host, two independent proofs — that pairing is what makes a finding report-grade instead of a hunch.

### Q60 — One indicator, every view (Stage-4 warm-up)
**Find:** how many *different* sourcetypes saw the C2 IP `45.77.65.211` — proof of how many independent angles you have on one indicator.

**Step 1 — search the bare indicator, unscoped.** Don't filter to one sourcetype — search the IP across the whole index, wide time window (this one shows up across most of the dataset's span).

**Step 2 — count by sourcetype.** `stats count by sourcetype`, `sort` descending. You should get a handful of genuinely different technology layers — network flow metadata, IDS, web logs, firewall — all independently agreeing on the same indicator.

**Step 3 — state the finding, not just the list.** How many *independent* sources does that give you? That count — not any single alert — is the report-grade statement you carry into Stage 4: this isn't a guess from one tool, it's corroborated across the entire stack.

---

**When you can open any v2 sourcetype and know how to read it** (and which
need `rex`), you're ready for **Stage 4** → [`../../specialized/botsv2/`](../../specialized/botsv2/): the froth.ly APT, hunted end-to-end.

➡️ [SOLUTIONS.md](SOLUTIONS.md)
