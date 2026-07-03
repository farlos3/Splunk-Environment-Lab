# Solutions — Self-Practice

⚠️ **Last resort.** Try every problem honestly first.

> Some answers are specific numbers from the BOTS v1 dataset; others are SPL templates because the right answer depends on interpretation.
> The SPL below is written for **readability**, not maximum efficiency.
>
> **Time picker per section (set this before running the queries below):**
>
> | Section / Questions | Time picker |
> |---|---|
> | Section 1 (Q1–Q15) | `8/10/2016 00:00:00` → `8/11/2016 00:00:00` |
> | Section 2 Q16–Q26 | `8/10/2016 00:00:00` → `8/11/2016 00:00:00` |
> | Section 2 Q27–Q30 | `8/24/2016 00:00:00` → `8/25/2016 00:00:00` |
> | Scenario A (Q31–Q40) | `8/10/2016 00:00:00` → `8/12/2016 00:00:00` |
> | Scenario B (Q41–Q50) | `8/24/2016 00:00:00` → `8/25/2016 00:00:00` |
> | Section 4 (Q51–Q67)  | Per question — Scenario A or B window |

---

# Section 1 — Splunk Fundamentals

### Q1
```spl
index=botsv1 | stats count by sourcetype | sort - count
```
Returns the full sourcetype inventory — typical entries: `stream:http`, `WinEventLog:Security`, `suricata`, `stream:dns`, `iis`, `fgt_utm`, etc.

---

### Q2
```spl
index=botsv1 | stats count
```
Several million events (exact count depends on the dataset version).

---

### Q3
```spl
index=botsv1 sourcetype=stream:http | stats dc(source) as unique_sources
```

---

### Q4
```spl
index=botsv1
| stats earliest(_time) as first latest(_time) as last
| eval first=strftime(first,"%F %T"), last=strftime(last,"%F %T")
```
Within a 24-hour window you see only that window. To inspect the full dataset bounds, temporarily widen the time picker to **8/10/2016 → 8/27/2016** for this question only — the dataset spans **2016-08-10 → 2016-08-26**.

---

### Q5
```spl
index=botsv1 sourcetype=stream:http | top limit=5 src_ip
```

---

### Q6
```spl
index=botsv1 sourcetype=stream:http | stats dc(dest_ip)
```

---

### Q7
```spl
index=botsv1 sourcetype=stream:http status=404 | stats count
```

---

### Q8
```spl
index=botsv1 sourcetype=stream:http | timechart span=1h count
```

---

### Q9
```spl
index=botsv1 sourcetype=stream:http | top limit=5 http_user_agent
```

---

### Q10
```spl
index=botsv1 sourcetype=stream:http uri_path="*admin*" | stats count
```

---

### Q11
```spl
index=botsv1 sourcetype=stream:http
| rex field=uri_path "^/(?<first_dir>[^/]+)"
| top limit=10 first_dir
```

---

### Q12
```spl
index=botsv1 sourcetype=stream:http | stats count by http_method
```
You should see `GET`, `POST`, `HEAD`, and `OPTIONS`.

---

### Q13
```spl
index=botsv1 sourcetype=stream:http
| sort - bytes_out
| head 10
| table _time src_ip dest_ip bytes_out uri_path
```

---

### Q14
```spl
index=botsv1 sourcetype=stream:http
| eval total_bytes=bytes_in+bytes_out
| stats sum(total_bytes) as total by src_ip
| sort - total | head 5
```

---

### Q15
```spl
index=botsv1 sourcetype=stream:http http_method=POST status=200 uri_path="*login*"
| table _time src_ip dest_ip uri_path
| sort _time
```

---

# Section 2 — Security Log Analysis

### Q16
```spl
index=botsv1 EventCode=4625 | stats count
```

---

### Q17
```spl
index=botsv1 EventCode=4624 | stats count
```
Compare against Q16 — in BOTS v1 you will see failed logons spike during the attack window.

---

### Q18
```spl
index=botsv1 EventCode=4625 | top limit=5 user
```

---

### Q19
```spl
index=botsv1 sourcetype=XmlWinEventLog EventCode=1 | stats count
```
If you get zero, try `sourcetype=*sysmon*` or `sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational`.

---

### Q20
```spl
index=botsv1 EventCode=1
| stats count by ParentImage Image
| sort - count | head 10
```
Watch for unnatural pairs like `winword.exe → cmd.exe` or `outlook.exe → powershell.exe`.

---

### Q21
```spl
index="botsv1" sourcetype=suricata event_type=alert | top limit=10 alert.signature
```

---

### Q22
```spl
index="botsv1" sourcetype=suricata event_type=alert alert.severity=1 | stats count
```

---

### Q23
```spl
index=botsv1 bytes_out=*
| stats sum(bytes_out) as total_out by src_ip
| sort - total_out | head 5
| eval total_MB=round(total_out/1048576,2)
```

---

### Q24
```spl
index=botsv1 sourcetype=stream:http http_method=POST
| top limit=10 uri_path
```

---

### Q25
```spl
index=botsv1 sourcetype=stream:http
  (form_data="*union*select*" OR form_data="*'%20or%20*"
   OR uri_query="*union*select*" OR uri_query="*'%20or%20*")
| table _time src_ip uri_path form_data uri_query
```
Other patterns worth checking: `--`, `;--`, `xp_cmdshell`, `INFORMATION_SCHEMA`.

---

### Q26
```spl
index=botsv1 sourcetype=stream:dns | rare limit=10 query
```

---

### Q27
```spl
index=botsv1 EventCode=1 Image="*powershell.exe"
| stats count by ParentImage user
| sort - count
```

---

### Q28
```spl
index=botsv1 EventCode=4698
| table _time user TaskName
```
If this returns nothing, the dataset does not capture that event — fall back to `EventCode=4699` (deleted) or Sysmon EID 1 with `schtasks.exe`.

---

### Q29
```spl
index=botsv1 EventCode IN (12,13,14)
| top limit=10 TargetObject
```
Watch for Run keys: `Software\Microsoft\Windows\CurrentVersion\Run`.

---

### Q30
```spl
index=botsv1 EventCode=3
| top limit=10 Image
```

---

# Section 3 — SOC Tier 1 Investigations

## Scenario A: Web Server Attack

> **Time picker:** `8/10/2016 00:00:00` → `8/12/2016 00:00:00`

### Q31 — Web server IP
```spl
index=botsv1 sourcetype=stream:http site="imreallynotbatman.com"
| top limit=1 dest_ip
```
**Answer:** `192.168.250.70` — the internal IP serving `imreallynotbatman.com`. Scoping on `site` (the HTTP Host header) ties the IP to the hostname the question asks about; a bare `top dest_ip` would only tell you the busiest host, which happens to coincide here because the server is under heavy attack.

---

### Q32 — Reconnaissance scanner
```spl
index=botsv1 sourcetype=stream:http dest_ip=192.168.250.70
| stats count dc(uri_path) as unique_paths by src_ip
| sort - unique_paths | head 10
```
**Answer:** `40.80.148.42` (Po1s0n1vy's scanning host).

---

### Q33 — Scanner tool identity
```spl
index=botsv1 sourcetype=stream:http src_ip=40.80.148.42
| top http_user_agent
```
**Answer:** Acunetix Web Vulnerability Scanner.

---

### Q34 — Brute force source
```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST
| stats count by src_ip, uri_path
| sort - count
```
**Answer:** `23.22.63.114` (brute-force host — different from the scanner; a later phase).

---

### Q35 — Brute force duration
```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" src_ip="23.22.63.114" uri_path="/joomla/administrator/index.php" http_method=POST
| stats count min(_time) as earliest max(_time) as latest
| eval duration_minutes = (latest - earliest) / 60
| eval start_time = strftime(earliest, "%Y-%m-%d %H:%M:%S")
| eval end_time = strftime(latest, "%Y-%m-%d %H:%M:%S")
| table start_time end_time duration_minutes
```
**Answer:** Hundreds of attempts within a few minutes.

---

### Q36 — Unique passwords
```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" src_ip="23.22.63.114" uri_path="/joomla/administrator/index.php" http_method=POST
| rex field=form_data "passwd=(?<password>[^&]+)"
| stats dc(password) as unique_passwords
```
**Answer:** ~400+ unique passwords (close to the attempt count — each password tried once = classic dictionary attack).

---

### Q37 — Successful password
```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" src_ip="23.22.63.114" uri_path="/joomla/administrator/index.php" http_method=POST
| rex field=form_data "passwd=(?<password>[^&]+)"
| stats count by password, status, bytes_out
| sort - bytes_out
```
The outlier `bytes_out` row is the success — most failures share one consistent response size.
**Answer:** `batman` (the admin password).

---

### Q39 — Defacement file

BOTS v1's `stream:http` doesn't capture POST upload bodies, so the multipart `filename=` token isn't searchable directly. Use **GET-side discovery** — find the file by observing the web server serve it afterward (this is the technique the official walkthrough uses too).

```spl
index=botsv1 sourcetype=stream:http src_ip=192.168.250.70 http_method=GET
| search "*.jpeg" OR "*.jpg" OR "*.png" OR "*.gif"
| stats count by uri_path
| sort - count
```
The defaced file is the one being served from the web server that **doesn't match the legitimate site's image inventory**.

**Answer:** `poisonivy-is-coming-for-you-batman.jpeg`. The .exe payload `3791.exe` (MD5 `ec78c938...`) was uploaded alongside it — see the [BOTS v1 official walkthrough Q109](../../splunk-bots/botsv1/README.md) for the malware analysis chain.

---

### Q40 — IOC summary (Scenario A)

| IOC type | Value |
|---|---|
| Victim IP | `192.168.250.70` (imreallynotbatman.com) |
| Scanner IP / Uploader IP | `40.80.148.42` (recon **and** post-breach upload of JPEG + .exe) |
| Scanner tool | Acunetix WVS |
| Brute force IP | `23.22.63.114` (cracked password only — did not upload) |
| Targeted username | `admin` |
| Successful password | `batman` |
| Defacement file | `poisonivy-is-coming-for-you-batman.jpeg` |
| Threat actor | Po1s0n1vy (APT) |

---

## Scenario B: Ransomware Outbreak

> **Time picker:** `8/24/2016 00:00:00` → `8/25/2016 00:00:00`

### Q41 — Patient zero IP

A free-text search for `we8105desk` returns noisy hits — every host in the network broadcasts and queries this hostname via DNS / NetBIOS, so the resulting IP set is mixed and hard to attribute. For a clean answer, pivot to a log source that **directly binds hostname → IP**: Windows Security logons (Event 4624).

```spl
index=botsv1 sourcetype="WinEventLog:Security" EventCode=4624 "we8105desk"
| stats count by ComputerName,Workstation_Name, Source_Network_Address, EventCode
```

Every successful logon event carries the originating host's IP in `Source_Network_Address`. Filtering out the special values `-` (local logon) and `::1` (loopback) leaves the real network address used by `we8105desk`.

**Reading the `stats` fields (these are Windows' native names, not the `src_ip`/`dest_ip` you used earlier):**

| Field | What it means | Why it's here |
|---|---|---|
| `ComputerName` | The machine that *recorded* the event = the host being logged **into** (destination). | Confirms the event belongs to `we8105desk`. |
| `Workstation_Name` | The name the connecting client reported for **itself** (where the logon came from) — a *name*, not an IP. | Cross-check only; clients report it inconsistently. |
| `Source_Network_Address` | The **IP the logon came from** — the only field carrying an actual address. | This is your answer. |
| `EventCode` | `4624` = successful logon. | Sanity check the filter held. |

> ⚠️ Why not `src_ip`? `src_ip`/`dest_ip` are *CIM-normalized* fields Splunk auto-creates for network sourcetypes (`stream:*`). Raw `WinEventLog:Security` events keep Windows' own field names, so the source address is `Source_Network_Address` — there's no `src_ip` to search here unless an add-on aliases it.

**Answer:** `192.168.250.100`.

> 🛈 The DHCP source (`sourcetype=stream:dhcp`) is the textbook alternative, but BOTS v1 doesn't reliably surface a DHCP lease for this host in the active window — endpoint logon data is the source of truth here.

---

### Q42 — First suspicious DNS

Pivot on the host's IP (from Q41) into `stream:dns` and group by the **`query{}`** field — the canonical, always-populated DNS field — to get the earliest lookup per domain.

> 🔁 **Wait — in Q41 the host's IP was `Source_Network_Address`, why is it `src_ip` now?** Same IP (`192.168.250.100`), different field name — *because the sourcetype changed.* Q41 read `WinEventLog:Security` (raw Windows logs that keep Windows' own field names, so there's no `src_ip` — the address is `Source_Network_Address`). Q42 reads `stream:dns`, a **network** sourcetype where Splunk auto-creates the CIM-normalized `src_ip`/`dest_ip`. So the rule of thumb: **network sourcetypes (`stream:*`) → use `src_ip`; raw Windows event logs → use `Source_Network_Address`.** You carry the *value* forward from Q41; you just address it with whatever field the new sourcetype exposes.

```spl
index=botsv1 sourcetype=stream:dns src_ip="192.168.250.100" "query{}"="*"
| stats earliest(_time) as first_seen count by "query{}"
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| sort first_seen
| table first_seen, "query{}", count
```

Around **16:48** on 8/24/2016 you see two suspicious domains within seconds of each other:

| Time | query{} | Role |
|---|---|---|
| **16:48:12** | `solidaritedeproximite.org` | **Patient Zero** — the drive-by landing page (French-looking long name: "*solidarité de proximité*") |
| 16:48:16 | `dedie73.olfsoft.net` | Secondary — Cerber's connectivity-check domain |

**Answer:** `solidaritedeproximite.org` (drive-by landing page for the Cerber dropper).

> 🛈 Why the curly braces? Splunk renders JSON-array source fields with `{}` suffixed to the name. The literal field name *is* `query{}` — you must quote it (`"query{}"`) so SPL doesn't try to interpret the braces.

---

#### ⚠️ Pitfall — don't group by `hostname{}` (it hides Patient Zero)

The intuitive move is to group by `hostname{}` instead. **Don't** — it gives the *wrong* answer. The same query grouped by `hostname{}` surfaces `dedie73.olfsoft.net` at 16:48:16 and **misses** `solidaritedeproximite.org` at 16:48:12 entirely, so a *later* domain looks like "the first." Here's why:

- **`query{}` comes from the DNS *question*** (*"what's the IP for `<host>`?"*). Splunk Stream copies it verbatim — as long as the host *attempted* the lookup, it's populated. **Guaranteed presence.**
- **`hostname{}` comes from the DNS *response*** — Stream's best-effort extraction from the Answer/Authority/Additional records. Malicious domains routinely return odd response shapes (CNAME chains, NXDOMAIN, no response), so Stream can't extract a name and the field stays **NULL**.
- **The silent drop:** `| stats ... by "hostname{}"` **drops NULL-keyed rows with no warning**. Patient Zero — precisely the "weird response shape" kind of domain — vanishes from the output, and its `_time` never enters `earliest()`.

**Lessons:**
1. In `stream:dns`, always pivot on `query{}` — it's the canonical field and is consistently populated.
2. When two analysts produce different "first suspicious domain" answers, the difference is almost always the field they grouped by. Be explicit about which field you trust.
3. Four seconds matter in incident response — the earliest event is usually the one that *caused* everything downstream.

---

#### 🧹 Bonus — when the output is hundreds of noisy rows, how do you find the one domain?

Run the query above for real and you don't get a tidy two-row table — you get **hundreds of rows** of reverse-DNS lookups, Windows telemetry, and NetBIOS junk, with `solidaritedeproximite.org` buried in the middle. You are *not* expected to write the perfect filter up front. Analysts do **subtractive triage**: remove what you recognize as normal, one layer at a time, until only the odd ones are left.

**First, recognize the normal "noise" categories:**

| Pattern in the output | What it is | Verdict |
|---|---|---|
| `FHEFDJDADEDB…` (gibberish, **no dots**) | encoded **NetBIOS** broadcast names | normal |
| `*.in-addr.arpa` | **reverse DNS (PTR)** lookups | normal plumbing |
| `*.local`, `_ldap._tcp.…waynecorpinc.local` | internal AD / domain | normal |
| `wpad`, `wpad.waynecorpinc.local` | proxy auto-discovery | normal |
| `*.microsoft.com`, `*.msftncsi.com` | Windows telemetry | normal |

**You don't need to know any filter in advance — get there one of three ways:**

1. **Click to exclude (zero syntax).** In the results, click a noise value → **"Exclude from results"**. Splunk writes the `NOT …` clause for you. Repeat for each junk pattern.
2. **Peel off the biggest pile first with `NOT` + `*` (wildcards, not regex).** Look at what repeats most, exclude it, re-run, look again:
   ```spl
   index=botsv1 sourcetype=stream:dns src_ip="192.168.250.100" "query{}"="*"
   | stats earliest(_time) as first_seen count by "query{}"
   | search NOT "query{}"="*.in-addr.arpa" NOT "query{}"="*.local"
           NOT "query{}"="wpad*" NOT "query{}"="*.microsoft.com" NOT "query{}"="*.msftncsi.com"
   | eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
   | sort first_seen
   ```
   After two or three rounds the list collapses to a handful you can eyeball.
3. **(Optional) one line of regex** to drop the dot-less NetBIOS gibberish, *if* it still bothers you — but you can also just ignore it, since a name with no dot isn't a real domain:
   ```spl
   | regex "query{}"="\."
   ```
   `\.` means "contains a literal dot." That's the *only* regex here, and now you know it.

**What's left after the noise is gone:** `solidaritedeproximite.org` (16:48:12) and `ipinfo.io` (16:49:24). The first is Patient Zero (earliest external, non-infrastructure domain); `ipinfo.io` is later — malware checking its own public IP *after* infection.

> 💡 The filter isn't something you memorize — it **emerges from looking at the data.** Do this across a few investigations and you'll *know* your environment's baseline noise by heart. That baseline knowledge — not regex syntax — is the real analyst skill. And always **confirm by pivoting**: the true Patient Zero is the domain immediately followed by the dropper (`wscript.exe` running `20429.vbs` in Q43 — *not* the `cscript.exe`/Acronis noise).

---

### Q43 — Initial dropper

**Don't start by reading 305 rows — narrow them down.** Here's the funnel, step by step.

**Step 1 — the naive search (too noisy).**
```spl
index=botsv1 host=we8105desk EventCode=1
| table _time User ParentImage Image CommandLine
| sort _time
```
~305 events: Windows boot, Splunk forwarder, Acronis backup… almost all benign. This is the *starting point*, not the answer.

**Step 2 — scope to the victim user.** Which user? Don't assume — derive it: `… EventCode=1 | stats count by User` shows the box is mostly service accounts (`NT AUTHORITY\SYSTEM`, `NETWORK SERVICE`, `LOCAL SERVICE`) plus one dominant *human* account, `WAYNECORPINC\bob.smith` (~205 events). He's the workstation owner (same Bob from Q41), so he's who could have opened a malicious file. Cut everything else:
```spl
index=botsv1 host=we8105desk EventCode=1 User="*bob.smith*"
| table _time ParentImage Image CommandLine
| sort _time
```
This already removes the bait — the `cscript.exe` running `.vbs` from `C:\Windows\TEMP` you saw earlier is **Acronis backup running as `NT AUTHORITY\SYSTEM`**, not the attack. Scoping to Bob drops it.

**Step 3 — filter on behaviour that should never happen.** Office apps don't launch shells; script hosts don't run code from a user's profile:
```spl
index=botsv1 host=we8105desk EventCode=1 User="*bob.smith*"
  (ParentImage="*WINWORD*" OR Image="*wscript.exe" OR Image="*cscript.exe"
   OR Image="*powershell*" OR CommandLine="*AppData*" OR CommandLine="*.vbs*" OR CommandLine="*.tmp*")
| table _time ParentImage Image CommandLine
| sort _time
```
Now you're down to a handful of rows, and the parent→child chain is obvious:

| time | ParentImage → Image | what it is |
|---|---|---|
| 16:43:21 | `WINWORD.EXE` → `cmd.exe` | malicious Word macro fires, builds a `%RANDOM%.vbs` in `%APPDATA%` |
| 16:43:21 | `cmd.exe` → `wscript.exe` (`…\AppData\Roaming\20429.vbs`) | **the dropper** — VBScript that fetches the payload |
| 16:48:21 | `wscript`/`cmd` → `121214.tmp` | Cerber payload executed from `AppData\Roaming` |
| 16:48:41 | `cmd.exe` → `taskkill` + `del` | payload deletes itself to cover tracks |

**Answer:** The initial dropper is the VBScript **`20429.vbs`**, run by **`wscript.exe`**, which a **Word macro** (`WINWORD.EXE` → `cmd.exe`) wrote into `AppData\Roaming` and launched. It drops and executes **`121214.tmp`** (the Cerber payload).

> ⚠️ **Heads-up — the `cscript.exe` red herring.** Skim the raw EventCode=1 list and the first scripting host you hit is `cscript.exe` running `.vbs` files. It's tempting to call that the dropper — but look at the **User** (`NT AUTHORITY\SYSTEM`) and **ParentImage** (`…\Acronis\…\mms_mini.exe`): it's the backup product, completely unrelated. The actual dropper runs as **`bob.smith`** and uses **`wscript.exe`**. The whole reason Step 2 scopes to the user is to kill this trap. Always check *who* ran a process and *what launched it* before calling it malicious.

> 🧩 **Why `EventCode=1` and `Image`/`CommandLine` exist at all here.** Those fields don't live in the raw Sysmon event — they're *search-time extractions*. A real Sysmon event is XML: the event id is `<EventID>1</EventID>` and the process details are `<Data Name='Image'>…</Data>`, `<Data Name='CommandLine'>…</Data>`, etc. In production a Windows box, those get parsed by **`Splunk_TA_windows`**, which renames `EventID`→`EventCode` and pulls each `<Data Name='X'>` into a field `X`. This lab doesn't ship that TA, so a tiny add-on (`docker/apps/bots_sysmon_extractions/`) does the same job via `props.conf`/`transforms.conf`. The takeaway for an analyst: **convenient field names are a parsing convention, not ground truth.** If `EventCode=1` ever returns nothing, don't assume "no data" — check whether the sourcetype is actually being *parsed* (`… | head 1` and read `_raw`). Two gotchas this dataset shows off: (1) classic `WinEventLog` is `key=value` text so `EventCode` auto-extracts, but `XmlWinEventLog` is XML and needs a parser; (2) `props.conf` stanza names are **case-sensitive** — BOTSv1 indexed Sysmon under *both* `XmlWinEventLog:…` and `xmlwineventlog:…`, so the add-on lists both.

---

### Q44 — Suricata Cerber signatures
```spl
index=botsv1 sourcetype=suricata Cerber
| stats count by alert.signature_id alert.signature
| sort count | head 5
```
**Answer:** **5 Cerber alerts total**, across **3 signatures**. Sorted ascending, the rarest is `ETPRO TROJAN Ransomware/Cerber Checkin 2` (sig id **2816763**, fired **once**) — the outbound C2 check-in. The other two are `Cerber Checkin Error ICMP Response` (×2) and `Cerber Onion Domain Lookup` (×2).

---

### Q45 — Encryption phase URL
```spl
index=botsv1 sourcetype=stream:dns src_ip="192.168.250.100"
  ("query{}"="*onion*" OR "query{}"="*cerber*" OR "query{}"="*xmfir0*")
| stats count by "query{}"
| sort - count
```
**Answer:** `cerberhhyed5frqa.xmfir0.win` (TOR gateway used for the ransom note).

---

### Q46 — File server

**Part 1 — which server?** Look at where `we8105desk` opened SMB sessions:
```spl
index=botsv1 sourcetype=stream:smb src_ip="192.168.250.100"
| stats count by dest_ip
| sort - count
```
One IP dominates: **`192.168.250.20`** (~39k events) — the file server `we9041srv`. The other dest IPs are broadcast/noise.

**Part 2 — how many PDFs?** ⚠️ First trap: the obvious `filename="*.pdf.cerber"` returns **0**, because Cerber doesn't append `.cerber` to the original name — it *renames* the whole file to random characters (`report.pdf` → `aB3xK9.cerber`). The `.pdf` is gone, so you can't count encrypted PDFs by their *new* names. Instead count the distinct PDF names the host touched on the share **before** encryption — the SMB read traffic still carries them.

⚠️ Second trap — **don't just wildcard `"*.pdf*"`**. That's a substring match and it grabs junk like `windows.data.pdf.dll` (a Windows system DLL, not a document). Match names that actually *end* in `.pdf`:
```spl
index=botsv1 sourcetype=stream:smb dest_ip="192.168.250.20" filename="*.pdf"
| stats dc(filename) as pdfs values(filename) as files
```
**Answer:** File server **`192.168.250.20` (`we9041srv`)**, and **22** distinct PDFs were encrypted. (The loose `"*.pdf*"` reports 23 — the extra one is the `windows.data.pdf.dll` false positive. Always sanity-check *what* your wildcard matched.)

**The actual files** are a numbered document repository — names like:
```
000\000578.pdf   004\004157.pdf   097\097040.pdf   303\303951.pdf
317\317646.pdf   561\561054.pdf   714\714932.pdf   999\999354.pdf   … (22 total)
```

**How do you know a file is ransomware-hit (vs. a normal file)?** Three tell-tales, all visible in `stats count by filename`:
1. **Extension `.cerber`** — Cerber's signature extension. `sourcetype=stream:smb ".cerber"` shows **125** distinct files on this share renamed to random 10-char names like `fgOZ1-mA5H.cerber`, `4Lh0bYNVMq.cerber`. Random name + `.cerber` = encrypted.
2. **Ransom notes** dropped into every affected folder: `# DECRYPT MY FILES #.txt`, `.html`, `.url`, and `.vbs`. Search `sourcetype=stream:smb "DECRYPT"` — their presence *is* the proof of encryption.
3. **Original names vanish** — the tidy `NNN\NNNNNN.pdf` names stop appearing after ~17:04 and are replaced by the random `.cerber` names in the same directories. That before/after flip is the encryption event itself.

So the workflow is: originals (`*.pdf`, readable names) → attacker reads them → same paths reappear as random `*.cerber` + a `# DECRYPT MY FILES #` note. You count impact off the *originals*; you confirm encryption off the `.cerber` + ransom-note artifacts.

---

### Q47 — USB device

The USB trail lives in the **`winregistry`** sourcetype, *not* Sysmon — Windows records removable drives under the `USBSTOR` registry path. First confirm where the data is:
```spl
index=botsv1 host=we8105desk USBSTOR
| stats count by sourcetype
```
→ all the hits are `sourcetype=winregistry` (~193 events). Now pull the device's friendly name out of the registry key (the `FriendlyName` value holds the human-readable label):
```spl
index=botsv1 host=we8105desk sourcetype=winregistry key_path="*USBSTOR*" key_path="*friendlyname*"
| table _time key_path data
```
**Answer:** A USB flash drive was inserted; its friendly name is **`MIRANDA_PRI`** (`Ven_Generic&Prod_Flash_Disk`). 

> ⚠️ Earlier versions of this answer key said "Miranda_Tate_Unveiled" — that's wrong for this dataset. The registry `FriendlyName` value is literally **`MIRANDA_PRI`**; trust the data, not lore.

---

### Q48 — Timeline (example)

Times below are the **real** anchors verified against the data:

```
08/24/2016 16:43:21 - Word macro fires: WINWORD.EXE -> cmd.exe -> wscript.exe 20429.vbs   [Q43]
08/24/2016 16:48:12 - 20429.vbs resolves solidaritedeproximite.org (pulls the payload)    [Q42]
08/24/2016 16:48:21 - 121214.tmp written to AppData\Roaming and executed (Cerber)         [Q43]
08/24/2016 16:48:41 - osk.exe launched from AppData (persistence active; T1547.001)       [Q47]
08/24/2016 ~16:48   - DNS lookup for cerberhhyed5frqa.xmfir0.win + Suricata C2 check-in    [Q44/Q45]
08/24/2016 16:49:23 - vssadmin.exe delete shadows /all /quiet  (destroy backups; T1490)
08/24/2016 16:49:24 - bcdedit /set {default} recoveryenabled no  (disable recovery; T1490)
08/24/2016 17:04:33 - first .cerber file written on \\192.168.250.20 (encryption begins)   [Q46]
```
Note the order: the **dropper executes first (16:43)**, then sleeps/loops before reaching out to its download domain at 16:48 — that's why `solidaritedeproximite.org` (Q42's "patient zero") appears *after* the initial process launch, not before.

> 🔑 **Don't miss the anti-recovery stage.** At **16:49:23–24**, *before* encryption, Cerber runs `vssadmin delete shadows /all /quiet` and `bcdedit … recoveryenabled no` — **Inhibit System Recovery (T1490)**. This is *why* the victim can't just restore from Volume Shadow Copies, and it's a high-value detection point (legit software rarely deletes all shadows). A ransomware timeline that omits it is incomplete. Hunt it with: `host=we8105desk EventCode=1 (Image=*vssadmin* OR Image=*bcdedit*)`.
Reconstruct via (note the window starts *before* 16:48 so it actually captures patient zero):
```spl
index=botsv1 host=we8105desk
  (EventCode=1 OR sourcetype=stream:dns OR sourcetype=suricata)
  earliest="08/24/2016:16:40:00" latest="08/24/2016:17:30:00"
| sort _time
| table _time sourcetype EventCode Image "query{}" alert.signature
```

---

### Q49 — Dwell time
Two bookends: `t0` = the first compromise reach-out (the `solidaritedeproximite.org` DNS lookup, Q42), `t1` = the first `.cerber` file write on the share (Q46). Compute the earliest timestamp of each, then subtract:
```spl
index=botsv1
  (sourcetype=stream:dns "query{}"="*solidarite*")
  OR (sourcetype=stream:smb ".cerber")
| eval marker=case(sourcetype=="stream:dns","t0", sourcetype=="stream:smb","t1")
| stats min(_time) as ts by marker
| stats min(eval(if(marker=="t0",ts,null()))) as t0
        min(eval(if(marker=="t1",ts,null()))) as t1
| eval dwell_min=round((t1-t0)/60,1)
| eval t0=strftime(t0,"%H:%M:%S"), t1=strftime(t1,"%H:%M:%S")
```
**Answer:** `t0` = **16:48:12**, `t1` = **17:04:33** → dwell time ≈ **16 minutes** (16.3 min). Cerber moves fast — initial reach-out to encryption in well under half an hour.

> 🧰 **Why `case()` over `if()` for the marker:** `if(sourcetype=="stream:dns","t0","t1")` lumps *everything that isn't DNS* into `t1` — fine while the search only returns two sourcetypes, but fragile if a third ever sneaks in. `case(sourcetype=="stream:dns","t0", sourcetype=="stream:smb","t1")` labels each explicitly and returns `null` for anything unexpected (which then won't pollute your `t1`). Explicit beats "catch-all else" when the value drives a metric.

> 💡 If you instead anchor `t0` to the *very first* malicious process (the Word macro / `wscript.exe` at **16:43:21**), dwell is ~21 min. Either is defensible — just state which event you called "initial compromise." That explicitness is what a Tier 2 reviewer wants.

---

### Q50 — Incident report (example)

```
[Severity: CRITICAL] Cerber ransomware infection on host we8105desk
(192.168.250.100, user bob.smith) detected at 2016-08-24 17:00 UTC.

INITIAL VECTOR: malicious Word macro (WINWORD.EXE -> cmd.exe) that wrote and ran
a VBScript dropper (20429.vbs) via wscript.exe at 16:43, which reached out to
solidaritedeproximite.org at 16:48 and dropped/executed 121214.tmp (Cerber
payload) at 16:48:21.

IMPACT: encryption of bob.smith's local user profile and files on the remote
share \\we9041srv (192.168.250.20), including 22 PDFs and other office
documents (125 files renamed with the .cerber extension). The ransom note
points to TOR gateway cerberhhyed5frqa.xmfir0.win. Dwell time: approximately
16 minutes (16:48 -> 17:04).

CONTAINMENT: isolated we8105desk from the network; disabled bob.smith;
blocked solidaritedeproximite.org and cerberhhyed5frqa.xmfir0.win at the
perimeter.

IOCs delivered to Tier 2:
  Domains  : solidaritedeproximite.org, cerberhhyed5frqa.xmfir0.win
  Files    : 20429.vbs (dropper), 121214.tmp (payload), *.cerber (encrypted)
  Process  : WINWORD.EXE -> cmd.exe -> wscript.exe (20429.vbs) -> 121214.tmp
  Removable: USB flash drive FriendlyName "MIRANDA_PRI" inserted on we8105desk
  Suricata : ETPRO Cerber sig IDs 2816763 / 2816764 / 2820156
```

---

# Section 4 — CIM, Data Models & the Enterprise Security Workflow

> Prerequisite: CIM app installed (lightweight path) or ES trial installed (full path). See [04-enterprise-security.md](04-enterprise-security.md) for setup. **Part 1 (Q51–Q60)** only needs the CIM app + accelerated data models. **Part 2 (Q61–Q67)** additionally assumes you've created `index=notable` and `index=risk` under *Settings → Indexes*.
>
> Every Part-1 model query includes a raw-SPL fallback — if a data model returns zero rows, the sourcetype isn't CIM-tagged (missing TA), not a bug in your SPL.

### Q51
```spl
| datamodel
```
Lists every data model the CIM app installed. For acceleration status and backfill range:
```spl
| rest /services/datamodel/model
| table title acceleration.enabled acceleration.earliest_time
```
For Part 1 you want `Authentication`, `Web`, and `Network_Traffic` showing `acceleration.enabled = 1`. If they read `0`, go back to Prerequisites step 4 and enable acceleration — otherwise every `tstats summariesonly=t` below returns nothing.

---

### Q52
```spl
| datamodel Authentication Authentication search
| head 10
| table _time sourcetype user action src dest app
```
Syntax is `| datamodel <Model> <Dataset> search`. On BOTS v1 the `sourcetype` column should read `WinEventLog:Security`; `user` is the account (raw `TargetUserName`); `action` is `success`/`failure` (derived from EventCode 4624/4625). Zero rows ⇒ `Splunk_TA_windows` isn't installed/tagging — same root cause you'll dissect in Q60.

---

### Q53
```spl
| from datamodel:"Authentication"
| search action="failure"
| stats count by user
| sort - count | head 10
```
On BOTS v1 during Scenario A you should see `administrator` near the top — the brute-force target on `imreallynotbatman.com`. If you see zero rows, the Windows TA isn't tagging events into the Authentication DM — fall back to:
```spl
index=botsv1 sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name | sort - count | head 10
```
and then ask yourself: "what's missing for CIM to recognize this?"

---

### Q54
Outcome split:
```spl
| from datamodel:"Authentication"
| stats count by action
```
Two rows — `success` and `failure`. Then the noisiest failure sources:
```spl
| from datamodel:"Authentication"
| search action="failure"
| stats count by src
| sort - count | head 5
```
The top `src` is the brute-force origin — the same host you fingered in Section 3, found here without touching a single EventCode. Raw fallback: `... EventCode=4625 | stats count by Source_Network_Address`.

---

### Q55
```spl
| tstats summariesonly=t count
    FROM datamodel=Authentication
    WHERE Authentication.action="failure"
    BY Authentication.user
| rename Authentication.user as user
| sort - count | head 10
```
Same answer as Q53, runs in ~milliseconds against the accelerated DM instead of seconds. The risk of `summariesonly=t`: if acceleration is paused or behind, you silently get an *incomplete* answer with no warning. Set `summariesonly=f` when you're unsure (that's Q60).

---

### Q56
```spl
| tstats summariesonly=t count
    FROM datamodel=Authentication
    WHERE Authentication.action="failure"
    BY _time span=1h
```
`tstats ... BY _time span=1h` returns time-bucketed rows — switch to the **Visualization** tab → Line to see the brute-force hour spike. Split per targeted host:
```spl
| tstats summariesonly=t count
    FROM datamodel=Authentication
    WHERE Authentication.action="failure"
    BY _time span=1h Authentication.dest
```
This is the exact shape ES uses to render dashboard panels quickly.

---

### Q57
Top URLs:
```spl
| tstats summariesonly=t count
    FROM datamodel=Web
    WHERE Web.dest="192.168.250.70"
    BY Web.url
| rename Web.url as url
| sort - count | head 10
```
Status breakdown:
```spl
| tstats summariesonly=t count
    FROM datamodel=Web
    WHERE Web.dest="192.168.250.70"
    BY Web.status
```
Expect a flood from the Acunetix scan plus the brute-force POSTs, with a mix of `200`/`302`/`404`. Raw fallback: `index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" | top url`.

---

### Q58
```spl
| tstats summariesonly=t sum(All_Traffic.bytes_out) as bytes_out
    FROM datamodel=Network_Traffic
    WHERE All_Traffic.dest_ip="192.168.250.70"
    BY All_Traffic.src
| rename All_Traffic.src as src
| sort - bytes_out | head 10
```
The attacker IP from Section 3 (`23.22.63.114`) should dominate. Note the root dataset is `All_Traffic`, not `Network_Traffic`. If `Network_Traffic` returns nothing, BOTS v1's `stream:ip` isn't CIM-tagged — use the raw fallback:
```spl
index=botsv1 sourcetype=stream:ip dest_ip="192.168.250.70"
| stats sum(bytes_out) as bytes_out by src_ip
| sort - bytes_out | head 10
```

---

### Q59
```spl
| tstats summariesonly=t count dc(All_Traffic.dest_port) as distinct_ports
    FROM datamodel=Network_Traffic
    WHERE All_Traffic.dest_ip="192.168.250.70"
    BY All_Traffic.src
| rename All_Traffic.src as src
| sort - count | head 10
```
The attacker IP dominates by `count`, but its `distinct_ports` stays low (mostly 80/443) — that reads as "hammering the web service," not a port sweep. A source with high `distinct_ports` would be the scanner. Raw fallback: `sourcetype=stream:ip dest_ip="192.168.250.70" | stats count dc(dest_port) as distinct_ports by src_ip`.

---

### Q60
Data model (accelerated summaries only) vs raw:
```spl
| tstats summariesonly=t count
    FROM datamodel=Authentication
    WHERE Authentication.action="failure"
```
```spl
index=botsv1 sourcetype=WinEventLog:Security EventCode=4625 | stats count
```
If the DM number is lower, re-run with `summariesonly=f`:
```spl
| tstats summariesonly=f count
    FROM datamodel=Authentication
    WHERE Authentication.action="failure"
```
`summariesonly=f` fills the un-accelerated gap from raw events, so it should match the raw count; `=t` reads only pre-built summaries and lags while acceleration catches up. A gap that *persists even with `=f`* means the sourcetype isn't tagged into the model at all (TA missing) — the model literally can't see those events. Reconciling `=t`, `=f`, and raw is the habit that stops you shipping a detection that silently misses half its data.

---

### Q61
```spl
index=botsv1 sourcetype=stream:http
| eval is_sqli = if(match(uri, "(?i)(union|select|0x|%27|--)"), 1, 0)
| stats count, dc(uri_path) as unique_paths, sum(is_sqli) as sqli_hits
        by src_ip dest_ip
| where unique_paths >= 200 OR sqli_hits >= 5
| rename src_ip as src, dest_ip as dest
| eval signature = case(sqli_hits >= 5, "SQL Injection Probe",
                        unique_paths >= 200, "Web Scanner Activity",
                        true(), "Suspicious Web Activity"),
       severity  = if(sqli_hits >= 5, "high", "medium")
| table _time src dest signature severity count unique_paths sqli_hits
```
Expected hit: `23.22.63.114` → `192.168.250.70` with `signature="Web Scanner Activity"` (Acunetix, hundreds of paths). Tune thresholds based on what you saw in Q32 — every environment is different.

---

### Q62
```spl
<Q61 search>
| eval rule_name        = signature,
       rule_id          = case(sqli_hits >= 5, "WEB-SQLI-001",
                               true(),         "WEB-SCAN-001"),
       rule_description = "Self-practice Section 4 - web attack detection"
| collect index=notable
```
Verify:
```spl
index=notable rule_id IN ("WEB-SQLI-001", "WEB-SCAN-001")
| table _time src dest rule_name rule_id severity unique_paths sqli_hits
```
`| collect` runs as a write — re-running it appends duplicate rows. In production you'd schedule the search once with a defined cron and let ES handle de-duplication via the throttle window.

---

### Q63
```spl
index=notable
| stats earliest(_time) as first_seen,
        latest(_time)   as last_seen,
        count,
        latest(severity) as severity
    by src signature
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```
This is the SPL behind ES's *Incident Review* page — one row per unique notable group, count = how often it fired.

---

### Q64
```spl
index=notable
| bin span=1h _time as window
| stats min(_time) as first_event, count by window src signature severity
| stats earliest(first_event) as first_seen,
        latest(first_event)   as last_seen,
        sum(count) as total_events,
        count as throttled_groups
    by src signature severity
| convert ctime(first_seen) ctime(last_seen)
| sort - throttled_groups
```
`throttled_groups` ≈ how many independent 1-hour campaigns the attacker ran. ES's "Window duration" on a correlation search does the same thing with one config field.

---

### Q65
Drive-by domain hit:
```spl
index=botsv1 sourcetype=stream:http site="*solidaritedeproximite.org*"
| eval risk_object      = host,
       risk_object_type = "system",
       risk_score       = 30,
       risk_message     = "HTTP contact to known drive-by domain solidaritedeproximite.org",
       source_rule      = "Cerber - Drive-by Domain"
| table _time risk_object risk_object_type risk_score risk_message source_rule
| collect index=risk
```
Suricata TROJAN alerts:
```spl
index=botsv1 sourcetype=suricata alert.signature="*ET TROJAN*Cerber*"
| eval risk_object      = host,
       risk_object_type = "system",
       risk_score       = 60,
       risk_message     = "Suricata ET TROJAN signature: " . 'alert.signature',
       source_rule      = "Cerber - Suricata IDS"
| table _time risk_object risk_object_type risk_score risk_message source_rule
| collect index=risk
```
Both should target `host=we8105desk`. Verify:
```spl
index=risk | stats sum(risk_score) by risk_object source_rule
```

---

### Q66
```spl
index=risk
| stats sum(risk_score)       as total_risk,
        dc(source_rule)       as distinct_rules,
        values(source_rule)   as rules_fired,
        latest(_time)         as last_seen,
        values(risk_message)  as risk_details
    by risk_object risk_object_type
| where total_risk >= 80 AND distinct_rules >= 2
| convert ctime(last_seen)
| sort - total_risk
```
After Q65, `we8105desk` should appear with `total_risk = 90` (30 + 60) and `distinct_rules = 2` — a single high-confidence "ransomware on we8105desk" incident instead of dozens of noisy single-signal alerts. *This is the whole point of RBA.*

---

### Q67
```csv
host,ip,criticality,owner,business_unit
imreallynotbatman.com,192.168.250.70,critical,batman,marketing
we8105desk,192.168.250.100,medium,bob.smith,sales
we9041srv,192.168.250.20,high,file-share,sales
```
Upload as `assets.csv` under *Settings → Lookups → Lookup table files*, define `assets_lookup`, then:
```spl
index=notable
| lookup assets_lookup host AS dest OUTPUT criticality owner business_unit
| stats earliest(_time) as first_seen,
        latest(_time)   as last_seen,
        count,
        values(criticality)   as criticality,
        values(owner)         as owner,
        values(business_unit) as business_unit
    by src signature
| convert ctime(first_seen) ctime(last_seen)
| sort - count
```
Now an analyst sees not just `dest=192.168.250.70` but `criticality=critical, business_unit=marketing` — which is what drives triage priority. ES's Asset & Identity Framework just does this automatically via two pre-shipped lookups (`asset_lookup_by_str`, `identity_lookup_expanded`).

---

# Tips For Continued Practice

1. **Don't stop at one answer** — rewrite each SPL 2–3 different ways and compare
2. **Maintain your own cheat sheet** of patterns you reach for repeatedly
3. **Try BOTS v2 and v3** — `./setup.sh --v2` or `--v3` for fresh scenarios
4. **Convert your best queries into dashboards** — save each as a panel
5. **Write a real alert** — schedule a search that triggers when, for example, 4625 fires more than 10 times per minute from a single IP
6. **Schedule your Section 4 detections** — turn each `| collect` query into a saved search with a cron and let `index=notable` / `index=risk` build up over multiple days; then re-run Q63–Q64 and Q66 to see real triage data

Happy hunting.
