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
> | Section 4 (Q51–Q60)  | Per question — Scenario A or B window |

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
index=botsv1 sourcetype=stream:http | top limit=1 dest_ip
```
**Answer:** `192.168.250.70` (imreallynotbatman.com).

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
| stats count min(_time) as start max(_time) as end
| eval duration_minutes = (end - start) / 60
| eval start_time = strftime(start, "%y-%m-%d %H:%M:%S")
| eval end_time = strftime(end, "%y-%m-%d %H:%M:%S")
| table count start_time end_time duration_minutes
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

### Q38 — Post-breach file upload

⚠️ **Common pitfall:** the upload is *not* from the brute-force IP (`23.22.63.114`). Po1s0n1vy used the scanner box (`40.80.148.42`) for the upload — credentials passed between boxes. If you filtered by `src_ip=23.22.63.114` you'll get zero results.

**Option A — fastest, free-text:**
```spl
index=botsv1 poisonivy
| stats count by sourcetype src_ip dest_ip
```
You'll see `stream:http` and `fgt_utm` matches sourced from `40.80.148.42`.

**Option B — FortiGate UTM (file transfer captured directly):**
```spl
index=botsv1 sourcetype=fgt_utm filename=*
| stats count by src_ip dest_ip filename
| sort - count
```
The `filename` field is directly parsed by the FortiGate add-on — you'll see `poisonivy-is-coming-for-you-batman.jpeg` and `3791.exe` from `40.80.148.42` → `192.168.250.70`.

**Option C — stream:http multipart upload (more "by the book"):**
```spl
index=botsv1 sourcetype=stream:http http_method=POST "filename="
| rex field=_raw "filename=\"(?<uploaded_file>[^\"]+)\""
| where isnotnull(uploaded_file)
| table _time src_ip dest_ip uploaded_file uri_path
```

**Lesson learned:** APT actors split roles across multiple boxes. *Don't anchor on a single attacker IP* during an investigation — pivot on the *action* (the file transfer) and let the IP fall out of the data.

---

### Q39 — Defacement file

Same gotcha as Q38 — upload came from `40.80.148.42`, not the brute-force IP. Use either of the approaches below.

**Option A — fastest, via FortiGate UTM:**
```spl
index=botsv1 sourcetype=fgt_utm filename=*
| stats values(filename) as files by src_ip dest_ip
```

**Option B — via stream:http multipart parsing:**
```spl
index=botsv1 sourcetype=stream:http http_method=POST "filename=" src_ip=40.80.148.42
| rex field=_raw "filename=\"(?<fname>[^\"]+)\""
| where isnotnull(fname)
| stats values(fname) by uri_path
```

**Option C — confirm via the GET side (clients viewing the defaced page):**
```spl
index=botsv1 sourcetype=stream:http src_ip=192.168.250.70 http_method=GET
| search "*.jpeg" OR "*.jpg"
| stats count by uri_path
```

**Answer:** `poisonivy-is-coming-for-you-batman.jpeg`. The .exe payload `3791.exe` (MD5 `ec78c938...`) was uploaded alongside it — see the [BOTS v1 official walkthrough Q109](../splunk-bots/botsv1/README.md) for the malware analysis chain.

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
```spl
index=botsv1 host=we8105desk
| stats values(src) values(src_ip) values(dest_ip) by host
```
Or look at DHCP / Windows logs.
**Answer:** `192.168.250.100`.

---

### Q42 — First suspicious DNS
```spl
index=botsv1 sourcetype=stream:dns src=192.168.250.100
| stats earliest(_time) as first_seen count by query
| sort first_seen
| head 20
```
**Answer:** `solidaritedeproximite.org` (the typical drive-by landing for the Cerber dropper).

---

### Q43 — Initial dropper
```spl
index=botsv1 host=we8105desk EventCode=1
| table _time User ParentImage Image CommandLine
| sort _time
```
**Answer:** `cscript.exe` running a VBScript that drops `121214.tmp` (the Cerber payload).

---

### Q44 — Suricata Cerber signatures
```spl
index=botsv1 sourcetype=suricata Cerber
| stats count by alert.signature_id alert.signature
| sort count | head 5
```
**Answer:** The lowest-firing signature is usually the one that fires once on the outbound C2 callback.

---

### Q45 — Encryption phase URL
```spl
index=botsv1 sourcetype=stream:dns src=192.168.250.100
  (query="*onion*" OR query="*cerber*" OR query="*hjhqmbxyinislkkt*")
| stats count by query
| sort - count
```
**Answer:** `cerberhhyed5frqa.xmfir0.win` (TOR gateway used for the ransom note).

---

### Q46 — File server
```spl
index=botsv1 host=we8105desk
  (sourcetype=*smb* OR EventCode IN (5140,5145))
| stats count by dest_ip ShareName
| sort - count
```
**Answer:** The fileserver IP (typically `192.168.250.20`, hostname `we9041srv`).

PDF count:
```spl
index=botsv1 *.pdf
| search filename="*.cerber*" OR file_name="*.cerber*"
| stats dc(filename) as encrypted_pdfs by host
```

---

### Q47 — USB device
```spl
index=botsv1 host=we8105desk
  (EventCode=43 OR "USBSTOR" OR DeviceClass="*disk*")
| table _time host TargetObject Image
```
Or:
```spl
index=botsv1 host=we8105desk EventCode=12 TargetObject="*USBSTOR*"
```
**Answer:** USB device "Miranda_Tate_Unveiled" (from the BOTS v1 lore).

---

### Q48 — Timeline (example)

```
08/24/2016 17:00  - we8105desk visits solidaritedeproximite.org (drive-by landing)
08/24/2016 17:01  - cscript.exe executes a VBScript dropper
08/24/2016 17:02  - 121214.tmp written and executed (Cerber payload)
08/24/2016 17:03  - DNS lookup for cerberhhyed5frqa.xmfir0.win (C2 / ransom URL)
08/24/2016 17:04  - SMB connections to the file server, encryption begins
08/24/2016 17:15  - Ransom note dropped; encryption phase complete
```
Reconstruct via:
```spl
index=botsv1 host=we8105desk
  (EventCode=1 OR sourcetype=stream:dns OR sourcetype=suricata)
  earliest="08/24/2016:17:00:00" latest="08/24/2016:17:30:00"
| sort _time
| table _time sourcetype EventCode Image query alert.signature
```

---

### Q49 — Dwell time
Use the initial DNS query and the first encrypted-file write as your bookends:
```spl
index=botsv1 host=we8105desk
  (query="*solidarite*" OR file_name="*.cerber*")
| stats earliest(_time) as t0 latest(_time) as t1
| eval dwell_min=round((t1-t0)/60,1)
```
**Answer:** Approximately 10–15 minutes — Cerber moves very fast.

---

### Q50 — Incident report (example)

```
[Severity: CRITICAL] Cerber ransomware infection on host we8105desk
(192.168.250.100, user bob.smith) detected at 2016-08-24 17:15 UTC.

INITIAL VECTOR: drive-by download from solidaritedeproximite.org at 17:00,
delivering a VBScript via cscript.exe which dropped 121214.tmp (Cerber payload)
at 17:02.

IMPACT: encryption of bob.smith's local user profile and files on the remote
share \\we9041srv, including N PDFs and other office documents. The ransom
note points to TOR gateway cerberhhyed5frqa.xmfir0.win. Dwell time:
approximately 12 minutes.

CONTAINMENT: isolated we8105desk from the network; disabled bob.smith;
blocked solidaritedeproximite.org and cerberhhyed5frqa.xmfir0.win at the
perimeter.

IOCs delivered to Tier 2:
  Domains  : solidaritedeproximite.org, cerberhhyed5frqa.xmfir0.win
  Files    : 121214.tmp, *.cerber, *.cerber3
  Process  : cscript.exe -> 121214.tmp
  Suricata : ET TROJAN W32/Cerber signature IDs (see attached)
```

---

# Section 4 — Enterprise Security Workflow

> Prerequisite: CIM app installed (lightweight path) or ES trial installed (full path). See [04-enterprise-security.md](04-enterprise-security.md) for setup. Q53, Q58–Q60 also assume you've created `index=notable` and `index=risk` under *Settings → Indexes*.

### Q51
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

### Q52
```spl
| tstats summariesonly=t count
    FROM datamodel=Authentication
    WHERE Authentication.action="failure"
    BY Authentication.user
| rename Authentication.user as user
| sort - count | head 10
```
Same answer as Q51, runs in ~milliseconds against the accelerated DM instead of seconds. The risk of `summariesonly=t`: if acceleration is paused or behind, you silently get an *incomplete* answer with no warning. Set `summariesonly=f` when you're unsure.

---

### Q53
```spl
| tstats summariesonly=t sum(All_Traffic.bytes_out) as bytes_out
    FROM datamodel=Network_Traffic
    WHERE All_Traffic.dest_ip="192.168.250.70"
    BY All_Traffic.src
| rename All_Traffic.src as src
| sort - bytes_out | head 10
```
The attacker IP from Section 3 (`23.22.63.114`) should dominate. If `Network_Traffic` returns nothing, BOTS v1's `stream:ip` isn't CIM-tagged — use the raw fallback:
```spl
index=botsv1 sourcetype=stream:ip dest_ip="192.168.250.70"
| stats sum(bytes_out) as bytes_out by src_ip
| sort - bytes_out | head 10
```

---

### Q54
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

### Q55
```spl
<Q54 search>
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

### Q56
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

### Q57
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

### Q58
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

### Q59
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
After Q58, `we8105desk` should appear with `total_risk = 90` (30 + 60) and `distinct_rules = 2` — a single high-confidence "ransomware on we8105desk" incident instead of dozens of noisy single-signal alerts. *This is the whole point of RBA.*

---

### Q60
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
6. **Schedule your Section 4 detections** — turn each `| collect` query into a saved search with a cron and let `index=notable` / `index=risk` build up over multiple days; then re-run Q56–Q57 and Q59 to see real triage data

Happy hunting.
