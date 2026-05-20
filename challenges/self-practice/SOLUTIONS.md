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
index=botsv1 sourcetype=suricata | top limit=10 alert.signature
```

---

### Q22
```spl
index=botsv1 sourcetype=suricata "alert.severity"=1 | stats count
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
index=botsv1 sourcetype=stream:http http_method=POST uri_path="*login*"
  dest_ip=192.168.250.70
| stats count by src_ip
| sort - count
```
**Answer:** `23.22.63.114` (brute-force host — different from the scanner; a later phase).

---

### Q35 — Brute force duration
```spl
index=botsv1 sourcetype=stream:http http_method=POST uri_path="*login*"
  src_ip=23.22.63.114
| stats count earliest(_time) as start latest(_time) as end
| eval duration_min=round((end-start)/60,1)
| eval start=strftime(start,"%F %T"), end=strftime(end,"%F %T")
```
**Answer:** Hundreds of attempts within a few minutes.

---

### Q36 — Unique passwords
```spl
index=botsv1 sourcetype=stream:http http_method=POST src_ip=23.22.63.114
  uri_path="*login*"
| rex field=form_data "passwd=(?<pwd>[^&]+)"
| stats dc(pwd) as unique_passwords values(pwd) as password_list
```
**Answer:** ~400+ unique passwords (close to the attempt count — each password tried once = classic dictionary attack).

---

### Q37 — Successful password
```spl
index=botsv1 sourcetype=stream:http http_method=POST src_ip=23.22.63.114
  uri_path="*login*"
| rex field=form_data "passwd=(?<pwd>[^&]+)"
| stats count by pwd bytes_out
| sort bytes_out
```
The outlier `bytes_out` row is the success — most failures share one consistent response size.
**Answer:** `batman` (the admin password).

---

### Q38 — Post-breach file upload
```spl
index=botsv1 sourcetype=stream:http http_method=POST
  src_ip=23.22.63.114
  (uri_path="*upload*" OR form_data="*filename=*")
| table _time uri_path form_data
```
You will see POSTs to the Joomla admin upload endpoint.

---

### Q39 — Defacement file
```spl
index=botsv1 sourcetype=stream:http http_method=POST src_ip=23.22.63.114
| rex field=form_data "filename=\"(?<fname>[^\"]+)\""
| where isnotnull(fname)
| stats values(fname) by uri_path
```
**Answer:** `poisonivy-is-coming-for-you-batman.jpeg`.

---

### Q40 — IOC summary (Scenario A)

| IOC type | Value |
|---|---|
| Victim IP | `192.168.250.70` (imreallynotbatman.com) |
| Scanner IP | `40.80.148.42` |
| Scanner tool | Acunetix WVS |
| Brute force IP | `23.22.63.114` |
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

# Tips For Continued Practice

1. **Don't stop at one answer** — rewrite each SPL 2–3 different ways and compare
2. **Maintain your own cheat sheet** of patterns you reach for repeatedly
3. **Try BOTS v2 and v3** — `./setup.sh --v2` or `--v3` for fresh scenarios
4. **Convert your best queries into dashboards** — save each as a panel
5. **Write a real alert** — schedule a search that triggers when, for example, 4625 fires more than 10 times per minute from a single IP

Happy hunting.
