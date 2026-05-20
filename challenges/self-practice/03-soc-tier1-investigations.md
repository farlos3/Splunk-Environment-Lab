# Section 3 — SOC Tier 1 Investigations (Q31–Q50)

🟠 **Level:** Intermediate
🎯 **Goal:** Practice the investigative mindset — form a hypothesis, gather evidence, build a timeline, and extract IOCs.

> Questions in this section often have **multiple valid approaches** — what matters is the reasoning, not memorizing one command.

---

## Scenario A: Web Server Attack (Q31–Q40)

> The website `imreallynotbatman.com` has been defaced. As the Tier 1 analyst on shift, you need to answer the following.
>
> **Time picker for this scenario:** `8/10/2016 00:00:00` → `8/12/2016 00:00:00`

### Q31 — Identify the victim

What is the IP address of the `imreallynotbatman.com` web server?

**Hint:** It's the `dest_ip` that receives the most `stream:http` traffic — web servers attract a lot of inbound requests.
**SOC angle:** Before chasing the attacker, identify the asset under attack.

---

### Q32 — Reconnaissance phase

Is anyone scanning the web server? Find the top external `src_ip` values by
both event count and distinct path count (`uri_path`).

**Hint:**
```spl
sourcetype=stream:http dest_ip=<web_ip>
| stats count dc(uri_path) as unique_paths by src_ip
| sort - unique_paths | head 10
```
**SOC angle:** Vulnerability scanners request many paths in a short time — high `unique_paths` per source is the giveaway.

---

### Q33 — Scanner identification

For the scanning IP from Q32, inspect `http_user_agent`. Which scanning tool was used?

**Hint:**
```spl
sourcetype=stream:http src_ip=<scanner_ip>
| top http_user_agent
```
**SOC angle:** Scanners usually identify themselves in the User-Agent string (Nikto, Acunetix, sqlmap, OWASP ZAP, ...).

---

### Q34 — Brute force detection

Did a brute-force attack hit the login page? Count POST requests to the
login URL grouped by `src_ip`.

**Hint:**
```spl
sourcetype=stream:http http_method=POST uri_path="*login*"
| stats count by src_ip
| sort - count
```
**SOC angle:** A single IP issuing hundreds of POSTs to a login endpoint in a short window is brute force.

---

### Q35 — Attack volume and duration

For the attacker IP from Q34, how many login attempts were made, and over
how long? Report the start time, end time, and duration in minutes.

**Hint:**
```spl
sourcetype=stream:http http_method=POST uri_path="*login*" src_ip=<attacker_ip>
| stats count earliest(_time) as start latest(_time) as end
| eval duration_min=round((end-start)/60,1)
| eval start=strftime(start,"%F %T"), end=strftime(end,"%F %T")
```
**SOC angle:** Always report the start and end of an attack window in any triage note.

---

### Q36 — Unique passwords tried

How many distinct passwords did the attacker try?

**Hint:** Look at the `form_data` field on POST requests — it contains
`passwd=...&...`. Extract the password with `rex`, then `dc(...)` it.
```spl
sourcetype=stream:http http_method=POST src_ip=<attacker_ip> uri_path="*login*"
| rex field=form_data "passwd=(?<pwd>[^&]+)"
| stats dc(pwd) as unique_passwords
```
**SOC angle:** A wordlist tells you something about the attacker — dictionary attack vs. targeted, English vs. localized, hash-cracked vs. random.

---

### Q37 — Which password succeeded?

Which password resulted in a **successful** login? Spotting it requires
comparing response sizes — most attempts return a "failed" page of a
consistent size; the successful one will differ.

**Hint:**
```spl
sourcetype=stream:http http_method=POST src_ip=<attacker_ip> uri_path="*login*"
| rex field=form_data "passwd=(?<pwd>[^&]+)"
| stats count by pwd bytes_out
| sort bytes_out
```
**SOC angle:** When you can't see content directly, look for response-size or status-code outliers.

---

### Q38 — Post-breach file upload

After successful login, was anything uploaded? Find the file upload request.

**Hint:** Look for POSTs to upload-related paths, or POSTs whose `form_data` contains `multipart` / `Content-Disposition`.
```spl
sourcetype=stream:http http_method=POST src_ip=<attacker_ip>
  (uri_path="*upload*" OR form_data="*Content-Disposition*")
| table _time src_ip uri_path form_data
```
**SOC angle:** Web-shell upload is the typical pivot from "logged in" to "owns the server".

---

### Q39 — Defacement file

What is the filename used for the defacement (image or HTML page)?

**Hint:** Extract the filename from `form_data` (`filename="..."`).
```spl
sourcetype=stream:http http_method=POST src_ip=<attacker_ip>
| rex field=form_data "filename=\"(?<fname>[^\"]+)\""
| where isnotnull(fname)
| table _time fname
```
**SOC angle:** The chosen filename often hints at the threat actor or campaign.

---

### Q40 — IOC summary for Scenario A

Summarize the IOCs from this incident:
- Attacker IP(s)
- Scanner tool / User-Agent
- Targeted username
- Successful password
- Uploaded filename (with hash if available)

**SOC angle:** A clean IOC list is the deliverable Tier 1 hands to Tier 2 / Incident Response — completeness is what makes the handoff useful.

---

## Scenario B: Ransomware Outbreak (Q41–Q50)

> Workstation `we8105desk` (user `bob.smith`) was hit by **Cerber ransomware** on August 24, 2016.
>
> **Time picker for this scenario:** `8/24/2016 00:00:00` → `8/25/2016 00:00:00`

### Q41 — Patient zero

What is the IP address of `we8105desk`?

**Hint:**
```spl
index=botsv1 we8105desk
| stats values(src_ip) values(dest_ip) by host
```
or look at DHCP / Windows logs.
**SOC angle:** Identify the first infected host — the rest of the investigation hangs on this.

---

### Q42 — First suspicious domain

What is the first suspicious DNS query made by `we8105desk` on 8/24/2016?

**Hint:**
```spl
sourcetype=stream:dns src=<we8105_ip>
| stats earliest(_time) as first_seen count by query
| sort first_seen
| head 20
```
Look for domains that stand out — unusual TLDs, random-looking labels, long names.
**SOC angle:** Drive-by and phishing landing pages routinely use throwaway domains.

---

### Q43 — Initial dropper

Was an executable or script run on `we8105desk` just before the ransomware
fired? Look at process-creation events around the infection time.

**Hint:**
```spl
index=botsv1 host=we8105desk EventCode=1
| table _time User ParentImage Image CommandLine
| sort _time
```
Watch for `cscript.exe`, `wscript.exe`, `powershell.exe`, `.tmp`, `.vbs`.
**SOC angle:** Cerber's typical chain: VBScript dropper → `.tmp` payload → encryption binary.

---

### Q44 — Suricata Cerber signatures

How many Suricata alerts mention Cerber, and which signature fired the
fewest times?

**Hint:**
```spl
index=botsv1 sourcetype=suricata Cerber
| stats count by alert.signature_id alert.signature
| sort count | head 5
```
**SOC angle:** The lowest-firing signature is often the one that confirms a single high-fidelity action (e.g., the C2 callback after encryption).

---

### Q45 — Ransom note destination

After encryption, Cerber points the user to a payment / decryption portal.
What domain (often a `.onion` mirror or TOR gateway) is involved?

**Hint:**
```spl
sourcetype=stream:dns src=<we8105_ip>
| search query="*onion*" OR query="*cerber*"
| stats count by query
```
**SOC angle:** The ransom-note URL itself is a high-value IOC for both detection and threat-intel sharing.

---

### Q46 — File-server impact

Which file server did `we8105desk` connect to during the outbreak, and how
many PDFs were encrypted there?

**Hint:**
```spl
index=botsv1 host=we8105desk (sourcetype=*smb* OR EventCode IN (5140,5145))
| stats count by dest_ip ShareName
| sort - count
```
For the PDF count, look for events that show new `.cerber` files written:
```spl
index=botsv1 *.pdf.cerber* OR *.cerber*
| stats dc(filename) by host
```
**SOC angle:** Lateral encryption via SMB shares is the textbook ransomware blast-radius expansion.

---

### Q47 — USB device evidence

Was a USB device inserted into Bob Smith's workstation? If so, what was its name?

**Hint:**
```spl
index=botsv1 host=we8105desk
  (EventCode=43 OR "USBSTOR" OR DeviceClass="*disk*")
| table _time host TargetObject Image
```
Or look at registry writes touching `USBSTOR`:
```spl
index=botsv1 host=we8105desk EventCode=12 TargetObject="*USBSTOR*"
```
**SOC angle:** USB-drop is a classic initial-access technique — always check.

---

### Q48 — Build the attack timeline

Construct a timeline of attack stages ordered by time:
1. Initial recon (suspicious DNS / web visit)
2. Dropper execution
3. C2 callback
4. Encryption begins
5. Encryption complete + ransom note dropped

**Hint:** Pull events from `EventCode=1`, `stream:dns`, and `suricata` for the host within the infection window and sort by `_time`.
**SOC angle:** A clean timeline is what Tier 2 / Incident Response uses to plan containment.

---

### Q49 — Dwell time

Compute the **dwell time** — minutes between initial compromise and the
start of file encryption.

**Hint:**
```spl
... | stats earliest(_time) as t0 latest(_time) as t1
| eval dwell_min=round((t1-t0)/60,1)
```
**SOC angle:** Dwell time is a top SOC KPI — the lower, the better.

---

### Q50 — Incident report

Write a short incident report (3–5 sentences) covering:
- **What** happened (ransomware family + impact)
- **When** it was detected and when the attack started (dwell time)
- **Where** — host, IP, user
- **How** — initial vector and propagation method
- **IOCs** to hand to the IR team

**Example template:**
```
[Severity: HIGH] Cerber ransomware infection on host we8105desk
(10.x.x.x, user bob.smith) detected at 2016-08-24 HH:MM.
Initial vector: drive-by download from <domain>, followed by VBScript
dropper (<filename>) at HH:MM. Encryption phase started at HH:MM,
affecting N local files and M files on file server 10.x.x.x.
Dwell time: NN minutes. IOCs attached: <domains>, <hashes>, <filenames>.
```
**SOC angle:** A short, complete written summary is the final deliverable of a Tier 1 triage — concise and complete is the standard.

---

🎉 **You've completed all 50 exercises.**

Check your work in → [SOLUTIONS.md](SOLUTIONS.md)

## Next Steps

- Repeat the exercises in 3–7 days without looking at the solutions
- Work through the official BOTS v1 walkthrough in [../splunk-bots/botsv1/](../splunk-bots/botsv1/)
- If you have BOTS v2 / v3, load them with `./setup.sh --v2` or `--v3` for new scenarios
- Practice building dashboards, scheduled alerts, and saved searches from the queries you wrote here
