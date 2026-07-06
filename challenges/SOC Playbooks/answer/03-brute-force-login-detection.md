# Playbook 3 — Brute Force Login Detection — Solutions

Reference answers, verified against the loaded `index=botsv1` / `index=botsv2`.
Questions: [../question/03-brute-force-login-detection.md](../question/03-brute-force-login-detection.md)

---

## Primary case (v1: Joomla)

### Steps 1–3 — Alert, failed attempts, count
```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri_path=/joomla/administrator/index.php
| stats count earliest(_time) as first latest(_time) as last by src_ip
```
**`23.22.63.114`** → **412** POST attempts. (Compute `last - first` for duration.)

### Step 4 — Targeted username
```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri_path=/joomla/administrator/index.php
| rex field=form_data "username=(?<user>[^&]+)"
```
Targeted username: **`admin`**.

### Step 5 — Source IP
Confirmed above: **`23.22.63.114`**, `Python-urllib/2.7` UA — distinct from the Acunetix scanner (`40.80.148.42`) hitting the same server (see [Playbook 6](06-web-application-attack-detection.md)).

### Step 6 — Geo-location
```spl
index=botsv1 sourcetype=stream:http src_ip="23.22.63.114" earliest="08/10/2016:00:00:00" latest="08/12/2016:00:00:00"
| iplocation src_ip | stats count by src_ip Country City
```
**United States, Ashburn** — cloud-hosted (AWS), not the brute-forcer's real physical location; treat geo as a data point, not proof of origin.

### Step 7 — Successful logon
```spl
index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri_path=/joomla/administrator/index.php
| rex field=form_data "passwd=(?<password>[^&]+)"
| stats count by password | sort - count
```
All passwords used exactly once **except `batman` (count 2)** — used once during the brute force, once for the actual compromised login. **Answer: `batman`.**

### Steps 8–9 — Response
Block `23.22.63.114`; force-reset the `admin` credential.

---

## Alternate case (v2: SSH brute force)

```spl
index=botsv2 sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)" | stats count by src_ip | sort - count
```
Top offender: **`58.242.83.20`**, **26,174** failures, targeting `gacrux`. `iplocation` → **China**.
```spl
index=botsv2 sourcetype=linux_secure "Accepted password"
| rex "Accepted password for (?<user>\S+) from (?<src_ip>\S+)"
```
The one successful login — **`klager` from `71.39.18.125`** — is a **different IP entirely** from every brute-force source. Lesson: the loudest source rarely correlates with the successful one; verify Step 7 independently of Step 5.

---

➡️ This escalates to [Playbook 6 — Web Application Attack Detection](06-web-application-attack-detection.md)
