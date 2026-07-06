# Playbook 4 — Privilege Escalation Detection — Solutions

Reference answers, verified against the loaded `index=botsv2`.
Questions: [../question/04-privilege-escalation-detection.md](../question/04-privilege-escalation-detection.md)

---

### Steps 1–3 — Alert, event details, affected changes
```spl
index=botsv2 sourcetype=wineventlog:security EventCode IN (4728,4732)
| table _time ComputerName EventCode Message | sort _time
```
Verified chain, all `2017-08-24`:

| Time | Host | EventCode | Subject | Member added | Group |
|---|---|---|---|---|---|
| 03:42:01 | wrk-btun | 4728 | **billy.tun** | WRK-BTUN\svcvnc | (global) |
| 03:42:09 | wrk-btun | 4732 | **billy.tun** | WRK-BTUN\svcvnc | BUILTIN\Administrators |
| 04:02:54 | wrk-klagerf | 4728 | **service3** | WRK-KLAGERF\svcvnc | (global) |
| 04:10:51 | venus | 4728 | **service3** | VENUS\svcvnc | (global) |
| 04:18:58 | mercury | 4732 | **service3** | FROTHLY\svcvnc | BUILTIN\Administrators |

The same backdoor local account, **`svcvnc`**, is added to Administrators on host after host. The *Subject* changes partway through — `billy.tun` (the phishing foothold) does the first escalation on its own host, then **`service3`** (the account already known to drive WMI lateral movement) repeats it on three more hosts.

### Step 4 — Validate / corroborate
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 host=mercury (CommandLine="*-enc*" OR CommandLine="*WmiPrvSE*")
```
⚠️ **`mercury` has no independent corroborating process evidence** in this lab's Sysmon telemetry (no encoded PowerShell, no WMI-spawned shell found). Report it as **a lead flagged by this event alone — needs further evidence**, not a confirmed compromise, while `wrk-btun`/`venus`/`wrk-klagerf` are independently corroborated (see the [Playbook 2 alternate case](02-malware-alert-investigation.md#alternate-case-v2-powershell-empire)).

### Step 5 — Anti-forensics
```spl
index=botsv2 sourcetype=wineventlog:security EventCode=1102
```
**`2017-08-26 05:30:27`**, `wrk-klagerf`, Subject **`service3`** — the audit log was cleared, two days after the escalation chain. Deliberate anti-forensics, not routine administration.

---

➡️ Next: [Playbook 5 — Data Exfiltration Detection](05-data-exfiltration-detection.md)
