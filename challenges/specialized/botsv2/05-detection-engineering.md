# Track 5 — Detection Engineering (BOTS v2 / froth.ly APT)

Turn the froth.ly findings into **tuned, operational detections**. One
continuous build: hypothesis → rule → test on the true positive → tune out
noise → document → operationalize. Behaviour over IOC, so it survives the
next campaign.

> Reference detections: [SOLUTIONS.md](SOLUTIONS.md) (Track 5). Uses Track 1–3 findings.

---

### DE1 — Encoded / Empire PowerShell
**🔗 From:** Track 1 A2 · **ATT&CK:** T1059.001, T1027
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1
  (CommandLine="*-enc*" OR CommandLine="*FromBase64*" OR CommandLine="*-noP*" OR CommandLine="*AmsiUtils*" OR CommandLine="*DownloadData*")
| table _time host User CommandLine
```
**Test:** fires on the Empire stager across **3 hosts** (`wrk-btun`, `wrk-klagerf`, `venus`). **Tune:** legit admin scripts rarely use `-enc`+`-noP`+AMSI-bypass together; require ≥2 markers to cut FPs. High-signal.

### DE2 — PowerShell/shell spawned by WMI
**🔗 From:** Track 1 A3 · **ATT&CK:** T1047
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 (Image="*powershell*" OR Image="*cmd.exe")
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)"
| search ParentImage="*WmiPrvSE.exe" | table _time host ParentImage CommandLine
```
**Why gold:** a script host parented by `WmiPrvSE.exe` = remote WMI execution — a strong lateral-movement signal that fires on the venus compromise.

### DE3 — Scheduled-task persistence (SYSTEM + encoded)
**🔗 From:** Track 1 A4 · **ATT&CK:** T1053.005
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 CommandLine="*schtasks*Create*"
  (CommandLine="*/RU system*" OR CommandLine="*powershell*" OR CommandLine="*FromBase64*")
| table _time host CommandLine
```
Fires on the `Updater` task. Tune: alert on tasks whose action is an *encoded/registry-sourced* PowerShell (that's the malicious tell), not every task creation.

### DE4 — C2 beacon to a rare external IP (multi-signal)
**🔗 From:** Track 1 A5 / Track 3 · **ATT&CK:** T1071
**Build:** correlate a rarely-seen external destination across PAN + Suricata (don't alert on one source). Sketch: newly-seen `dst_ip` in `pan:traffic` **joined** with a Suricata hit to the same IP within a window. Fires on `45.77.65.211`. Multi-signal beats single-signal.

### DE5 — SSH brute force
**🔗 From:** Track 1 B1 · **ATT&CK:** T1110
```spl
index=botsv2 sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)" | bin _time span=5m
| stats count by _time src_ip | where count > 20
```
Threshold on failures/5-min per source. Pair with an "Accepted password" join to escalate *brute-force-then-success*.

### DE6 — Network trojan / macOS backdoor
**🔗 From:** Track 1 B3 · **ATT&CK:** T1071
```spl
index=botsv2 sourcetype=suricata (alert.category="A Network Trojan was detected" OR alert.signature="*Backdoor*")
| stats count by src_ip alert.signature
```
The Mac (`kutekitten`) has osquery but no behavioural EDR, so the IDS category is what *alerts*; confirm the malware on-host via `osquery_results`. Fires on Quimitchin from `10.0.4.2`.

### DE7 — Tooling drop via msiexec from temp
**🔗 From:** Track 1 A6 · **ATT&CK:** T1105
```spl
index=botsv2 sourcetype=*ysmon* EventCode=1 CommandLine="*msiexec*" (CommandLine="*c:\\temp*" OR CommandLine="*\\download\\*")
```
Fires on `python.msi` in `c:\temp\download`. Legit installs rarely run from user-temp paths.

### DE8 — Tune, backtest & operationalize
**🔗 Builds on DE1–DE7.** Backtest each across August (should light up Aug 15/24, quiet otherwise); estimate precision; add exclusions. For each: notable title, ATT&CK id, severity, data source, response. Prefer **RBA** — score `host`/`user` risk (an APT trips *many* low-confidence rules; risk aggregation surfaces the compromised host better than any single alert).

---

➡️ Reference detections: [SOLUTIONS.md](SOLUTIONS.md) (Track 5).
