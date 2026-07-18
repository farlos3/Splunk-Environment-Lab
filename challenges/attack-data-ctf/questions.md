# Attack Data micro-CTF — Questions

Scope every search to the named family with `host=<family>`. See
[README.md](README.md) for field conventions. Full SPL + verified answers
live in [SOLUTIONS.md](SOLUTIONS.md) — try first.

### AD01 — acidrain
Which single process is the most common *parent* across every
process-create event in this capture?

*Hint: this is background package-manager noise, not the wipe itself — `stats count by ParentImage`.*

### AD02 — agent_tesla
What domain does the AgentTesla PowerShell loader reach out to for its
second-stage payload?

*Hint: PowerShell Script Block Logging captures the full command — look for a `DownloadString` call.*

### AD03 — amadey
What is the full path of the executable Amadey used to establish
persistence via the Startup registry key?

*Hint: a Sysmon registry-SetValue event under `...\Explorer\User Shell Folders\Startup` names the process (`Image`) making the change.*

### AD04 — awfulshred
Which exact command does this Linux wiper's host repeatedly run to
enumerate running processes?

*Hint: look at process-create events with `ps` as the image — command-line arguments included.*

### AD05 — azorult
AZORult drops a Remote Utilities (`rutserv.exe`) remote-access tool.
What destination IP:port does it phone home to?

*Hint: filter network-connection events to the process named `rutserv.exe`.*

### AD06 — brute_ratel
Amid the noise, one process-create event has a parent under
`C:\Temp\poc_2\` — the actual Brute Ratel C4 agent. What process does it
launch as its child?

*Hint: `stats count by ParentProcessName` first to spot the non-Splunk-forwarder parent, then look at what it spawned.*

### AD07 — chaos_ransomware
What is the full path of the Chaos ransomware payload launched from a
Downloads folder?

*Hint: process-create, non-Splunk-forwarder parent (`explorer.exe`).*

### AD08 — clop
Clop registers a new Windows service pointing at a suspicious binary in
`C:\Temp`. What is the service's name?

*Hint: Service Control Manager EventCode 7045 carries `ServiceName` and `ImagePath`.*

### AD09 — conti
What exact command does Conti use to archive the `C$` admin share's
`Public\Documents` folder before exfiltration?

*Hint: EventCode=4688 (Security), look at `CommandLine` for a 7-Zip invocation.*

### AD10 — cyclopsblink
Aside from routine SSH and Splunk-forwarder traffic, one process on this
host reaches an unusual destination — the cloud instance metadata
service. What IP and port?

*Hint: network-connection events, `DestinationIp`; the metadata service has a well-known link-local address.*

### AD11 — dcrat
DCRat's camera-enumeration script block queries a specific WMI class to
find connected imaging/camera devices. Which class?

*Hint: PowerShell Script Block Logging (EventCode 4104), look for `Get-CimInstance -Query`.*

### AD12 — doublezero_wiper
What is the full path of the DoubleZero wiper payload dropped on the
victim's Desktop?

*Hint: Sysmon FileCreate events (EventCode=11), `TargetFilename` ending in a telling name.*

### AD13 — fin7
A `wscript.exe` process in this FIN7 sample loads an LDAP client DLL it
has no ordinary reason to need. What's the DLL's filename?

*Hint: ImageLoad events (EventCode=7), filter to `Image=*wscript.exe`.*

### AD14 — gootloader
What is the full path of the malicious JScript file GootLoader drops
under the victim's Roaming AppData (disguised with an Adobe-looking
folder name)?

*Hint: FileCreate events, `TargetFilename` ending in `.JS`.*

### AD15 — hermetic_wiper
Every file-delete event in this small HermeticWiper sample touches the
same noisy path prefix. Whose housekeeping directory is it — not the
attacker's?

*Hint: EventCode=23 events, look at the common `TargetFilename` prefix under the Splunk Universal Forwarder's own install path.*

### AD16 — icedid
Behind the Splunk-forwarder noise, IcedID runs a `cmd.exe`-launched
discovery chain (ping, netstat, ipconfig, domain-trust enumeration...).
Which `nltest` switch does it use to enumerate domain trusts?

*Hint: `ParentImage=*cmd.exe` on EventCode=1, then look at the `nltest.exe` command line.*

### AD17 — industroyer2
What is the exact command line used to launch `industroyer2.exe` in this
capture?

*Hint: process-create, `Image` ending in `industroyer2.exe` — check the arguments.*

### AD18 — lockbit_ransomware
What is the filename of the ransom note LockBit drops throughout the
filesystem, and which process creates it?

*Hint: FileCreate events, `TargetFilename` ending in `README.txt`; `Image` names the dropper.*

### AD19 — notdoor
NotDoor's Outlook persistence mechanism overwrites a specific VBA
project file in the victim's Outlook profile. What's its full path?

*Hint: one FileCreate event, `TargetFilename` under `...\Roaming\Microsoft\Outlook\`.*

### AD20 — olympic_destroyer
This isn't one service getting disabled — count the distinct services
OlympicDestroyer flips to "disabled" in this capture. Roughly how many?

*Hint: EventCode=7040 (Service Control Manager); the raw text is multi-line, one "Message=..." per event — extract the service name with `rex` and count distinct values.*

### AD21 — prestige_ransomware
Prestige drops its ransom note in two locations. Name both paths, and
the process that creates them.

*Hint: FileCreate events, `TargetFilename` ending in `README` (no extension).*

### AD22 — qakbot
QakBot injects into a legitimate browser process via `CreateRemoteThread`
from `wermgr.exe`. Which browser executable is the dominant target?

*Hint: EventCode=8, look at `SourceImage`/`TargetImage` rather than `Image`.*

### AD23 — ransomware_ttp
PowerShell Script Block Logging uses a specific EventCode to mark the
*start* of a script block's execution (separate from 4104, which carries
the block's actual text). Which EventCode?

*Hint: `stats count by EventCode` on this host and compare against 4104/4106.*

### AD24 — redline
RedLine's registry-simulation scenario drops a decoy batch file via
Notepad++. What's its full path?

*Hint: FileCreate events, `Image=*notepad++.exe`.*

### AD25 — remcos
Remcos loads a DLL (via `wscript.exe`/`regsvr32.exe`) that gives it
low-level dynamic function-calling ability from script code. What's the
DLL's filename?

*Hint: ImageLoad events, `ImageLoaded` under a Temp folder.*

### AD26 — revil
PowerShell Script Block Logging uses a specific EventCode to mark the
*end* of a script block's execution (paired with the 4105 start event).
Which EventCode?

*Hint: same family of events as AD23 — this one's the closing bookend.*

### AD27 — ryuk
Before encrypting, Ryuk stops a specific Windows service tied to account
authentication. Which service (the short service name passed to `net
stop`)?

*Hint: process-create, `CommandLine=*net*stop*`.*

### AD28 — snakemalware
Snake malware hijacks the default "Open With" program ID for a specific
file extension via the registry. Which extension?

*Hint: registry SetValue event, `TargetObject` under `HKCR\.???\OpenWithProgIds\`.*

### AD29 — swift_slicer
SwiftSlicer's mass file-delete activity (EventCode=23) is dominated by a
single category — just over half of all deletes hit one application's
browser cache directory. Which application?

*Hint: `stats count by TargetFilename` won't scale — look for a common path segment instead.*

### AD30 — trickbot
TrickBot's lateral-movement scenario touches specific files over an SMB
admin share (`C$`). Name the file(s).

*Hint: EventCode=5145 (Security — network share access), `RelativeTargetName`.*

### AD31 — vilsel
One process in this Vilsel sample runs with an oddly bare, argument-less
command line. Which command?

*Hint: process-create, `Image=*ROUTE.EXE`, look at `CommandLine`.*

### AD32 — warzone_rat
Warzone RAT's DLL-search-order-hijack scenario abuses `Dism.exe` to
sideload a DLL it wouldn't normally load from that location. Which DLL?

*Hint: ImageLoad events, `Image=*Dism.exe`.*

### AD33 — winpeas
This WinPEAS enumeration sample's single captured script block runs a
cmdlet that reads a very specific, sensitive place. Which cmdlet?

*Hint: one EventCode=4104 event — read `ScriptBlockText` directly.*

### AD34 — winter-vivern
Winter Vivern's PowerShell backdoor beacons to a hardcoded C2 domain
visible directly in the captured script text. What's the domain?

*Hint: EventCode=4104, look for a `$singleHost` or similar URL-building variable.*
