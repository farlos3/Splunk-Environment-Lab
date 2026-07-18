# Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                    Splunk container (splunk-lab)                   │
│                                                                    │
│   /opt/splunk/etc/apps/botsv1_data_set/  ← splunklab_splunk-botsv1 │
│   /opt/splunk/etc/apps/botsv2_data_set/  ← splunklab_splunk-botsv2 │
│   /opt/splunk/etc/apps/botsv3_data_set/  ← splunklab_splunk-botsv3 │
│                                                                    │
│   /opt/splunk/var                        ← splunklab_splunk-var    │
│   /opt/splunk/etc/users                  ← splunklab_splunk-etc-…  │
└────────────────────────────────────────────────────────────────────┘
       Web UI :8000   HEC :8088   Mgmt :8089   Fwd :9997   Syslog :1514

   bots-data/botsv1/ (host staging) ─one-time copy─▶ splunk-botsv1 volume
   bots-data/botsv2/                                 splunk-botsv2 volume
   bots-data/botsv3/                                 splunk-botsv3 volume
```

> **Why a volume, not a bind mount?**  Docker Desktop on Windows exposes
> host files via gRPC-FUSE, which lacks the file-locking and mmap
> semantics Splunk's `validatedb` requires. Splunk refuses to use such
> paths as an index home ("unusable filesystem"). So we stage each
> dataset in `bots-data/bots<vN>/` on the host, then copy it into a
> named volume that lives on Docker's native ext4 — Splunk is happy
> with that.

See also: [CTF_SCOREBOARD.md](CTF_SCOREBOARD.md) for the scoreboard
app's own mount layout, and the root README's "Attack data micro-CTF"
section for the `attack_data` index's.
