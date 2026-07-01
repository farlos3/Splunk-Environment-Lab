# Self-Practice — Graduated Practice Packs

Hands-on exercise packs that take you from **SPL fluency** to advanced SOC /
Enterprise Security skills. Organized **by dataset** (mirroring
[`../specialized/`](../specialized/)), because each BOTS dataset is a
different incident and therefore a different set of exercises.

## Packs by dataset

| Folder | Dataset | Contents | Status |
|---|---|---|---|
| [**botsv1/**](botsv1/) | BOTS v1 (`./setup.sh`) | 60 exercises Q1–Q60: SPL fundamentals → log analysis → SOC Tier-1 investigations → Enterprise Security, with [SOLUTIONS](botsv1/SOLUTIONS.md) | ✅ complete |
| [**botsv2/**](botsv2/) | BOTS v2 (`./setup.sh --v2`) | Graduated path: fundamentals → intermediate SPL → log analysis (query fluency first) | 🚧 dataset loading; being built |

## The learning journey

```
self-practice/botsvN/   →   query fluency + SOC fundamentals   (start here)
        ↓
specialized/botsvN/     →   intensive: hunting, DFIR, network forensics,
                            detection engineering, purple team, reporting,
                            threat intel + full-incident capstone
```

Finish a dataset's **self-practice** pack before its **specialized** tracks —
you can't hunt if you're still fighting the syntax.

## Prerequisites
1. Lab running — `http://localhost:8000` (admin / `p@ssw0rd`)
2. The dataset for your pack is loaded (`index=botsvN | head 1` returns events)
3. You know how to set the **time picker** (each dataset has its own active window)

> Official BOTS walkthroughs (full vendor answers) live in [`../splunk-bots/`](../splunk-bots/).
