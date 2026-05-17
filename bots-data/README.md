# BOTS datasets — staging area

This folder is the host-side staging area for Splunk's **BOTS** (Boss
of the SOC) datasets. Each version goes into its own subfolder; the
setup script copies them into per-version Docker named volumes that
the Splunk container actually reads from.

```
bots-data/
├── botsv1/        ← BOTSv1 archive + extracted app
├── botsv2/        ← BOTSv2 archive + extracted app
└── botsv3/        ← BOTSv3 archive + extracted app
```

Each `bots<vN>/` folder, after extraction, contains the Splunk app
layout straight from the archive:

```
bots-data/botsv1/
├── default/                  ← indexes.conf, props.conf, transforms.conf, ...
├── local/
├── lookups/
├── metadata/
├── var/lib/splunk/botsv1/    ← pre-indexed Splunk buckets (the heavy bit)
└── README, LICENSE, ...
```

> The `--strip-components 1` flag in setup drops the top-level
> `botsv<N>/` folder inside the archive so its contents land directly
> in `bots-data/botsv<N>/`.

## How to populate

Easiest: let `setup.sh` / `setup.ps1` download and extract for you.

```bash
./setup.sh --v1               # just BOTSv1 (~6 GB)
./setup.sh --v1 --v2          # v1 + v2
./setup.sh --all              # v1 + v2 + v3
```

If the auto-download fails (Splunk has moved BOTS URLs several times),
grab the archive manually and drop it in the right subfolder:

1. Open <https://github.com/splunk/botsv1> (or `botsv2` / `botsv3`)
2. Follow the current **Download** section
3. Save the `.tgz` into `bots-data/botsv<N>/`
4. Re-run with `--v<N> --skip-download`

## How big is each?

| Dataset | Compressed | Extracted |
| --- | --- | --- |
| BOTSv1 | ~6 GB | ~9 GB |
| BOTSv2 | ~28 GB | very large — check upstream |
| BOTSv3 | ~3.5 GB | ~5 GB |

## Why this isn't in git

The archives and extracted buckets are tens of gigabytes — GitHub
rejects single files >100 MB. `.gitignore` keeps only this README and
the empty per-version `.gitkeep` placeholders, so the folder structure
is preserved without committing data.

## Verifying after setup

Open <http://localhost:8000>, go to **Apps**, and confirm the
**BOTS Dataset v1 / v2 / v3** apps appear for whichever versions you
loaded. In Search, with time range **All time**:

```
index=botsv1 | stats count by sourcetype
index=botsv2 | stats count by sourcetype
index=botsv3 | stats count by sourcetype
```
