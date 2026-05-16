# BOTSv1 dataset goes here

This folder is mounted into the Splunk container as
`/opt/splunk/etc/apps/botsv1`. Splunk treats whatever is in this folder
as a single app called `botsv1`.

## What to put here

Extract the BOTSv1 archive **so the app's top-level folders land directly
in this directory** — not nested inside another `botsv1/` folder.

Expected layout after extraction:

```
bots-data/
├── default/        ← indexes.conf, props.conf, transforms.conf, ...
├── local/
├── lookups/
├── metadata/
├── data/           ← pre-indexed Splunk buckets (the heavy bit)
└── README          ← from Splunk's archive
```

## How to download

1. Go to <https://github.com/splunk/botsv1>
2. Follow the **Download** section in its README (currently points to an S3
   bucket; URL has changed over time, always trust the upstream README).
3. Once you have the `.tgz`, extract it into this folder:

   ```powershell
   # PowerShell
   tar -xzf .\botsv1_data_set.tgz -C .\bots-data --strip-components 1
   ```

   ```bash
   # bash
   tar -xzf botsv1_data_set.tgz -C bots-data --strip-components 1
   ```

   The `--strip-components 1` flag drops the top-level `botsv1/` folder
   from the archive so its contents land directly in `bots-data/`.

4. Restart the container so Splunk re-scans apps:

   ```powershell
   docker compose -f docker/docker-compose.yml restart splunk
   ```

## Verifying

After Splunk finishes loading:

- Open <http://localhost:8000>
- Go to **Apps** → you should see **BOTS Dataset v1** listed
- In Search, run with time range **All time**:

  ```
  index=botsv1 | stats count by sourcetype
  ```

  You should see dozens of sourcetypes (`wineventlog`, `stream:http`,
  `xmlwineventlog`, `iis`, `suricata`, etc.) with millions of events.

## Why this isn't in git

The dataset is ~6 GB compressed (~25 GB extracted). `.gitignore` excludes
everything in this folder except this README and `.gitkeep`.
