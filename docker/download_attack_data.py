#!/usr/bin/env python3
"""Download the malware log files listed in attack-data/manifest.json from
splunk/attack_data (a Git LFS repo) via the media.githubusercontent.com CDN,
which serves LFS blobs directly over plain HTTPS -- no git-lfs client needed.

Usage: python3 download_attack_data.py <repo_root>
Idempotent: skips any file that already exists.
"""
import json
import sys
import urllib.request
from pathlib import Path

MEDIA = "https://media.githubusercontent.com/media/splunk/attack_data/master"
RAW = "https://raw.githubusercontent.com/splunk/attack_data/master"


def main():
    repo_root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    out_dir = repo_root / "attack-data"
    manifest_path = out_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    for entry in manifest:
        fam_dir = out_dir / entry["family"]
        fam_dir.mkdir(parents=True, exist_ok=True)

        dest_log = out_dir / entry["log_file"]
        dest_yml = out_dir / entry["yml_file"]

        if not dest_log.exists() or dest_log.stat().st_size == 0:
            # 'folder' is the datasets/malware/<family>/<scenario> path in
            # the upstream repo; log_file's basename is the file within it.
            log_url = f"{MEDIA}/{entry['folder']}/{Path(entry['log_file']).name}"
            print(f"[{entry['family']}] downloading {Path(entry['log_file']).name}")
            urllib.request.urlretrieve(log_url, dest_log)
        else:
            print(f"[{entry['family']}] already present, skipping")

        if not dest_yml.exists():
            yml_url = f"{RAW}/{entry['folder']}/{Path(entry['yml_file']).name}"
            urllib.request.urlretrieve(yml_url, dest_yml)

    print(f"\nDone. {len(manifest)} families staged under {out_dir}")


if __name__ == "__main__":
    main()
