# CTF Scoreboard — details

See the root README's "CTF scoreboard" section for the overview and
quick start. This doc covers setup/config detail.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Splunk container (splunk-lab)                    │
│                                                                     │
│  /opt/splunk/etc/apps/SA-ctf_scoreboard/        (questions, UI)    │
│  /opt/splunk/etc/apps/SA-ctf_scoreboard_admin/  (answers, hints)   │
│                                                                     │
│  KV store collections:                                             │
│    SA-ctf_scoreboard :: ctf_questions, ctf_users, ...              │
│    SA-ctf_scoreboard_admin :: ctf_answers, ctf_hints               │
└─────────────────────────────────────────────────────────────────────┘
        ▲
        │ setup.sh imports CSVs from docker/ctf_seed_data/<vN>_<source>/
        │ via the KV store REST API (batch_save) after the container is healthy
```

## Why only one question set at a time

`scoreboard_controller.py` hardcodes its own app name
(`SA-ctf_scoreboard` / `SA-ctf_scoreboard_admin`) in every KV store REST
call and in its own config-file path — it is **not** parameterized per
app instance. That means:

- The app folders **must** keep those exact names. Don't rename them.
- There is one shared KV store, not one per BOTS version. Only one
  question/answer set can be "live" at a time — switch with
  `--ctf-questions <set> --force`.

## Question sets (`docker/ctf_seed_data/`)

```
docker/ctf_seed_data/
├── v1_writeups/   ctf_questions.csv, ctf_answers.csv, ctf_hints.csv
├── v2_writeups/   (same three files)
├── v3_writeups/
├── v1_official/   README.md only — drop your own CSVs here
├── v2_official/
└── v3_official/
```

- **`vN_writeups`** — derived from the public
  [chan2git/splunk-bots](https://github.com/chan2git/splunk-bots)
  walkthroughs (29 / 27 / 33 questions for v1/v2/v3 — the same
  walkthroughs vendored under `challenges/splunk-bots/`).
  `BasePoints` is **inferred** from the question-number hundreds digit
  (Q1xx→100, Q2xx→200, ...) — it is not the real competition scoring.
  No hints (the source write-ups don't separate hints from the
  answer). A few multi-part answers got split into `-1`/`-2`
  sub-questions.
- **`vN_official`** — empty by default (just a `README.md` placeholder).
  The real BOTS question/answer/hint files are Splunk's own proprietary
  content, not published anywhere — you have to request them directly.
  See "Requesting the official question set" below.

Import is idempotent — it skips a collection that already has rows
unless you pass `--force` (which also re-extracts/re-populates the BOTS
volume; there's no CTF-only force flag yet).

## Requesting the official question set

The `vN_writeups` sets are enough to run the lab out of the box, but
they're community-derived (from
[chan2git/splunk-bots](https://github.com/chan2git/splunk-bots)) —
`BasePoints` is *inferred*, not the real competition scoring, and hints
are missing entirely. If you want the real thing, Splunk will send it
to you for free on request:

1. **Send an email to `bots@splunk.com`** (this address is called out
   in the "Related Projects" section of the
   [SA-ctf_scoreboard README](https://github.com/splunk/SA-ctf_scoreboard)
   as the contact for BOTS questions/answers/hints access). Include:
   - Which dataset(s) you want — BOTSv1 / v2 / v3.
   - What you're using it for (e.g. "self-study" or "university
     coursework" — this is a training lab, not a commercial product).
   - That you already have the BOTS *data* (the `.tgz` this repo's
     `setup.sh` downloads) and just need the CTF question/answer/hint
     set to go with it.
2. **Wait for a reply** — Splunk has historically sent back the
   questions/answers/hints as a small CSV/spreadsheet bundle. Response
   time isn't guaranteed since this is a manual, human-in-the-loop
   process on their end, not an automated download.
3. **Convert/save the three files** into `ctf_questions.csv`,
   `ctf_answers.csv`, `ctf_hints.csv`, matching the exact columns
   documented in `docker/ctf_seed_data/vN_official/README.md` (and the
   `vN_writeups/` CSVs, which are real working examples of the schema).
   Pay special attention to the `Number` (must be a plain integer) and
   `StartTime`/`EndTime` (must be real epoch seconds, not blank) rules
   spelled out there — the scoreboard controller crashes on either one.
4. **Drop the three files directly into `docker/ctf_seed_data/vN_official/`**
   (not a subfolder) — that's the exact path `setup.sh` reads from.
   This folder is gitignored precisely so this proprietary content never
   gets committed or pushed anywhere.
5. **Run** `./setup.sh --vN --ctf-questions vN-official --force` to
   (re)import it into the KV store — or just pick "official" at the
   question-set prompt next time you run `./setup.sh` interactively.

## Requirements & auth model

- **python3** on the host — converts the seed CSVs to JSON for the KV
  store import. Without it, `setup.sh` still installs the apps but
  skips the KV import (prints a warning); import manually afterwards
  or install python3 and re-run.
- The controller authenticates as a privileged "service account" to
  fetch answers server-side (so a competitor's own session can never
  read `ctf_answers` directly). The real upstream README has you
  create a dedicated `svcaccount` user with a custom
  `ctf_answers_service` role for this. For a single-player lab that's
  unnecessary ceremony: `setup.sh` just points it at the existing
  Splunk `admin` user (generated into
  `docker/apps/SA-ctf_scoreboard/appserver/controllers/scoreboard_controller.config`,
  gitignored, auto-regenerated if missing). Follow the upstream
  instructions instead for a real multi-team event.

## Known issues already patched in the vendored copy

- **`bin/splunklib/six.py`** shipped a `six==1.14.0` (2020) whose
  `sys.meta_path` importer only implements the legacy `find_module()`
  protocol. Python 3.12+ dropped the compatibility shim that used to
  paper over that, so every `from splunklib.six.moves import ...`
  (used throughout `splunklib/binding.py` and `client.py`) raised
  `ModuleNotFoundError`, which broke every single page of the app
  under the Python 3.13 this Splunk image bundles. Fixed by adding a
  `find_spec()` method to `_SixMetaPathImporter` in that file — don't
  overwrite it back from a fresh upstream clone without re-applying
  the patch (or bumping to a `six` release that already has
  `find_spec`).
- `bin/sa_ctf_scoreboard/{cloudconnectlib,solnlib,splunktaucclib,
  splunk_aoblib,modinput_wrapper,...}` were intentionally **not**
  vendored — deeply nested vendor trees inside them (e.g.
  `solnlib/packages/requests/packages/urllib3/packages/
  ssl_match_hostname/`) blow past `MAX_PATH` on a Windows checkout,
  and none of them are imported by `scoreboard_controller.py` (they
  back an optional TA-style modular input / the `award_ebadge` alert
  action, neither used here). If you wire up ebadges later and hit an
  `ImportError` from that alert action, that's why.

## Troubleshooting

- **Docker healthcheck shows "unhealthy" but the UI works fine**: the
  compose healthcheck authenticates (`curl -fks -u
  admin:$SPLUNK_PASSWORD ...`) — if you still see this, check
  `docker logs splunk-lab` for a real splunkd problem rather than
  assuming it's cosmetic.
- **`setup.sh` prints "KV store not responding — skipping import"**:
  the KV store subsystem for a freshly-mounted app can lag a few
  seconds behind splunkd reporting healthy. The import retries for
  ~30s; if it still fails, re-run `setup.sh` again (import is
  idempotent) or check `docker logs splunk-lab` for KV store errors.
- **Manual re-import / clearing a collection**:
  ```bash
  curl -ks -u admin:p@ssw0rd -X DELETE \
    "https://localhost:8089/servicesNS/nobody/SA-ctf_scoreboard/storage/collections/data/ctf_questions"
  ```
