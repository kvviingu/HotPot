# Notes for coding agents

Read this first when you pick up HotPot in a new session. It covers how the project fits together, how
to work on it safely, and the traps earlier sessions fell into. Human contributors: see
[CONTRIBUTING.md](CONTRIBUTING.md); the ground rules there apply to you too.

**Site-specific details** (VM addresses, SSH commands, the state of the live sensor, open tasks) are
in `AGENTS.local.md` next to this file. It is gitignored and exists only on the owner's PC. Read it if
it is there, and never copy anything from it into a tracked file.

## What HotPot is

A research honeypot that records what bots, scripts and AI agents do on a server that looks real. The
owner is not a programmer and builds it with AI help as a learning project; explain things plainly
and keep answers short.

Three parts:

| Part | Where it runs | What it is |
|---|---|---|
| Front VM | public cloud VM, `docker-compose.yml` | Cowrie (SSH/Telnet, proxy mode), web honeypot `web/`, decoy services `decoys/`, Suricata `ids/`, Squid `egress/` (apt proxy for the backend only) |
| Backend VM | private subnet, no internet | Incus container `fileserver01` that attackers really log in to; auditd + `backend/nb-collect.py` (events and samples, every minute), `backend/nb-reset.sh` (harvest and roll back to the `clean` snapshot, nightly and early on persistence) |
| Dashboard | owner's PC only, `dashboard/server.py` on 127.0.0.1:8787 | pulls logs over SSH, parses sessions, shows them; also lookups, IOC export, log forwarding, AbuseIPDB reporting |

`hotpot.py` (wrapped by `./hotpot` and `hotpot.cmd`) is the operator tool: `setup`, `check`, `deploy
[front|backend]`, `persona`, `identity`, `status`, `cleanup`, `dashboard`, `ssh front|backend`.
Site values live in `honeypot.conf` (template `honeypot.conf.example`); the identity attackers see
lives in `persona.json` (`persona.py`). Both are gitignored.

## Where things are

* `install/front.sh`, `install/backend.sh` and `install/lib.sh`: the installers that `hotpot deploy`
  copies to and runs on the VMs. They must stay idempotent.
* `backend/setup_host.sh`, `backend/setup_container.sh`: the backend host and its container.
* `install/retention.sh`: the daily `hotpot-retention.timer` clean-up on both VMs.
* `cowrie/patches/`: Cowrie patches (login rules, proxy login, extra commands). `cowrie/honeyfs/` and
  `cowrie/build_fs.py`: the fake file system (rebuild the pickle on the VM after changes).
* `dashboard/server.py`: one big stdlib HTTP server. Helpers: `forward.py`, `ioc.py`, `abuse.py`,
  `geo.py`. Front end: `dashboard/static/` (`index.html`, `app.js`, `style.css`), no build step.
* `tests/`: stdlib `unittest`. `test_retention.py` needs Linux (bash, flock) and is skipped on Windows.
* `docs/`: user docs. Keep them, `README.md` and `CHANGELOG.md` ("Unreleased") in step with changes.

## Rules that are not negotiable

* **Everything in the logs is attacker-controlled.** Escape it in the UI, cap sizes, bound regexes,
  never execute or fetch it, never put it into outgoing reports (see `abuse.py`).
* **The dashboard stays local-only** (127.0.0.1, CSRF token, Origin check, strict CSP, no CDNs).
* **Stdlib only** for `hotpot.py`, `persona.py` and the dashboard.
* **Never print or commit secrets**: the OpenRouter key, the backend password, API keys in
  `dashboard/data/settings.json`. Don't read the owner's private SSH key files.
* **Never open new inbound ports on the VMs** or loosen the backend's isolation without asking.
* **Samples stay on the VMs.** Downloads only as password-protected zips; uploads to VirusTotal or
  MalwareBazaar only when the owner clicks and confirms.
* **Outgoing data**: no personal details of the owner, no VM addresses, no install identity in
  anything sent to an outside service. The LLM fallback uses free models only.
* **Persona text uses the reference values** ("Northbridge Logistics", `fileserver01`,
  `NB-AGENT-CHECK-...`); every install swaps in its own identity through `persona.py`.

## How to work here

* **Ask before** pushing, deploying to the VMs, installing anything on them, or sending anything to an
  outside service. Commit when a piece of work is done, then ask whether to push.
* **Git**: work on `main`. Never push the local `private-history` branch. Author
  `kvviingu <22890612+kvviingu@users.noreply.github.com>`. End commit messages with
  `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` (or your own model's line).
* **CI** (`.github/workflows/ci.yml`) doesn't start on push for this repo. After a push, start it with
  `gh workflow run ci.yml`.
* **Tests**: `python -m unittest discover -s tests`, plus `node --check dashboard/static/app.js` and
  `bash -n` on changed shell scripts. Retention tests: run them under WSL or Linux.
* **Dashboard changes**: restart the dashboard process (it doesn't reload code), wait about 30 s for the
  first parse, then check in a browser. Look for console errors and check a 375 px wide view too.
* **Screenshots** must not show real addresses. Before taking one, set `#host` to "HotPot sensor" and
  replace the VM and owner IPs in the page (text nodes and input values) with 203.0.113.10. The page
  refreshes itself, so scrub right before each capture.

## Traps earlier sessions hit

* **Shell on Windows**: the Bash tool mangles `\\n` and some quoting in heredocs, and a stray `cat >`
  waits forever on stdin. For multi-line edits, write a small Python script to a scratch file and run
  it, or use the edit tool. PowerShell 5.1 has no `&&` or heredocs.
* **Two dashboard copies**: if a new one can't bind 8787, an old one is still running (maybe started
  with a different command line). Find it by port, not by command line.
* **Hash-only navigation** in the browser doesn't reload the page; call `location.reload()`.
* **Forwarding state** is versioned. An unreadable or old state file must mean "start from now", never
  "send everything": that once replayed about 226,000 events to a test receiver.
* **Rotated log names**: the dashboard mirrors remote files byte for byte, so rotated files get new,
  timestamped names (`web.jsonl.<UTC>`, `backend.jsonl.<UTC>`) instead of being overwritten.
* **Documentation IP ranges** (203.0.113.0/24 and friends) are not `is_global`; use real public IPs in
  tests that need an attacker address.
* **Backend memory**: the VMs have about 1 GB. A miner in the container once took the backend VM down.
  It now has 2 GB of swap and the container is capped at `CT_MEMORY` (448 MiB) with no swap of its own;
  keep that headroom when adding anything to the backend.
* **Incus limits** are set again on every `setup_host.sh` run, so a changed `CT_MEMORY` reaches an
  existing container. Most other container settings are only set when it is first created.
