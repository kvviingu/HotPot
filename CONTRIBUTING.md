# Contributing to HotPot

Thanks for helping. Bug reports, new bait, detection ideas, docs fixes and data from your own
sensor (anonymised) are all welcome.

## Before you start

* Open an issue first for anything bigger than a small fix, so we can agree on the approach.
* For security problems in HotPot itself, follow [SECURITY.md](SECURITY.md) instead of opening an issue.
* Never paste real secrets, your VM addresses or unredacted attacker samples into issues or pull requests.

## Development setup

You need Python 3.10+ and nothing else for the operator tool and the dashboard.

```bash
git clone https://github.com/kvviingu/HotPot.git && cd HotPot
python -m unittest discover -s tests -v     # unit tests
python hotpot.py --help
```

To try changes end to end you need your own VMs ([docs/cloud-setup.md](docs/cloud-setup.md)); run
`./hotpot setup` once, then `./hotpot deploy` after each change. The dashboard runs locally with
`./hotpot dashboard`.

## Ground rules

* **Stdlib only** for `hotpot.py`, `persona.py` and the dashboard. No CDNs in the dashboard: it is
  served under a strict CSP.
* **Treat logged data as hostile.** Everything attackers send is shown in the dashboard; escape it, cap
  its size, and use bounded regexes.
* **The bait must stay harmless.** Decoys never execute or fetch what they receive; the container has
  no route out. Changes that weaken isolation will not be merged.
* **Write persona text with the reference values** ("Northbridge Logistics", `fileserver01`,
  `NB-AGENT-CHECK-...`). Each install swaps in its own identity; add any new identifying value to
  `persona.py` so it is swapped too, and the tests check that none leaks.
* **Installers stay idempotent.** Every step in `install/*.sh` must be safe to run again.
* Keep the docs in `docs/` in step with behaviour, and add a line to [CHANGELOG.md](CHANGELOG.md).

## Pull requests

1. Fork, branch from `main`, keep the change focused.
2. Run the tests; CI runs them on Linux, macOS and Windows with Python 3.10 and 3.13, plus shell and
   JavaScript syntax checks.
3. Describe what changed and how you tested it (unit tests, a deploy to your own sensor, screenshots
   for dashboard changes with addresses removed).

By contributing you agree that your work is released under the [MIT licence](LICENSE).
