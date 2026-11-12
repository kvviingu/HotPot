# Dashboard

`python dashboard/server.py`, then open http://127.0.0.1:8787. Stdlib Python and vanilla JS, no CDN.
It listens on 127.0.0.1 only, rejects other Host headers, and pulls the VMs' JSON logs over SSH every
`sync_seconds` into `dashboard/data/` (gitignored). The Sync button turns red when the front VM pull
fails and says "backend failed" when only the backend pull fails. Settings: [configuration.md](configuration.md#dashboard).

## Tabs

| Tab | Shows |
|---|---|
| Overview | key numbers, map of where sessions come from, live hits, latest sessions, sessions over time, who is behind them, how far they got |
| Sessions | SSH/Telnet, web and decoy sessions with class, agent score, commands, replay. The drawer adds MITRE ATT&CK techniques and Suricata alerts. Search takes technique ids (`T1098.004`). |
| Traps | AI agents, tripwire hits, decoy activity, and cards for the web honeypot's MCP server, A2A agent and agent docs (web sessions flagged "MCP server", "A2A agent" or "agent docs"; click a card to list them) |
| Statistics | analytics for the chosen period against the one before it; see [Statistics](#statistics) |
| Intel | ranked lists: countries, networks, IPs, SSH clients and HASSH, web paths and user agents, logins, usernames, passwords, commands, Suricata alerts, categories, CVEs and TLS fingerprints, ATT&CK techniques and tactics, campaigns, payloads, decoy logins, AI API prompts, programs run, captured files |
| Samples | captured files with origin, YARA matches and hash lookups |
| Report | weekly report for any ISO week, including ATT&CK techniques and top IDS alerts |
| Status | VM, container and timer health, container resets, last IDS event and rule update |
| Settings | API keys, automatic lookups, sync interval, own IPs |

The 24 h / 7 days / 30 days / All buttons set the time range.

The page loads the newest 3,000 sessions of a period. When a period has more, the Sessions filters (text,
class, protocol) run on the server over all of them (`/api/sessions`), so a filter such as "Poland" finds
the same sessions Intel counts. Up to 3,000 matches are listed, newest first (or by the chosen sort).

### Map

Each circle is a place (city, rounded to 0.1°). Size follows sessions on a log scale (key: 1, 10, 100,
1,000), so one noisy scanner doesn't flatten everything else. Colour is the furthest any session from there
got: grey for connected, probed or guessed passwords; blue for logged in or read data; orange for ran
commands or changed something. A pink ring marks places with a likely AI agent, a green ring human-like
sessions. The five busiest places in view are labelled. Zoom with the World / Europe / Asia / Americas
buttons, + and −, Ctrl + scroll or a double-click; drag to pan. Country borders come from world-atlas
`countries-110m.json`, downloaded on first run next to the land outline.

## Statistics

A high-level view of the chosen period, compared with the period of the same length just before it
(not for All). Data comes from `/api/stats`.

| Panel | Shows |
|---|---|
| Summary | a few generated sentences: volume and change, busiest hour, top country, SSH login and command rates, top post-login technique, biggest risers |
| Metric cards | sessions, source IPs (new and returning), login attempts, SSH logins, commands, decoy actions, IDS alerts, files captured, likely AI agents; each with a sparkline and the change. Click a card to chart it. |
| Over time | the selected metric as stacked bars; legend buttons hide series; the dashed line is the previous period |
| When they come | weekday by hour heatmap (UTC), for all traffic, web, SSH/Telnet or decoys |
| How far they got | SSH, web and decoy funnels with step-to-step conversion and the previous period's rate |
| Who sent it | sessions over time by actor type, top 6 countries or top 6 networks, with shares |
| Distributions | session length, commands per SSH login, median gap between actions by class, agent score |
| MITRE ATT&CK | techniques per tactic, shaded by session count |
| What changed | most common, rising, falling and new credentials, commands, web paths, techniques, IDS signatures, CVEs, countries and networks |
| Countries, Services | sessions, share, IPs and change |

Clicking a country, network, actor type, service or technique opens Sessions filtered to it. Every
panel has a CSV button; cells that start with `=`, `+`, `-` or `@` get a leading `'` so attacker text
cannot run as a spreadsheet formula. Bucket size: an hour for 24 h, 6 hours for 7 days, a day for 30
days. Comparisons stay hidden until there is data from the previous period.

## Samples

Each sample has three actions:

* **Download**: a zip with the password `infected`, built on the VM. Open it only on an isolated
  analysis machine.
* **Check hash**: VirusTotal and MalwareBazaar. Only the SHA-256 is sent.
* **Upload…**: sends the file itself to VirusTotal or MalwareBazaar, which shares it with their users.
  Asks you to confirm first.

## YARA

Every `.yar` file under `yara/` (the repo ships `yara/rules/hotpot.yar`) goes to both VMs every 15
minutes, or when you press "Rescan with YARA". The VMs scan their quarantines with `yara` and `file`,
which the installers set up. Samples never leave the VMs for this. Add community rule sets by dropping
their files into `yara/`.

## IP reputation

AbuseIPDB (free key) and GreyNoise community (key optional), from a session's drawer or automatically.
Only attacker IPs are sent, never your own or private addresses. Results are cached for 7 days in
`dashboard/data/iprep.json`.

## Replay

SSH and Telnet sessions play back from Cowrie's ttylogs, fetched on demand and cached in
`dashboard/data/tty/`. Sessions without a recording replay their typed commands only.

## Weekly report

The Report tab shows any ISO week. "Download HTML" gives a self-contained page: no scripts, attacker
text escaped. Every Monday (UTC) the dashboard saves last week's report to
`dashboard/data/reports/hotpot-<week>.html`.
