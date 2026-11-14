# Detection: agents, bots, campaigns, resets, decoys, ATT&CK, IDS

## Session classes

Every session gets one class (`CLASSES` in `dashboard/server.py`): Script / scanner, Known bot
(signature), AI agent (suspected), AI agent (followed canary), Human-like, or Not enough data.

**Known bots.** Well-known botnet command lines (listed above `known_bot()` in `dashboard/server.py`)
outrank the timing heuristic, because proxy lag can make a bot look slow. These sessions are classed
"Known bot (signature)" and their agent score is capped near zero.

**People at a terminal.** An SSH session typed from a desktop client (PuTTY, MobaXterm, Termius,
SecureCRT and similar) or whose commands carry a terminal's bracketed-paste markers (`ESC[200~`) is
classed Human-like. Its pauses are a person reading and pasting, so they don't count towards the agent
score. Agent frameworks and bots connect through SSH libraries and never send paste markers.

**Waiting is not thinking.** The pause after a slow command (`apt`, `pip`, `git`, `wget`, `curl`,
`make`, `sleep`, scanners and the like) is the command running, not someone deciding the next step. Those
pauses are left out of the timing heuristic; if that leaves fewer than three pauses, timing counts for
nothing.

## AI-agent score (0-100)

100 when the session hit a canary token. Otherwise points for:

* using a canary credential,
* the timing pattern between commands,
* LLM-style shell habits: section-header echoes, plain-English comments, `|| echo` fallbacks, heredocs,
* reading the bait files.

## Tripwires

Each canary token sits in exactly one place, so a hit tells you what the visitor read:

| Token | Where |
|---|---|
| `7f3a` | login banner (`cowrie/honeyfs/etc/motd`) |
| `2c9e` | the web app's `.env` (`cowrie/honeyfs/var/www/northbridge/.env`) |
| `5b1d` | `/root/RUNBOOK.md` |
| `8e4f` | output of `nb-healthcheck` |
| `ollama` | the Ollama decoy's model |
| `k8s` | the Kubernetes decoy's config map |
| `llms` | the web `/llms.txt` and `/llms-full.txt` |
| `oapi` | the web OpenAPI spec (`/openapi.json`, `/swagger.json`, `/v3/api-docs`, ...) |
| `plug` | the web `/.well-known/ai-plugin.json` |
| `a2a` | the A2A agent card (`/.well-known/agent-card.json`) and the Dispatch Assistant at `/a2a` |
| `mcp` | the web MCP server (`/mcp`, `/sse`, `/.well-known/mcp.json`) |
| `agmd` | the leaked `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, Copilot instructions |

The web lures ask agents in prose, not as a link, to call `/internal/agent-verify` with their token, so
crawlers and OpenAPI fuzzers cannot trip them. The value counts wherever it shows up: a URL, a form, or a
JSON-RPC body (the MCP `run_report` tool, an A2A message).

**Agent surfaces on the web honeypot** (`web/app.py`, "agent bait"): `llms.txt`, an OpenAPI spec, an
`ai-plugin.json`, an A2A agent card with a working `/a2a` endpoint (what other agents ask it is logged
as the prompt), a working MCP server over streamable HTTP and legacy SSE (tools `query_shipments`,
`read_file`, `run_report`, `get_secret`; resources), and repo instruction files. They link to each
other, so an agent that finds one can find the rest.

Canary **credentials** sit in one bait file each: the runbook, `/etc/nb/monitor.env`, the
Kubernetes decoy's secrets, the `llms.txt` API key, the MCP vault (`get_secret`), the A2A assistant and
`AGENTS.md`. The SSH ones (user `deploy`) are in `cowrie/patches/passwords.txt`, so they log in. Using one anywhere (SSH login, a command, a web or decoy login, even a MySQL
decoy login, checked against the hash) shows under "Tripwires" in the session and in the weekly report.

## Campaigns and fingerprints

* **HASSH** (SSH client) and **JA4H** (HTTP) fingerprints appear in Intel and in each session.
* A **campaign** is two or more sessions with the same command sequence once IPs, URLs, numbers and
  random file names are blanked out.

## Early container reset

`backend/nb-collect.py` flags writes to persistence files: authorized_keys, cron, systemd units,
rc/profile files, passwd/shadow, sudoers, ld.so.preload. Once nobody has been connected for a minute, it
starts `nb-reset.service` (harvest, then restore the clean snapshot), at most once per 10 minutes.
Resets show in Status, in the session that caused them, and in the weekly report. The nightly reset
(`backend/nb-reset.timer`, 03:40 UTC) runs regardless.

## Decoy services

`decoys/honeysvc.py`, enabled with `DECOYS_ENABLED=1` and chosen with `DECOY_SERVICES`. Canned replies
only: nothing sent to them is executed or fetched. They log to the `decoy-data` volume
(`services.jsonl`).

* Redis 6379, Docker API 2375, Elasticsearch 9200.
* MySQL 3306: login hashes logged in hashcat mode 11200 format.
* Ollama 11434: prompts logged, nothing generated.
* Kubernetes API 6443: TLS, anonymous access, fake secrets (with canary credentials).
* RDP 3389 and SMB 445: stop after the NTLM login and log user, domain, workstation and a NetNTLMv2
  hash for `hashcat -m 5600`.

## MITRE ATT&CK tagging

Every session is tagged with the Enterprise ATT&CK techniques its own evidence shows (`attack_tags()` in
`dashboard/server.py`, rules in `ATTACK`, `CMD_RULES`, `WEB_RULES` and `DECOY_FLAG_RULES`). Each tag
keeps up to three pieces of evidence: the command, request or file change that triggered it.

| Source | Example techniques |
|---|---|
| Cowrie logins | T1110.001 Password Guessing, T1078 Valid Accounts |
| Typed commands and real-shell programs | T1059.004 Unix Shell, T1082/T1033/T1057/T1016 discovery, T1105 Ingress Tool Transfer, T1070.003 Clear Command History, T1496.001 Compute Hijacking |
| Files changed in the container, early resets | T1098.004 SSH Authorized Keys, T1053.003 Cron, T1543.002 Systemd Service, T1574.006 Dynamic Linker Hijacking |
| Web honeypot | T1190 Exploit Public-Facing Application, T1552.001 Credentials In Files, T1595.003 Wordlist Scanning |
| Decoys | T1610 Deploy Container, T1611 Escape to Host, T1609 Container Administration Command, T1552.007 Container API, T1496.004 Cloud Service Hijacking (Ollama), T1021.001/T1021.002 (RDP, SMB logins) |
| Suricata alerts | whatever technique the ET rule's `mitre_*` metadata names |

`crontab -l` and similar reads are discovery, not persistence; only writes count for persistence
techniques. Where to see the tags: the session drawer (grouped by tactic, links to attack.mitre.org),
Intel > MITRE ATT&CK (techniques and tactics; a row lists its sessions), session search by technique
id (`T1098.004`), and the weekly report.

## Network IDS (Suricata)

With `IDS_ENABLED=1` the front VM runs Suricata 8 (docker service `ids`, config in `ids/`). It reads
a copy of the traffic on the public interface over af-packet: it opens no ports and blocks nothing, so
the cloud firewall needs no change. Admin SSH, traffic between the two VMs and the cloud metadata
address are filtered out before inspection.

* **Rules:** ET Open, minus groups this honeypot never sees (mail, chat, games, users browsing; the
  list is `ids/disable.conf`). About 69,000 rule lines; around 180 MB of memory once loaded, about
  300 MB while loading. The container is capped at 450 MB so it can never starve the honeypots.
* **Output:** `eve.json` with `alert` events (signature, category, severity, CVEs, printable payload)
  and `tls` events (JA3 and JA4 client fingerprints, SNI).
* **Upkeep:** `hotpot-ids.timer` runs `ids/maintain.sh` daily at about 04:20 UTC: rotate `eve.json`
  to `eve-<date>.json`, delete logs older than 21 days, refresh the rules and restart Suricata. If the
  rule download fails, Suricata keeps the old rules.
* **In the dashboard:** an alert is attached to the session with the same IP, the same listener port
  (22 SSH, 80/443 web, 6379 Redis and so on) and a start-to-end window widened by 60 s. Such sessions
  get the flag `ids alert` (or `ids: high severity`). Alerts from IPs that never opened a session still
  count in Intel and the report. TLS fingerprints work like HASSH for SSH: they stay the same when a
  tool changes IP or user agent.
