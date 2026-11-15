# Changelog

All notable changes. Versions follow [semantic versioning](https://semver.org/); `hotpot version`
prints the one you have.

## Unreleased

* **The server gives itself away less.** Two test runs with a real agent tool named the same tells, now
  fixed. Deploy the backend (`hotpot deploy backend`) to apply them:
  * The SSH-side canary is a change-control house rule (`logger -t ..-ops "CHG-<token> <name> - <reason>"`)
    in the login banner and the runbook, instead of a line addressed to "AI assistants" in four files.
  * Credentials sit where they would really live (`/root/.my.cnf`, the deploy user's `~/.aws/credentials`)
    instead of together in the runbook.
  * Bait files are dated over the past year, the backup folder holds 30 nightly dumps of made-up rows,
    the backup log exists, and the command histories are longer.
  * `/etc/nb/` and `/var/backups/nb/` kept the public reference initials on every install; they are now
    `/etc/<initials>-ops/` and `/var/backups/<initials>-intranet/`.
* **Agent tools with uneven pauses are caught:** a session that follows up on what it saw and writes its
  commands the way models do (section headers, friendly fallbacks) is a suspected AI agent even when its
  pauses look like a person's. A Claude Code test session had been called Human-like.
* **Test real agent tools:** `tools/agent_eval.py bridge` keeps one shell on the honeypot open so a coding
  agent such as Claude Code can run commands through it without ever seeing the password; the session is
  labelled for the detection report. The command the agent is given has a plain name and path
  (`srv-tools/rsh.py` in your home folder), so it doesn't give the test away.
* **Alerts on your phone:** an optional alert address in Settings (ntfy, Discord or Slack) gets a short
  message when a serious problem starts and when it is over. Titles only, no addresses.
* **Days of history to load** (Settings, 7 by default) caps the dashboard's memory as logs pile up. Older
  logs stay on disk.
* **Half the memory again:** the dashboard no longer keeps the "connected" and "closed" lines of
  brute-force floods on the RDP and SMB decoys past the first 40 per visit, and works out what a decoy
  event means when it is shown instead of storing it. About 1 GB became about 500 MB.

* **Health banner:** the dashboard says in plain words when something is wrong (sensor unreachable, a VM
  overloaded or not answering, disk filling up, a service or the collector stopped, a honeypot gone
  quiet), with optional desktop notifications.
* **Identity check after deploy:** `hotpot deploy` and `hotpot status` confirm that the web honeypot and
  the container show this install's identity, not the public reference one.
* **AI pages follow the identity:** pages the web honeypot's AI wrote are deleted when the identity
  changes, so none keeps naming the old company.
* **"Files captured" counts each file once.** It counted every changed version; malware rewriting one
  file every minute had made it 12 times the number of samples.
* **Dashboard uses less memory and time:** identical commands that malware repeats (one ran 125,000
  times) are kept 20 times per login with a count of the rest, repeated text is stored once, and
  matching logins to sessions is faster. On the reference sensor a refresh went from 30 s to 20 s and
  memory from about 2 GB to about 1 GB.

* **Reset on overload:** when malware in the container keeps the backend VM's load at 15 or more for
  three minutes, the container is harvested and reset at once instead of at night. A brute-forcer and
  miner had pushed the load to 92, and logins hung for everyone.

* **Sleeping scripts are no longer called AI agents:** an SSH session with clockwork pauses (the same
  length to within 4%) is a script, and "suspected AI agent" now also needs the visitor to follow up on
  what it saw (list a directory, then open something in it). In the first test the old rule called 9 of
  9 sleeping scripts agents; the new one calls none, and still catches the test agent.

* **Detection test:** `tools/agent_eval.py` runs scripted sessions and a test AI agent against your own
  honeypot, lets you label sessions you run with real tools, and reports how often the dashboard's
  classes were right.

* **AI pages tab:** lists the pages the web honeypot's AI fallback wrote and saved, with the request,
  the model, how often each was served and who asked for it first. Click a path to read the page, or
  Preview to see an HTML page rendered in a sandbox that runs no scripts and loads nothing from outside.

* **Fewer false AI-agent alarms:** SSH sessions typed from a desktop client such as PuTTY, or with pasted
  commands, now count as human. Pauses after slow commands (installs, downloads) no longer look like an
  agent "thinking". Two of last week's three suspected agents were a person pasting commands and a
  script waiting for `apt`.

* **AbuseIPDB reports skip research scanners:** networks of known internet research scanners (Censys,
  Shodan, Shadowserver, Modat and others) are no longer reported, even without a GreyNoise lookup.
  Earlier runs had reported a few of them for reading a decoy's data.
* **Rebuilding the backend container no longer floods Samples:** the installer now pauses the collector
  for every install, not only when it updates an existing container. A rebuild had stored about 1,700
  of the new container's own system files as samples.
* **Same kernel everywhere:** `hotpot deploy` reads the backend's real kernel and Ubuntu version and
  uses them in the fake shell (`uname`, `/proc/version`, `dmesg`, `hostnamectl`, the motd) and the decoy
  services (Redis, Docker, Elasticsearch, Kubernetes). Before, they claimed an older kernel than the
  real shell, which gave the honeypot away.
* **Map replay** on the Overview: "Replay last 24 hours" plays the last day's events as arcs on the
  map, squeezed into 30 seconds to 3 minutes, with pause and a position slider.
* **Fewer duplicate samples:** the backend keeps the first 5 versions of each changed text file until the
  container restarts, instead of every version. Malware left running had rewritten `.bashrc` every
  minute, which filled the Samples tab with more than 100 near-identical copies. Programs, scripts and
  binary files are still always kept. Text at the same path that differs from an earlier sample only in
  standalone numbers (a PID, a counter) is not stored again either, across resets; addresses, ports,
  keys and URLs still count. The Samples tab lists the skipped versions under "Versions not stored",
  with the path, how many, why, and the hash of the newest one.
* **Indicator export** on the Intel tab: attacker IPs, sample hashes, URLs and domains as a STIX 2.1
  bundle, a MISP event, CSV or a plain blocklist, with a TLP marking.
* **Log forwarding** from the dashboard to syslog (UDP, TCP, TLS), Elasticsearch/OpenSearch, Splunk HEC
  or any NDJSON endpoint, set up in Settings.
* **Clean-up on the VMs:** a daily `hotpot-retention` timer on both VMs with `LOG_KEEP_DAYS`,
  `SAMPLE_KEEP_DAYS` and `DISK_MAX_PERCENT`, and a `hotpot cleanup` command. The web honeypot now
  rotates `web.jsonl` at 64 MB, and the backend's event log gets a new name at each rotation so the
  dashboard's copy of an older one is never overwritten.
* **Reporting to AbuseIPDB** from Settings: attackers that guessed passwords, went for bait or touched
  a decoy's data, each at most once a day, with a preview of what would be sent.
* **Backend memory:** a 2 GB swap file on the backend VM and a 448 MiB default for the container, with
  no swap of its own, after a miner in the container made the VM run out of memory.
* **Settings** is grouped into cards with a side menu and a status chip per card, and now also shows
  what `honeypot.conf` deploys (features, VMs, decoys, LLM fallback, clean-up), the decoy identity with
  a warning while it is still the public reference one, and an About card with version and data size.

## 1.0.0

First public release.

* **Capture:** Cowrie in proxy mode in front of a real Incus container (or Cowrie's emulated shell on
  a single VM); auditd-based collection of every program, connection and file change; quarantine of
  dropped files, memory-only binaries and fetched URLs; web honeypot with bait files, fake logins,
  WordPress, LLM-generated pages, and agent surfaces (llms.txt, OpenAPI, an MCP server, an A2A agent,
  AGENTS.md); eight decoy services (Redis, Docker API, Elasticsearch, MySQL, Ollama, Kubernetes, RDP,
  SMB); Suricata network IDS.
* **Analysis:** AI-agent score and canary tripwires, known-bot signatures, MITRE ATT&CK mapping,
  HASSH/JA3/JA4/JA4H fingerprints, campaigns, YARA, VirusTotal, MalwareBazaar, AbuseIPDB and GreyNoise.
* **Dashboard:** local-only console with a zoomable map coloured by how far sessions got, live hits,
  sessions with replay, traps, statistics against the previous period, intel lists, samples, weekly
  reports, VM status and settings. Session filters search the whole period on the server.
* **Operations:** `hotpot` CLI (setup wizard, checks, deploy, port test, status, dashboard autostart),
  a per-install random identity so installs can't be fingerprinted from the public repo, `hotpot update`,
  and one-line installers for Linux, macOS and Windows.
