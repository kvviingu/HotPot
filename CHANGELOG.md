# Changelog

All notable changes. Versions follow [semantic versioning](https://semver.org/); `hotpot version`
prints the one you have.

## Unreleased

* **AI pages tab:** lists the pages the web honeypot's AI fallback wrote and saved, with the request,
  the model, how often each was served and who asked for it first. Click a path to read the page.

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
