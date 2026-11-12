# Changelog

All notable changes. Versions follow [semantic versioning](https://semver.org/); `hotpot version`
prints the one you have.

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
