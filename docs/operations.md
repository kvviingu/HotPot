# Operations

## Where the data is

| What | Where |
|---|---|
| Cowrie events (JSON) | front: docker volume `honeypot_cowrie-var`, `log/cowrie/cowrie.json*` |
| Web honeypot events and its page cache | front: docker volume `honeypot_web-data` |
| Backend events: exec, connect, file, fetch (JSONL) | backend: `/var/lib/nb-export/backend.jsonl` |
| Quarantined samples, named `<sha256>.bin`, mode 0400 (text at the same path that differs from an earlier sample only in standalone numbers, such as a PID, is not stored again; addresses, ports, keys and URLs still count, and each text file keeps at most 5 versions per container start; the hash of a dropped version is still logged, and programs, scripts and binary files are always kept) | backend: `/var/lib/nb-quarantine/files/` |
| Nightly harvests: tarball, file list, sha256 list | backend: `/var/lib/nb-harvest/` (kept `SAMPLE_KEEP_DAYS`) |
| Raw audit log (auditd rotates it: 8 files of 50 MB) | backend: `/var/log/audit/` |
| Decoy service events | front: docker volume `honeypot_decoy-data`, `services.jsonl` |
| Suricata alerts and TLS fingerprints (EVE JSON) | front: `/var/lib/docker/volumes/honeypot_ids-log/_data/eve.json`, older days `eve-<date>.json` (kept `LOG_KEEP_DAYS`) |
| Suricata rules | front: `/var/lib/docker/volumes/honeypot_ids-lib/_data/rules/suricata.rules` |
| Dashboard's local copy of the logs, settings, reports | your machine: `dashboard/data/` (gitignored) |

Treat every byte of it as attacker-controlled: IPs, usernames, passwords, commands and file names
included. The dashboard escapes all of it. Your own scripts should too.

## Installer

`install/front.sh` and `install/backend.sh` run on the VMs (`hotpot` copies the repo and starts
them over SSH).

* **Supported systems:** Ubuntu 22.04/24.04 and Debian 12/13, amd64 or arm64. `install/os.sh` detects
  the system. Package names per distro family are in `install/packages.tsv`. Docker comes from Ubuntu's
  own packages, or from Docker's repository on Debian. Incus comes from the distro, Debian 12
  backports or the Zabbly repository on Ubuntu 22.04. Third-party signing keys are checked against
  pinned fingerprints.
* **Preflight:** `./hotpot check` (or `sudo bash install/front.sh --check` on the VM) checks the
  system, RAM, disk, ports, internet, the private network and apt mirrors, and changes nothing. The
  installers run the same checks before they start.
* **Moving admin SSH** off port 22 takes two steps. First sshd listens on 22 and `ADMIN_SSH_PORT`,
  and a 10-minute timer (`hotpot-ssh-revert`) is armed to undo that. Then `hotpot` connects to
  the new port from your machine and, if that works, finishes with `front.sh --confirm-ssh`. If the
  connection fails, it puts SSH back on 22 right away (`front.sh --revert-ssh`). If nobody confirms,
  the timer does it.
* **Port test:** `./hotpot ports` connects to every public port from your computer. *Open* is fine;
  *closed* means the VM answered but nothing listens (not deployed, or a container is down);
  *blocked* means no answer, almost always the cloud firewall. Many home ISPs block outgoing 445.
* **Dashboard at login:** `./hotpot dashboard --autostart on` (Windows Startup folder, a macOS
  LaunchAgent, or a systemd user service); `--autostart off` removes it.
* **Log and re-runs:** everything goes to `/var/log/hotpot-install.log` on the VM. If a step fails,
  fix the cause and run the same command again; every step is safe to repeat.

## Handling samples

* **Samples stay on the backend VM.** If you need to analyse one, copy it as a password-protected
  archive (the usual `infected` convention) to an isolated analysis machine, never to your workstation:
  ```bash
  ./hotpot ssh backend "sudo zip -j -P infected /tmp/s.zip /var/lib/nb-quarantine/files/<sha256>.bin"
  ```
* **Look up hashes first.** VirusTotal, MalwareBazaar and similar services often already know the sample.
* **Fetched URLs:** the backend fetches URLs found in attackers' commands at most 30 times an hour,
  16 MB each, HTTP/HTTPS on ports 80 and 443 only, and never to private or metadata addresses (Squid
  refuses those). Change `FETCH_PER_HOUR` and `MAX_FETCH` in `backend/nb-collect.py` if needed.

## Routine

* **Nightly reset** (about 03:40 UTC): `nb-reset.timer` saves everything changed since the last reset to
  `/var/lib/nb-harvest`, then rolls the container back to its `clean` snapshot. Its uptime therefore
  never exceeds a day.
* **Early reset:** after a persistence write the container is reset sooner, at most once per 10
  minutes ([detection.md](detection.md#early-container-reset)).
* **New releases:** `./hotpot update` pulls the latest release (with `git pull` in a git clone, or by
  downloading it from GitHub otherwise), keeps `honeypot.conf`, `persona.json`, `secrets/` and the
  dashboard's data, and offers to redeploy. `./hotpot version` prints the current version.
* **Your own changes:** edit the repo, then `./hotpot deploy` (or `deploy front` / `deploy backend`). Both are
  idempotent. The backend run restores the clean snapshot first and takes a new one afterwards.
  For persona, tripwire, collector or reset-script changes only, `./hotpot persona` is quicker.
* **IDS upkeep** (about 04:20 UTC): `hotpot-ids.timer` rotates Suricata's log and refreshes its rules
  ([detection.md](detection.md#network-ids-suricata)). Run it by hand with
  `./hotpot ssh front "sudo systemctl start hotpot-ids.service"`.
* **Clean-up** (about 05:10 UTC, both VMs): `hotpot-retention.timer` deletes rotated logs and Cowrie's
  recordings older than `LOG_KEEP_DAYS` (30), and samples and harvests older than `SAMPLE_KEEP_DAYS`
  (90). If the disk is fuller than `DISK_MAX_PERCENT` (85) it then deletes the oldest data, logs first,
  samples last, until it is below. It never touches a file a service is still writing. The dashboard's
  copy in `dashboard/data/mirror/` keeps every line it synced, so sync at least once within
  `LOG_KEEP_DAYS`. `./hotpot cleanup` shows disk use per kind of data, `cleanup dry-run` what would go,
  `cleanup run` runs it now.
* **Health:** `./hotpot status`. The dashboard's Sync button turns red when the front VM fails, and
  says "backend failed" when only the backend pull fails.

## Changing the persona

The persona lives in `cowrie/honeyfs/`: `/etc/passwd`, home directories with shell histories, the
Laravel app in `/var/www/northbridge`, nginx site, cron job, MOTD with the AI-agent canary. Both
shells use it:

* **Backend container:** run `./hotpot persona` after editing (harvest, reset, copy the files in,
  new clean snapshot). `./hotpot deploy backend` works too.
* **Cowrie emulated shell** (only with `BACKEND_ENABLED=0`): `./hotpot deploy front` rebuilds
  `cowrie/fs.pickle`.

Company name, domain and fake services in the web honeypot are constants at the top of `web/app.py`.
Keep the hostname, OS version and story the same everywhere: scanners compare the SSH banner, web
headers and what the shell reports.

Write new persona text with the reference values ("Northbridge Logistics", `fileserver01`,
`NB-AGENT-CHECK-...`, `nb-...` names). Each install's identity replaces them on the way to the VMs.

## Changing the identity

`persona.json` holds this install's identity. `persona.py` lists every reference value it replaces:
company and domain (`northbridge-logistics.com`, `northbridge.local`), host name, the
`NB-AGENT-CHECK` prefix and the four file canary values, the 15 tripwire credentials, the front
VM's private IP, and names built from the company's initials (`nb-intranet`, `nb_admin`, shipment
numbers like `NB-2026-104241`). The honeypot's own plumbing (`nb-collect`, `nb-reset`, `/etc/nb-honeypot.conf`)
runs outside what attackers see and keeps its name.

* `./hotpot identity` shows the current identity.
* `./hotpot identity new` makes a fresh one. Run `./hotpot deploy` to apply it. The dashboard picks it
  up on its next start; tripwire hits recorded under the old identity are no longer matched.
* A backend container that already exists gets the new host name and files, but keeps the old
  persona's files beside them. For a clean switch, delete it first:
  `./hotpot ssh backend "sudo incus delete -f <CT_NAME>"`, then `./hotpot deploy backend`.
* The kernel and Ubuntu version are not part of the identity. `./hotpot deploy` reads them from the
  backend container (or the front VM without a backend) and puts them into the fake shell and the
  decoy services, so `uname -r` gives the same answer everywhere. Deploy again after a kernel update.
* `./hotpot identity keep` writes the reference persona. Use it only for VMs that were deployed with
  it before identities existed: the reference values are public.

## Login policy

Only users `root`, `ubuntu`, `deploy` and `admin` can log in, and only with a password from
`cowrie/patches/passwords.txt`. Each (IP, user) pair is then locked to the first password that worked,
for 7 days, so that "any password works" doesn't give the honeypot away. Logins that look like known
honeypot probes are always refused (see `cowrie/userdb.txt`). Behind Cowrie, the real container
accepts one shared random password (`BACKEND_PASS`, generated on the front VM in
`/opt/honeypot/backend.env`); Cowrie logs in with it as whichever user the attacker typed.

## Troubleshooting

| Symptom | Check |
|---|---|
| SSH logins hang or close right away | Is the backend up (`./hotpot status`)? Can the front reach `BACKEND_IP:BACKEND_SSH_PORT`? (cloud firewall) |
| Backend install: "cannot reach the front VM's proxy" | Front installed with `BACKEND_ENABLED=1`? Front inbound TCP 3128 from the backend IP open? |
| No backend events in the dashboard | `systemctl status nb-collect` on the backend; `backend_host` in `dashboard/config.json` |
| No IDS alerts in the dashboard | `./hotpot ssh front "sudo docker logs --tail 20 ids"` should end with "Engine started". Is `IDS_ENABLED=1`? Rules present (Status tab, "IDS rules updated")? |
| Web pages for unknown paths are plain 404s | `secrets/openrouter.env` missing or the free models are rate-limited (HTTP 429). Pages are cached, so this improves over time. |

## More

* Dashboard tabs, samples, YARA, reputation, replay, weekly report: [dashboard.md](dashboard.md)
* Agent score, tripwires, known bots, campaigns, early resets, decoys, ATT&CK, Suricata: [detection.md](detection.md)
* Settings and keys: [configuration.md](configuration.md)
