# Configuration

These files hold settings. None of them is committed: `.gitignore` excludes `honeypot.conf`,
`persona.json`, `secrets/*`, `*.env`, `dashboard/config.json` and `dashboard/data/`.

| File | Holds | Written by |
|---|---|---|
| `honeypot.conf` | the deployment: addresses, ports, container, LLM, decoys, IDS, SSH access | `hotpot setup`, or you by hand from `honeypot.conf.example` |
| `persona.json` | this install's identity: company, host name, canary prefix and values, tripwire credentials ([operations.md](operations.md#changing-the-identity)) | `hotpot setup` or `hotpot identity new` |
| `secrets/openrouter.env` | `OPENROUTER_API_KEY` for the web honeypot's LLM fallback (optional) | you, from `secrets/openrouter.env.example` |
| `dashboard/config.json` | how the dashboard reaches the VMs | `hotpot dashboard` |
| `dashboard/data/settings.json` | API keys and dashboard options | the dashboard's Settings tab |

The front installer also generates `/opt/honeypot/backend.env` on the front VM (the shared password
Cowrie uses to log in to the container). It never leaves the VMs.

## honeypot.conf

Plain `KEY=value` lines, no spaces around `=`. It is read by bash, docker compose and Python.
`hotpot` copies it to the VMs, where the installers turn it into compose's `.env` and the backend
config.

| Key | Example | Meaning |
|---|---|---|
| `FRONT_PUBLIC_IP` | `203.0.113.10` | front VM public address |
| `FRONT_PRIVATE_IP` | `10.0.0.10` | front VM private address; Squid binds here |
| `ADMIN_SSH_PORT` | `22222` | your admin SSH moves here, because Cowrie takes 22 |
| `BACKEND_ENABLED` | `1` | `0` = no backend VM; Cowrie uses its emulated shell |
| `BACKEND_IP` | `10.0.1.10` | backend VM private address |
| `BACKEND_SSH_PORT`, `BACKEND_TELNET_PORT` | `2222`, `2323` | where Cowrie forwards logins on the backend |
| `CT_NAME` | `fileserver01` | Incus container name |
| `CT_BRIDGE_CIDR`, `CT_IP` | `10.200.0.1/24`, `10.200.0.10` | container's private bridge and address |
| `CT_MEMORY`, `CT_DISK_POOL_SIZE` | `560MiB`, `18GiB` | container limits |
| `LLM_ENABLED` | `1` | LLM-generated pages for unknown web paths |
| `LLM_MODELS` | comma list | OpenRouter models, tried in order |
| `LLM_DAILY_CAP`, `LLM_PER_MINUTE` | `300`, `10` | request limits for the fallback |
| `DECOYS_ENABLED` | `1` | run the decoy services container |
| `DECOY_SERVICES` | `redis,docker,elastic,mysql,ollama,k8s,rdp,smb` | which decoys to run |
| `IDS_ENABLED` | `1` | run Suricata on the front VM (needs about 300-450 MB RAM; no firewall change) |
| `LOG_KEEP_DAYS` | `30` | days the VMs keep rotated logs (Cowrie, web, decoys, Suricata, backend) and Cowrie's session recordings; `0` = forever |
| `SAMPLE_KEEP_DAYS` | `90` | days the VMs keep quarantined samples and nightly harvests; `0` = forever |
| `DISK_MAX_PERCENT` | `85` | above this disk use the daily clean-up deletes the oldest logs, then harvests, then samples, until it is below (50-98) |
| `EXTRA_APT_MIRRORS` | empty | extra apt mirror host names the backend may reach through the front VM's proxy (comma list; a leading dot allows subdomains). The defaults are in `install/mirrors.txt`. |
| `SSH_USER` | `ubuntu` | admin user on both VMs |
| `SSH_KEY` | `~/.ssh/honeypot_admin` | your admin key (same key for both VMs) |
| `KNOWN_HOSTS` | `~/.ssh/known_hosts_honeypot` | separate known_hosts file for the VMs |
| `OPERATOR_IPS` | empty | your own public IPs, hidden in the dashboard by default |

Set `HONEYPOT_CONF` to use a file other than `honeypot.conf`. Set `HOTPOT_FORCE=1` in the
environment to install on a Debian-based system that is not supported.

### Decoy ports

| Decoy | Port | Notes |
|---|---|---|
| `redis` | 6379 | |
| `docker` | 2375 | Docker API |
| `elastic` | 9200 | Elasticsearch |
| `mysql` | 3306 | login hashes logged for hashcat mode 11200 |
| `ollama` | 11434 | prompts logged, nothing generated |
| `k8s` | 6443 | Kubernetes API, TLS, fake secrets |
| `rdp` | 3389 | stops after NTLM login, NetNTLMv2 for hashcat mode 5600 |
| `smb` | 445 | same as RDP |

Each enabled decoy needs its port open in the cloud firewall ([cloud-setup.md](cloud-setup.md)).

### Suricata

The IDS has no settings in `honeypot.conf` beyond `IDS_ENABLED`. To tune it, edit the files in `ids/`
and run `./hotpot deploy front`:

| File | Change |
|---|---|
| `ids/suricata.yaml` | memory caps, `HTTP_PORTS`, which EVE event types are logged |
| `ids/disable.conf` | ET Open rule groups left out (one `group:<file>` per line) |
| `LOG_KEEP_DAYS` in `honeypot.conf` | how long old `eve-*.json` files are kept (the daily clean-up deletes them) |
| `docker-compose.yml`, service `ids` | the capture filter and the container's memory cap |

The installer picks the interface that holds `FRONT_PRIVATE_IP` and writes it to `.env` as
`IDS_INTERFACE`.

## Dashboard

`dashboard/config.json` (see `dashboard/config.example.json`):

| Key | Meaning |
|---|---|
| `ssh_host`, `ssh_port`, `ssh_user`, `ssh_key`, `known_hosts` | admin SSH to the front VM |
| `ssh_path` | path to `ssh` if it is not on `PATH` (empty = find it) |
| `backend_host`, `backend_user` | backend VM, reached through the front VM; empty without a backend |
| `own_ips` | from `OPERATOR_IPS` |
| `sync_seconds` | how often logs are pulled (default 15) |
| `port` | local port (default 8787; the `PORT` environment variable overrides it) |

Settings tab (stored in `dashboard/data/settings.json`):

| Setting | Used for |
|---|---|
| VirusTotal API key, MalwareBazaar Auth-Key | sample hash lookups and confirmed uploads |
| Check new samples automatically | background hash lookups, 4 a minute |
| AbuseIPDB API key, GreyNoise API key (optional) | IP reputation |
| Check attacker IPs automatically | one lookup a minute, most interesting sessions first |
| Pull logs every (seconds), My own IPs | same as `sync_seconds` and `own_ips` |
| Forward logs | where new events go after each sync: type, address, token, index, sensor name, CA file, sources ([dashboard.md](dashboard.md#log-forwarding)) |
