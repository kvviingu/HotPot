# Fleet design: many sensors, one master

Status: proposal (2026-11-11). Nothing here is built yet.

## Goal

Run several honeypots ("sensors") in different networks and countries. A single master server
collects their events and every captured sample, deduplicates them, analyses the samples, and shows
the whole fleet in one dashboard. Comparing sensors is the point: does the same agent, botnet or
dropper reach all of them, in what order, and does it adapt to each persona?

Constraints carried over from the single-sensor setup:

* Never open a new inbound port to the internet on a sensor.
* Samples never reach a workstation; they live only on machines built for that.
* Treat everything collected as attacker-controlled, including whatever a compromised sensor sends.
* Stay inside free tiers where possible.

## Decision 1: the master pulls, sensors don't push

| | Pull over SSH (recommended) | Push to an ingest API |
|---|---|---|
| New listening services | none on sensors; master needs only admin SSH | an HTTPS ingest endpoint on the master, open to every sensor |
| A compromised sensor can... | only serve bad data when asked | send data at will, and hold a credential for the master's API |
| A compromised master can... | run the export script on every sensor, nothing else (forced command) | nothing on sensors |
| Sensors behind NAT | not reachable without a relay | work |
| Code to reuse | the dashboard already syncs this way (offsets, signatures, dedup) | new on both sides |
| Latency | the poll interval (15-60 s) | seconds |

**Pull wins at this scale** (a handful of sensors, all on cloud VMs with public IPs). It adds no
attack surface on either side, and the existing sync code becomes the master's collector. The master's
SSH key is limited by a forced command on each sensor (below), so a stolen key reads logs and nothing
more. Push can be added later for NAT'd sensors without changing the storage side.

### Restricted export account on each sensor

The installers add a user `nbexport` on the front and backend VMs. It has no password, no shell and no
sudo except one command:

```
# /home/nbexport/.ssh/authorized_keys on the FRONT VM
restrict,port-forwarding,permitopen="BACKEND_IP:22",from="MASTER_IP",command="/usr/local/sbin/nb-export" ssh-ed25519 AAAA... master
# on the BACKEND VM
restrict,from="FRONT_PRIVATE_IP",command="/usr/local/sbin/nb-export" ssh-ed25519 AAAA... master
# /etc/sudoers.d/nbexport
nbexport ALL=(root) NOPASSWD: /usr/local/sbin/nb-export-root
```

* **`nb-export`** reads a request from stdin and calls `nb-export-root` with fixed, validated
  arguments. A request is a JSON list of `{source, offset, sig}` cursors, or a list of sample hashes.
* **`nb-export-root`** answers with the requested log bytes (the current `REMOTE_SCRIPT` logic, moved
  into a file that lives on the sensor), or with the requested samples. It reads only fixed paths:
  Cowrie and web logs on the front, `/var/lib/nb-export` and `/var/lib/nb-quarantine` on the backend.
* **Reaching the backend:** the master jumps through the front VM. `permitopen` allows a tunnel to the
  backend's SSH and nowhere else.
* **Admin SSH port:** the master connects to the existing admin port. The cloud firewall gets one more
  source IP: the master's.

## Decision 2: sensor identity and per-sensor personas

`honeypot.conf` gains:

```
SENSOR_ID=fra-1                 # short, unique, never shown to attackers
PERSONA=northbridge             # directory under personas/
```

**Sensor ID.** Events get the sensor ID at the master (it knows which sensor it pulled from), so
sensors never have to be trusted to label themselves.

**Why personas must differ.** Identical sensors are the fastest way to get the whole fleet
fingerprinted. One honeypot spotted means all of them land on Shodan-style "honeyscore" lists and
shared blocklists. So `cowrie/honeyfs` becomes `personas/<name>/` plus `persona.conf`:

```
personas/northbridge/
  persona.conf        COMPANY, DOMAIN, HOSTNAME, USERS, OS_RELEASE, KERNEL, SSH_BUILD, ARCH, INTERNAL_NET...
  honeyfs/            files, with {{COMPANY}}-style placeholders where a value differs per sensor
  web/                bait pages and the fake admin app's branding
```

**What gets generated per sensor at install time:**
- SSH host keys, and the fake `authorized_keys` and API keys in bait files.
- MOTD dates, the fake internal IPs, and the canary token.

**Canary tokens become per-sensor.** `NB-AGENT-CHECK-<random>` is generated per sensor and recorded on
the master. An agent that read the token on sensor A and uses it on sensor B (or anywhere we can see)
links the two sessions. That is strong evidence of the same operator or agent memory.

**Match the hardware.** An Oracle A1 sensor is ARM: `uname -m`, `/proc/cpuinfo` and the persona's
story must say aarch64. A persona declares `ARCH`, and the installer refuses a mismatch.

Ship 3 or 4 personas: the current logistics file server, a small dev shop's CI runner, a dental
clinic's NAS, and a hosting reseller's mail server. Each has a different set of services and users.

## Decision 3: the master

A separate VM: never the workstation, because it holds the malware. Oracle A1 Flex
(1 OCPU, 6 GB, ARM, Always Free) fits, in its own subnet. Inbound is limited to admin SSH from the
operator's IP. Outbound is SSH to the sensors, plus HTTPS for hash lookups.

```
master VM
  /srv/nb/raw/<sensor>/<source>/<yyyy-mm-dd>.jsonl.gz   append-only copy of every pulled byte
  /srv/nb/samples/<ab>/<cd>/<sha256>.bin               content-addressed, 0400, on a noexec mount
  /srv/nb/nb.sqlite                                    index: sessions, events, samples, sightings
  nb-master (systemd)   collector loop, normaliser, analysis queue, dashboard API on 127.0.0.1
```

**Raw files are the source of truth.** The SQLite index is rebuilt from them whenever the parsing
changes, which is how the dashboard already works. At today's volume, about 20 MB of events per
sensor per day, SQLite with WAL handles tens of sensors for years. The upgrade path, if it is ever
needed, is DuckDB over the raw files for analysis, with no change to the collector.

**Core tables**

| Table | Holds |
|---|---|
| `sensors` | id, persona, region, provider, first/last seen, last pull, status |
| `sessions` | the current session model (web/ssh/telnet, class, stage, timing) plus `sensor_id` |
| `events` | normalised events with `(sensor_id, source, source_offset)` as the dedup key |
| `samples` | sha256, size, type, first seen, analysis results |
| `sightings` | sample x sensor x session x path or URL x time: the many-to-many that makes cross-sensor questions answerable |
| `tokens` | per-sensor canary tokens and every place each token was used |

**Collector loop:** for each sensor, every 30 s:
1. Pull new log bytes from the front, then from the backend through it.
2. Write them to the raw files.
3. Normalise them into `events` and `sessions`.
4. List sample hashes the master doesn't have yet, and pull only those. Samples are deduplicated by
   hash before they cross the network.

A sensor that is down is skipped and retried with backoff. It shows as stale in the dashboard rather
than blocking the others.

## Decision 4: analysis pipeline (on the master, nothing executes)

Run per new sample, from a queue:

1. **Static facts:** `file`, size, entropy, ELF header (arch, stripped, static or dynamic, packer
   hints such as UPX), strings, and TLSH/ssdeep similarity hashes.
2. **YARA:** community rulesets (for example signature-base and the Elastic and ReversingLabs
   open rules), plus our own rules for droppers seen on this fleet.
3. **Hash reputation:** only the hash is sent to MalwareBazaar, VirusTotal and abuse.ch, never the
   file. Uploading a sample is a manual decision, because it tells the attacker their sample was seen.
4. **Script unpacking:** for shell droppers, extract every URL and IP and link them back to sightings.
   Payloads are not fetched again; the sensor already did that.
5. **Sandbox:** later, and only on a separate, isolated analysis VM such as CAPEv2 with its own
   network policy. It is a separate project; the master only exports to it.

**Cross-sensor clustering** groups sessions into campaigns by:
- shared sample hash or TLSH neighbour;
- HASSH plus client version;
- normalised command sequence, with IPs and random names masked;
- canary token reuse;
- source ASN.

## Dashboard

The dashboard moves onto the master and reads SQLite instead of mirrored files. It still listens on
127.0.0.1 only; the operator reaches it with `ssh -L 8787:127.0.0.1:8787 master`. The pages stay; what's
new:
- a sensor filter;
- a fleet health strip showing last pull per sensor;
- a Samples tab with hash, type, YARA hits, sightings and reputation;
- a Campaigns tab from the clustering;
- "same actor on several sensors" timelines.

## Fleet operations

```
fleet/
  master.conf               master IP, SSH key for pulls, retention, API keys for hash lookups
  sensors/fra-1.conf        a honeypot.conf per sensor (today's deployment)
  sensors/ams-1.conf
./deploy.sh --sensor fra-1 front|backend|status
./deploy.sh master                   install or update the master
./deploy.sh fleet status             one line per sensor: ok, stale, down
```

`deploy.sh front|backend` for a sensor also installs `nbexport` with the master's public key.

## Legal and data handling

Attacker IP addresses and the passwords they type count as personal data under GDPR. For research,
legitimate interest usually covers collecting them, but write down:
- **Retention:** for example, raw events 12 months, aggregates indefinitely.
- **Access:** who can see the master.
- **Publication:** IPs are never published unaggregated.

Check what your university or employer requires if the data feeds a thesis.

## Plan

| Phase | Delivers | Proves |
|---|---|---|
| 1. Master v1 | master VM; `nbexport` on today's sensor; collector, raw store, SQLite, sample pull; dashboard moved over | the pull model works end to end with one sensor, renamed `fra-1` |
| 2. Personas | `personas/` with templating, per-sensor keys and canary tokens; a second persona | two sensors that share no fingerprintable artefact |
| 3. Second sensor | one more region or provider (Oracle A1 ARM, or another free tier); `fleet` commands | cross-sensor views on real traffic |
| 4. Analysis | static analysis, YARA, hash reputation, Samples tab | samples become findings |
| 5. Campaigns | clustering, Campaigns tab, canary cross-linking | the research question: the same actors across sensors |

Phase 1 changes nothing an attacker can see, so it is safe to build on the live sensor. Phase 2 must
land before the second sensor goes online.

## Open questions

1. **Where the second sensor runs.** Your Oracle tenancy is at its limit for E2.1.Micro VMs. A1 ARM
   capacity in Frankfurt is free but often "out of host capacity", and an ARM sensor needs an ARM
   persona. Another provider's free tier (Google Cloud e2-micro in a US region, for example) gives
   geographic spread.
2. **Single-VM sensors.** Should sensors without a backend VM (Cowrie's emulated shell only) be a
   supported, cheaper sensor type? They are easy to fingerprint, but useful for counting scanners.
3. **Hash lookups.** Are hash lookups at third parties acceptable to you? They leak almost nothing,
   but they are outbound requests.
