# Cloud setup

The honeypot needs two VMs in one virtual network. The cloud firewall does most of the isolation, so
set it up exactly like this. The example uses Oracle Cloud (OCI) names, but any provider works.

## Network

| Subnet | Example CIDR | Route table | Holds |
|---|---|---|---|
| public | 10.0.0.0/24 | default route to the internet gateway | front VM (public IP) |
| backend | 10.0.1.0/24 | **empty: no internet, no NAT gateway** | backend VM (no public IP) |

## Firewall rules

**Front VM**, inbound:

| Port | From | For |
|---|---|---|
| TCP 22, 23, 80, 443 | 0.0.0.0/0 | the honeypot |
| TCP 6379, 2375, 9200, 3306, 11434, 6443, 3389, 445 | 0.0.0.0/0 | decoys, only those in `DECOY_SERVICES` |
| TCP `ADMIN_SSH_PORT` | your own IP only | your SSH |
| TCP 3128 | backend VM IP /32 | Squid: package installs and sample fetches |

**Front VM**, outbound: whatever the web honeypot's LLM fallback and Docker image pulls need (80, 443
and DNS are enough), plus TCP 22, `BACKEND_SSH_PORT` and `BACKEND_TELNET_PORT` to the backend subnet.

**Backend VM**, inbound:

| Port | From | For |
|---|---|---|
| TCP 22 | front VM private IP /32 | your SSH, jumped through the front VM |
| TCP `BACKEND_SSH_PORT`, `BACKEND_TELNET_PORT` | front VM private IP /32 | Cowrie forwarding logins |

**Backend VM**, outbound: only to the front VM's private IP (TCP 3128 is all it uses). On OCI, also
allow 169.254.169.254 so the instance agent keeps working.

## VMs

* **Image:** Ubuntu 24.04 or 22.04, or Debian 13 or 12, on both; amd64 or arm64 (OCI Ampere works).
  Other systems are refused (`HOTPOT_FORCE=1` tries another Debian-based one anyway).
* **SSH key:** use the same key for both VMs. `hotpot` reaches the backend through the front VM.
* **Shapes:** both run on 1 OCPU and 1 GB RAM. Give the backend a boot volume of about 50 GB.
* **OCI images:** these ship with a default-deny `iptables` INPUT chain. The front installer opens
  `ADMIN_SSH_PORT` in it. The backend needs no change, because the container ports go through Incus's
  own forwarding rules.

## Settings for honeypot.conf

| Setting | Value |
|---|---|
| `FRONT_PUBLIC_IP` | the front VM's public address |
| `FRONT_PRIVATE_IP` | the front VM's private address; Squid binds to it |
| `BACKEND_IP` | the backend VM's private address |

Then run `./hotpot setup` (or `./hotpot check` if `honeypot.conf` is already filled in). It runs the installers' preflight checks on both VMs (system, RAM,
disk, ports, internet access, the private network, apt mirrors) and changes nothing.

If your provider's images use their own apt mirror (Hetzner uses `mirror.hetzner.com`, for example),
the backend's check reports it. Add it to `EXTRA_APT_MIRRORS` and run `./hotpot deploy front` again, so
the front VM's proxy lets the backend reach it.
