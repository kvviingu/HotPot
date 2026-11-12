# Distro layer for the installers (sourced by install/lib.sh): what this machine is, and how to install
# packages, Docker and Incus and open firewall ports on it.
# Supported: Ubuntu 22.04 / 24.04 and Debian 12 / 13, on amd64 or arm64.

OS_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OS_ID="" OS_VER="" OS_NAME="" OS_CODENAME="" OS_FAMILY="" ARCH=""
SUPPORTED_TEXT="Ubuntu 22.04 or 24.04, Debian 12 or 13, on amd64 or arm64"

detect_os() {
  [ -r /etc/os-release ] || die "cannot read /etc/os-release; is this a Linux server?"
  local ID="" VERSION_ID="" PRETTY_NAME="" VERSION_CODENAME="" ID_LIKE=""
  # shellcheck disable=SC1091
  . /etc/os-release
  OS_ID=${ID:-unknown} OS_VER=${VERSION_ID:-} OS_NAME=${PRETTY_NAME:-$ID} OS_CODENAME=${VERSION_CODENAME:-}
  case " $OS_ID ${ID_LIKE:-} " in
    *" debian "* | *" ubuntu "*) OS_FAMILY=debian ;;
    *" rhel "* | *" fedora "* | *" centos "*) OS_FAMILY=rhel ;;
    *) OS_FAMILY=other ;;
  esac
  case "$(uname -m)" in
    x86_64) ARCH=amd64 ;;
    aarch64 | arm64) ARCH=arm64 ;;
    *) ARCH=$(uname -m) ;;
  esac
}

os_supported() {
  case "$OS_ID:$OS_VER" in ubuntu:22.04 | ubuntu:24.04 | debian:12 | debian:13) ;; *) return 1 ;; esac
  case "$ARCH" in amd64 | arm64) ;; *) return 1 ;; esac
}

need_supported_os() {
  detect_os
  os_supported && return 0
  if [ "${HOTPOT_FORCE:-0}" = 1 ] && [ "$OS_FAMILY" = debian ]; then
    warn "$OS_NAME ($ARCH) is not a supported system; continuing because HOTPOT_FORCE=1"
    return 0
  fi
  die "$OS_NAME ($ARCH) is not supported. Use $SUPPORTED_TEXT.
       (On another Debian-based system you can try anyway with HOTPOT_FORCE=1.)"
}

# ---- packages -----------------------------------------------------------------------------------------
APT_UPDATED=0
pkg_name() {
  local col=2
  [ "$OS_FAMILY" = rhel ] && col=3
  awk -F'\t' -v k="$1" -v c="$col" '!/^#/ && $1 == k { print $c; exit }' "$OS_DIR/packages.tsv"
}
pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "ok installed"; }
pkg_update() {
  [ "$APT_UPDATED" = 1 ] && return 0
  apt-get update -q
  APT_UPDATED=1
}
# install the distro packages for the given logical names (see packages.tsv); skips what is installed
pkg_install() {
  [ "$OS_FAMILY" = debian ] || die "package installs are only implemented for Debian and Ubuntu so far"
  local want=() n p
  for n in "$@"; do
    p=$(pkg_name "$n")
    [ -n "$p" ] || die "install/packages.tsv has no entry for '$n'"
    [ "$p" = - ] && continue
    pkg_installed "$p" || want+=("$p")
  done
  [ ${#want[@]} = 0 ] && return 0
  step "Installing packages: ${want[*]}"
  pkg_update
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${want[@]}"
}
# apt-get install of exact package names, for packages that come from an added repository
pkg_install_raw() {
  local want=() p
  for p in "$@"; do pkg_installed "$p" || want+=("$p"); done
  [ ${#want[@]} = 0 ] && return 0
  step "Installing packages: ${want[*]}"
  pkg_update
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${want[@]}"
}

# add an apt repository whose signing key must have the given fingerprint (checked, not trusted blindly)
#   add_apt_repo NAME KEY_URL FINGERPRINT "URI SUITE COMPONENTS"
# HOTPOT_PROXY, when set, is used to download the key (the backend VM has no direct internet).
add_apt_repo() {
  local name=$1 url=$2 fpr=$3 src=$4 key=/etc/apt/keyrings/$1.gpg list=/etc/apt/sources.list.d/$1.list tmp got
  if [ -s "$list" ] && [ -s "$key" ]; then return 0; fi
  pkg_install ca-certs curl gnupg
  install -d -m 755 /etc/apt/keyrings
  tmp=$(mktemp)
  curl -fsSL --retry 3 --max-time 60 ${HOTPOT_PROXY:+--proxy "$HOTPOT_PROXY"} "$url" -o "$tmp" \
    || { rm -f "$tmp"; die "cannot download the signing key for the $name repository from $url"; }
  # Import into a throwaway keyring, require exactly one primary key with the pinned fingerprint, and
  # export only that key: extra keys smuggled into the downloaded file never reach apt.
  local gh
  gh=$(mktemp -d)
  GNUPGHOME=$gh gpg --batch --quiet --import "$tmp" 2>/dev/null || true
  got=$(GNUPGHOME=$gh gpg --batch --with-colons --list-keys 2>/dev/null \
        | awk -F: '$1 == "pub" { want = 1; next } want && $1 == "fpr" { print $10; want = 0 }' | paste -sd, -)
  if [ "$got" != "$fpr" ]; then
    rm -rf "$tmp" "$gh"
    die "the $name signing key file holds '${got:-no key}', expected exactly $fpr; refusing it"
  fi
  GNUPGHOME=$gh gpg --batch --yes --export -o "$key" "$fpr"
  chmod 644 "$key"
  rm -rf "$tmp" "$gh"
  echo "deb [arch=$ARCH signed-by=$key] $src" > "$list"
  APT_UPDATED=0
}

DOCKER_KEY_FPR=9DC858229FC7DD38854AE2D88D81803C0EBFCD88
ZABBLY_KEY_FPR=4EFC590696CB15B87C73A3AD82CC8797C838DCFD

# Docker Engine with the compose v2 plugin
ensure_docker() {
  if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
    systemctl enable --now docker >/dev/null 2>&1 || true
    return 0
  fi
  step "Installing Docker"
  case "$OS_ID" in
    ubuntu) pkg_install docker docker-compose ;;
    *)
      # Debian's own docker.io has no compose v2 plugin on Debian 12: use Docker's repository
      add_apt_repo docker https://download.docker.com/linux/debian/gpg "$DOCKER_KEY_FPR" \
        "https://download.docker.com/linux/debian $OS_CODENAME stable"
      if command -v docker >/dev/null; then
        pkg_install_raw docker-compose-plugin                     # keep the existing engine
      else
        pkg_install_raw docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
      fi
      ;;
  esac
  systemctl enable --now docker
  docker compose version >/dev/null 2>&1 || die "Docker is installed but 'docker compose' does not work"
}

# Incus (the backend's container manager)
ensure_incus() {
  if command -v incus >/dev/null; then return 0; fi
  step "Installing Incus"
  case "$OS_ID:$OS_VER" in
    ubuntu:24.04 | debian:13) pkg_install incus ;;
    debian:12)
      pkg_update
      if ! apt-cache policy | grep -q "bookworm-backports"; then
        echo "deb http://deb.debian.org/debian bookworm-backports main" > /etc/apt/sources.list.d/hotpot-backports.list
        APT_UPDATED=0
        pkg_update
      fi
      DEBIAN_FRONTEND=noninteractive apt-get install -y -q -t bookworm-backports incus
      ;;
    *)
      # Ubuntu 22.04 (and forced systems): the Zabbly Incus LTS repository
      add_apt_repo zabbly-incus https://pkgs.zabbly.com/key.asc "$ZABBLY_KEY_FPR" \
        "https://pkgs.zabbly.com/incus/lts-6.0 $OS_CODENAME main"
      pkg_install_raw incus
      ;;
  esac
  command -v incus >/dev/null || die "Incus did not install"
}

# ---- host firewall ------------------------------------------------------------------------------------
# Open a TCP port in the host firewall. Cloud images differ: Oracle's ship a deny-by-default iptables
# INPUT chain, some have ufw switched on, most have nothing. The cloud provider's own firewall
# (security list / security group) is separate and still has to allow the port.
allow_input_tcp() {
  local port=$1
  if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "^Status: active"; then
    ufw allow "$port/tcp" >/dev/null
    return 0
  fi
  command -v iptables >/dev/null || return 0                # no host firewall at all
  iptables -C INPUT -p tcp -m state --state NEW -m tcp --dport "$port" -j ACCEPT 2>/dev/null && return 0
  iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport "$port" -j ACCEPT
  save_firewall
}
save_firewall() {
  if command -v netfilter-persistent >/dev/null; then netfilter-persistent save >/dev/null 2>&1 || true
  elif [ -d /etc/iptables ]; then iptables-save > /etc/iptables/rules.v4; fi
}

# ---- cloud provider (from DMI data, no network calls) -------------------------------------------------
detect_cloud() {
  local v p t
  v=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || true)
  p=$(cat /sys/class/dmi/id/product_name 2>/dev/null || true)
  t=$(cat /sys/class/dmi/id/chassis_asset_tag 2>/dev/null || true)
  case "$v|$p|$t" in
    *OracleCloud*) echo oracle ;;
    *Amazon*) echo aws ;;
    *Google*) echo gcp ;;
    *7783-7084-3265-9085-8269-3286-77* | *"Microsoft Corporation"*) echo azure ;;
    *Hetzner*) echo hetzner ;;
    *DigitalOcean*) echo digitalocean ;;
    *) echo unknown ;;
  esac
}
cloud_firewall_hint() {
  case "$1" in
    oracle) echo "Oracle Cloud: Networking > Virtual cloud networks > your VCN > Security Lists (or the instance's NSG) > Add Ingress Rules" ;;
    aws) echo "AWS: EC2 > Instances > your instance > Security > Security groups > Edit inbound rules" ;;
    gcp) echo "Google Cloud: VPC network > Firewall > Create firewall rule (target: this instance's tag)" ;;
    azure) echo "Azure: Virtual machine > Networking > Add inbound port rule" ;;
    hetzner) echo "Hetzner: Cloud Console > Firewalls > your firewall > Inbound rules" ;;
    digitalocean) echo "DigitalOcean: Networking > Firewalls > your firewall > Inbound Rules" ;;
    *) echo "your provider's firewall for this server (often called security group or security list)" ;;
  esac
}
