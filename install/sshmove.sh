# Moving admin SSH off port 22 (Cowrie needs it) without locking anyone out. Sourced by install/front.sh.
#
#   1. ssh_move_begin   sshd listens on 22 AND ADMIN_SSH_PORT; a timer undoes this in 10 minutes
#   2. (you connect to ADMIN_SSH_PORT from your own computer; deploy.sh does this for you)
#   3. ssh_move_finish  sshd keeps only ADMIN_SSH_PORT and the timer is cancelled
#
# If step 2 never happens (the cloud firewall blocks the new port), the timer puts SSH back on port 22.

SSH_DROPIN=/etc/ssh/sshd_config.d/10-admin.conf
SSH_MAIN=/etc/ssh/sshd_config
SSH_MAIN_BAK=/etc/ssh/sshd_config.hotpot-bak
SSH_REVERT=hotpot-ssh-revert
SSH_PROBATION_MIN=10

ssh_ports() { sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }' | sort -un | paste -sd' ' -; }

restart_sshd() {
  sshd -t || die "the new sshd configuration is invalid; nothing was restarted"
  systemctl daemon-reload                     # Ubuntu 24.04: regenerates ssh.socket from the Port lines
  systemctl restart ssh.socket 2>/dev/null || true
  systemctl restart ssh 2>/dev/null || systemctl restart sshd
  sleep 1
}

ssh_listening() { ss -Hltn "( sport = :$1 )" 2>/dev/null | grep -q .; }

# moved: sshd is on the admin port only
ssh_moved() { [ "$(ssh_ports)" = "$ADMIN_SSH_PORT" ]; }
# waiting for confirmation: the revert timer is armed
ssh_in_probation() { systemctl is-active --quiet "$SSH_REVERT.timer"; }

ssh_move_begin() {
  step "Opening admin SSH on port $ADMIN_SSH_PORT (port 22 stays open for now)"
  allow_input_tcp "$ADMIN_SSH_PORT"
  # Port lines add up across files. Keep 22 unless another file already declares it.
  local keep22="Port 22" f
  for f in "$SSH_MAIN" /etc/ssh/sshd_config.d/*.conf; do
    [ "$f" = "$SSH_DROPIN" ] || [ ! -f "$f" ] && continue
    grep -Eq '^\s*Port\s+22\s*$' "$f" && keep22=""
  done
  printf '# HotPot admin SSH (probation: port 22 is closed once the new port is confirmed)\n%s\nPort %s\n' \
    "$keep22" "$ADMIN_SSH_PORT" | grep -v '^$' > "$SSH_DROPIN"
  restart_sshd
  if ! ssh_listening "$ADMIN_SSH_PORT" || ! ssh_listening 22; then
    ssh_revert_now
    die "sshd did not come up on both 22 and $ADMIN_SSH_PORT; the change was undone"
  fi

  systemctl stop "$SSH_REVERT.timer" 2>/dev/null || true
  systemctl reset-failed "$SSH_REVERT.service" 2>/dev/null || true
  systemd-run --quiet --unit="$SSH_REVERT" --on-active="${SSH_PROBATION_MIN}min" --timer-property=AccuracySec=5s \
    --description="HotPot: undo the admin SSH move if it was never confirmed" \
    /bin/sh -c "rm -f '$SSH_DROPIN'; [ -f '$SSH_MAIN_BAK' ] && mv -f '$SSH_MAIN_BAK' '$SSH_MAIN';
                systemctl daemon-reload; systemctl restart ssh.socket 2>/dev/null; systemctl restart ssh 2>/dev/null || systemctl restart sshd"
}

ssh_move_finish() {
  [ -f "$SSH_DROPIN" ] || die "admin SSH is not being moved (no $SSH_DROPIN); run the installer without --confirm-ssh first"
  step "Closing port 22 for admin SSH; it stays on $ADMIN_SSH_PORT"
  printf '# HotPot admin SSH; port 22 belongs to the Cowrie honeypot\nPort %s\n' "$ADMIN_SSH_PORT" > "$SSH_DROPIN"
  # a "Port 22" line elsewhere would keep sshd on 22 and block Cowrie: comment it out (backup kept)
  if grep -Eq '^\s*Port\s' "$SSH_MAIN"; then
    [ -f "$SSH_MAIN_BAK" ] || cp -p "$SSH_MAIN" "$SSH_MAIN_BAK"
    sed -i -E 's/^(\s*Port\s.*)$/# \1    # disabled by HotPot, see 10-admin.conf/' "$SSH_MAIN"
  fi
  restart_sshd
  ssh_moved || die "sshd still listens on: $(ssh_ports). Remove other Port lines under /etc/ssh/ and re-run;
       the old setup comes back by itself within $SSH_PROBATION_MIN minutes if you do nothing"
  ssh_listening "$ADMIN_SSH_PORT" || die "sshd is not listening on $ADMIN_SSH_PORT"
  systemctl stop "$SSH_REVERT.timer" 2>/dev/null || true
  rm -f "$SSH_MAIN_BAK"
}

ssh_revert_now() {
  systemctl stop "$SSH_REVERT.timer" 2>/dev/null || true
  rm -f "$SSH_DROPIN"
  [ -f "$SSH_MAIN_BAK" ] && mv -f "$SSH_MAIN_BAK" "$SSH_MAIN"
  restart_sshd
}
