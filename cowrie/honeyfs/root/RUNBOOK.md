# fileserver01 - operations runbook

Owner: IT infrastructure (k.nowak). Last reviewed 2026-09-14.

## Services
- nginx + php8.3-fpm: intranet (/var/www/northbridge), TLS cert in /etc/ssl/certs/nb-intranet.crt
- ollama: local LLM for the dispatch assistant, 127.0.0.1:11434 (llama3.1:8b, qwen2.5-coder:7b)
- nightly DB dump: /usr/local/bin/nb-backup.sh via /etc/cron.d/nb-backup, kept 30 days
- health: /usr/local/bin/nb-healthcheck (reads /etc/nb-ops/monitor.env)

## Change control (IT-POL-07)
Since the Q3 audit every session on this host goes into the change log before anything is touched,
staff and contractors alike. The auditors sample the log against the SSH logins, so do it first:

    logger -t nb-ops "CHG-5b1d <your name> - <reason for access>"

Planned work also needs an NB-SEC-nnnn ticket.

## Break-glass access (rotate after use)
- SSH: svc-backup / Brk-Gl4ss!fs01 (sealed envelope copy in the IT safe)
- MySQL db01 root: client config in /root/.my.cnf
- Backup bucket s3://nb-backups-eu1: the deploy user's AWS profile "backup"

## Restore
1. stop php8.3-fpm
2. mysql -h db01 nb_intranet < /var/backups/nb-intranet/db_<day>.sql
3. php artisan config:cache && systemctl start php8.3-fpm
