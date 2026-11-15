systemctl status nginx php8.3-fpm
journalctl -u php8.3-fpm --since yesterday | tail -n 40
df -h
du -sh /var/backups/nb-intranet
ls -la /var/backups/nb-intranet/ | tail
logger -t nb-ops "CHG-0412 k.nowak - cert renewal intranet"
openssl x509 -in /etc/ssl/certs/nb-intranet.crt -noout -dates
systemctl reload nginx
tail -f /var/log/nginx/error.log
vi /etc/nginx/sites-available/northbridge
nginx -t && systemctl reload nginx
apt update
apt list --upgradable | wc -l
apt upgrade -y
needrestart -r l
cat /etc/cron.d/nb-backup
/usr/local/bin/nb-backup.sh
tail /var/log/nb-backup.log
mysql -e "show processlist"
mysql nb_intranet -e "select count(*) from shipments"
logger -t nb-ops "CHG-0437 k.nowak - disk cleanup, backup retention"
find /var/backups/nb-intranet -name 'db_*.sql' -mtime +30 | wc -l
vi /usr/local/bin/nb-backup.sh
free -m
systemctl status ollama
journalctl -u ollama -n 30
ss -tlnp
last -n 20
grep "Failed password" /var/log/auth.log | wc -l
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head
ufw status
nb-healthcheck
vi /etc/nb-ops/monitor.env
nb-healthcheck
passwd svc-backup
vi /root/RUNBOOK.md
logger -t nb-ops "CHG-0458 k.nowak - runbook update after audit"
tail -n 50 /var/www/northbridge/storage/logs/laravel.log
sudo -u deploy aws --profile backup s3 ls s3://nb-backups-eu1/ | tail -n 3
systemctl status nginx php8.3-fpm ollama
uptime
exit
