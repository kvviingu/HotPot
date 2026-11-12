#!/bin/bash
# Dump the intranet database to /var/backups/nb (served under /admin/backups/)
set -e
DAY=$(date +%F)
mysqldump -h 10.0.0.21 -u nb_backup -p'Nb-Backup!2024' nb_intranet > /var/backups/nb/db_${DAY}.sql
find /var/backups/nb -name 'db_*.sql' -mtime +30 -delete
