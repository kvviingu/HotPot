cd /var/www/northbridge
git status
git pull origin main
composer install --no-dev
php artisan migrate --force
php artisan config:cache
php artisan queue:restart
tail -n 30 storage/logs/laravel.log
exit
cd /var/www/northbridge
git log --oneline -5
git pull origin main
composer install --no-dev --optimize-autoloader
php artisan migrate --force
php artisan view:clear && php artisan config:cache
curl -sk https://localhost/ -o /dev/null -w "%{http_code}\n"
exit
aws --profile backup s3 ls s3://nb-backups-eu1/
aws --profile backup s3 cp /var/backups/nb-intranet/db_2026-10-31.sql s3://nb-backups-eu1/monthly/
cd /var/www/northbridge
git stash
git pull origin main
git stash pop
vi .env
php artisan config:cache
php artisan tinker
exit
