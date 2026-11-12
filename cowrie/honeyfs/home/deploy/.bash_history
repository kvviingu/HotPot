cd /var/www/northbridge
git pull origin main
composer install --no-dev
php artisan migrate --force
php artisan config:cache
exit
