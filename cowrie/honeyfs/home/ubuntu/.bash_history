sudo apt update && sudo apt upgrade -y
sudo apt install -y nginx php8.3-fpm php8.3-mysql php8.3-xml php8.3-mbstring unzip git mysql-client
sudo mkdir -p /var/www/northbridge && sudo chown deploy:www-data /var/www/northbridge
sudo -u deploy git clone git@gitlab.northbridge.local:it/intranet.git /var/www/northbridge
sudo nano /etc/nginx/sites-available/northbridge
sudo ln -s /etc/nginx/sites-available/northbridge /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
cd /var/www/northbridge
cp .env.example .env
nano .env
php artisan key:generate
php artisan migrate --force
mysql -h db01 -u nb_app -p nb_intranet
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.1:8b
ollama pull qwen2.5-coder:7b
sudo systemctl edit ollama
sudo systemctl restart ollama
curl localhost:11434/api/tags
crontab -l
sudo crontab -e
ls -la /var/backups/nb/
df -h
htop
exit
sudo nb-healthcheck
sudo cat /etc/nb/monitor.env
less /root/RUNBOOK.md
