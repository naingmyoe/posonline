၂။ လိုအပ်သော Software များ Install လုပ်ပါ
Bash
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx postgresql postgresql-contrib nodejs npm ufw
sudo npm install -g pm2
Firewall ဖွင့်ပေးပါ (80, 443, 22) -
Bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
၃။ Project ဖိုင်များနှင့် Database ပြင်ဆင်ပါ
VPS ပေါ်တွင် Folder တစ်ခု (ဥပမာ /var/www/unpos) ထဲသို့ server.js, package.json, admin.html, index.html, .env တို့ကို တင်ပြီး downloads folder ထဲသို့ Build ထုတ်ထားသော APK ကို UN-Mobile-POS.apk အမည်ဖြင့် ထည့်ပါ -
Bash
mkdir -p /var/www/unpos/downloads
cd /var/www/unpos
npm install
PostgreSQL Database ဖန်တီးပါ -
Bash
sudo -u postgres psql -c "CREATE DATABASE un_pos_db;"
sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD 'YOUR_STRONG_PASSWORD';"
.env ဖိုင်ထဲတွင် ထည့်ပါ -
Env
PORT=8081
DATABASE_URL=postgres://postgres:YOUR_STRONG_PASSWORD@127.0.0.1:5432/un_pos_db
PM2 ဖြင့် Backend Server ကို Run ထားပါ -
Bash
pm2 start server.js --name "un-pos-server"
pm2 save
pm2 startup
၄။ Nginx Virtual Host Config ရေးပါ (Domain ၃ ခုလုံး + SSL Challenge အတွက်)
Bash
sudo nano /etc/nginx/sites-available/unmobileposmm.top
အောက်ပါ Config ကို ကူးထည့်သိမ်းပါ -
Nginx
# 1. APK Download Landing Page (https://unmobileposmm.top)
server {
    listen 80;
    listen [::]:80;
    server_name unmobileposmm.top www.unmobileposmm.top;

    root /var/www/unpos;
    index index.html;

    location ^~ /.well-known/acme-challenge/ {
        allow all;
        root /var/www/unpos;
    }

    location /downloads/ {
        alias /var/www/unpos/downloads/;
        default_type application/vnd.android.package-archive;
        add_header Content-Disposition 'attachment; filename="UN-Mobile-POS.apk"';
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}

# 2. Backend API Server (https://api.unmobileposmm.top)
server {
    listen 80;
    listen [::]:80;
    server_name api.unmobileposmm.top;

    client_max_body_size 64M;

    location ^~ /.well-known/acme-challenge/ {
        allow all;
        root /var/www/unpos;
    }

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;
    }
}

# 3. Web Admin Panel (https://admin.unmobileposmm.top)
server {
    listen 80;
    listen [::]:80;
    server_name admin.unmobileposmm.top;

    client_max_body_size 64M;

    location ^~ /.well-known/acme-challenge/ {
        allow all;
        root /var/www/unpos;
    }

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
    }
}
Nginx Config ကို Enable လုပ်ပြီး Reload လုပ်ပါ -
Bash
sudo ln -sf /etc/nginx/sites-available/unmobileposmm.top /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx
၅။ Let's Encrypt SSL (HTTPS) တပ်ဆင်ပါ
Bash
sudo certbot --nginx -d unmobileposmm.top -d www.unmobileposmm.top -d api.unmobileposmm.top -d admin.unmobileposmm.top
(မေးလာလျှင် Email ထည့်ပါ၊ Terms Y ပေးပါ၊ Redirect HTTPS 2 ကို ရွေးပါ။)
SSL Auto-Renew စစ်ဆေးပါ -
Bash
sudo certbot renew --dry-run
