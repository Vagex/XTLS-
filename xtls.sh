#!/bin/bash

echo "#===================================================="
echo "#	System Request:Debian 9+/Ubuntu 18.04+"
echo "#	Author:	Alibama"
echo "#	Dscription: Xray Vless-gRPC Vless-tcp-xtls Trojan-tcp onekey Management"
echo "#	Version: 1.0"
echo "#	email:admin@examples.com"
echo "#	Official document: www.xray.com"
echo "#===================================================="

read -rp "请输入你的域名信息(eg:www.examples.com):" domain
read -rp "请输入你的Trojan密码(eg:Adeja285):" password
read -rp "请输入你的Trojan端口(eg:1234):" tPORT
read -rp "请输入你的Xray-ID(eg:$(uuidgen)):" uuid_init
[[ -z "$uuid_init" ]] && uuid_init=$(uuidgen)


#系统更新安装包并升级
apt update && apt upgrade -y
# 安装所需要的软件
apt install curl jq lsof cron
apt purge nginx 
#安装防火墙ufw
apt install ufw
echo y|ufw enable
ufw allow 80/tcp
ufw allow 80/udp
ufw allow 443/tcp
ufw allow 443/udp
ufw allow 22/tcp
ufw allow ${tPORT}/udp
ufw allow ${tPORT}/tcp


# Firewall reload
yes |ufw reload

#检测网络环境
#1、检测ipv4
curl -s ip.sb --ipv4 --max-time 8
rm -rf /etc/localtime
ln -s  -rf /usr/share/zoneinfo/Asia/Hong_Kong /etc/localtime
date

#下载Caddy Latest版本代码
CaddyVersion=$(wget -qO- -t1 -T2 "https://api.github.com/repos/caddyserver/caddy/releases/latest" | jq -r '.tag_name')

rm -rf  /tmp/caddy.tar.gz
rm -rf /etc/caddy
rm -rf /usr/share/caddy
cd /tmp/

wget -O caddy.tar.gz https://github.com/caddyserver/caddy/releases/download/${CaddyVersion}/caddy_${CaddyVersion:1}_linux_amd64.tar.gz

mkdir /etc/caddy
tar -zxvf caddy.tar.gz -C  /etc/caddy
cp -rf /etc/caddy/caddy /usr/bin

# Caddy服务器配置
cat <<EOF >/etc/caddy/Caddyfile
${domain}:80 {
    root * /usr/share/caddy
    file_server
}
EOF

#配置Caddy.service
cat <<EOF >/etc/systemd/system/caddy.service
[Unit]
Description=Caddy
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
#User=caddy
#Group=caddy
User=root
Group=root
ExecStart=/usr/bin/caddy run --environ --config /etc/caddy/Caddyfile
ExecReload=/usr/bin/caddy reload --config /etc/caddy/Caddyfile
TimeoutStopSec=5s
#LimitNOFILE=1048576
#LimitNPROC=512
PrivateTmp=true
ProtectSystem=full
#AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable caddy
systemctl restart caddy

mkdir /usr/share/caddy
chmod 755 /usr/share/caddy

# 安装Xray-Core
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
#设置xray 权限
sed -i 's/User=nobody/User=root/g' /etc/systemd/system/xray.service
sed -i 's/CapabilityBoundingSet=/#CapabilityBoundingSet=/g' /etc/systemd/system/xray.service
sed -i 's/AmbientCapabilities=/#AmbientCapabilites=/g' /etc/systemd/system/xray.service
systemctl daemon-reload
#安装TLS证书
#1、安装Acme
apt install socat -y
apt install -y automake autoconf libtool
curl https://get.acme.sh yes |sh
alias acme.sh=/root/.acme.sh/acme.sh

#2、申请证书
#read -rp "请输入你的域名信息(eg:www.examples.com):" domain
~/.acme.sh/acme.sh --force --debug --issue  --standalone -d ${domain} --pre-hook "systemctl stop caddy" --post-hook "systemctl restart caddy" --server letsencrypt

#3、安装TLS证书
mkdir  -p /usr/local/etc/xray/ssl
~/.acme.sh/acme.sh --installcert -d ${domain} --certpath /usr/local/etc/xray/ssl/xray_ssl.crt --keypath /usr/local/etc/xray/ssl/xray_ssl.key --capath /usr/local/etc/xray/ssl/xray_ssl.crt
chmod 755 /usr/local/etc/xray/ssl

#配置Xray-Core
cat <<EOF >/usr/local/etc/xray/config.json
{
  "log": {
    "access": "none",
    "loglevel": "none"
  },
  "dns": {},
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "ip": [
          "geoip:private"
        ],
        "outboundTag": "block"
      }
    ]
  },
  "policy": {},
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid_init}",
            "flow": "xtls-rprx-direct"
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "dest": 1310,
            "xver": 1
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "xtls",
        "xtlsSettings": {
          "allowInsecure": false,
          "minVersion": "1.2",
          "alpn": [
            "http/1.1"
          ],
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/xray/ssl/xray_ssl.crt",
              "keyFile": "/usr/local/etc/xray/ssl/xray_ssl.key"
            }
          ]
        }
      }
    },
    {
      "port": 1310,
      "listen": "127.0.0.1",
      "protocol": "trojan",
      "settings": {
        "clients": [
          {
            "password": "${password}"
          }
        ],
        "fallbacks": [
          {
            "dest": 80
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "none",
        "tcpSettings": {
          "acceptProxyProtocol": true
        }
      }
    },
    {
      "port": ${tPORT},
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid_init}"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "gun",
        "security": "tls",
        "tlsSettings": {
          "serverName": "${domain}",
          "alpn": [
            "h2"
          ],
          "certificates": [
            {
              "certificateFile": "/usr/local/etc/xray/ssl/xray_ssl.crt",
              "keyFile": "/usr/local/etc/xray/ssl/xray_ssl.key"
            }
          ]
        },
        "grpcSettings": {
          "serviceName": "/7GB14QT"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    },
    {
      "protocol": "blackhole",
      "tag": "block"
    }
  ],
  "transport": {},
  "stats": {},
  "reverse": {}
}
EOF


#重启系统
systemctl restart caddy
systemctl restart xray

echo “安装完成..............“
echo "Trojan Tcp 二维码"
qrencode -o /home/tj.png -t trojan://${password}@${domain}:443?security=tls&headerType=none&type=tcp#Trojan-tcp
echo "trojan://${password}@${domain}:443?security=tls&headerType=none&type=tcp#Trojan-tcp" | qrencode -s 10 -m 1 -t UTF8

echo "Vless Tcp XTLS 二维码"
qrencode -o /home/vtxtls.png vless://${uuid_init}@${domain}:443?security=xtls&encryption=none&headerType=none&type=tcp&flow=xtls-rprx-direct#Vless-tcp-xtls
echo "vless://${uuid_init}@${domain}:443?security=xtls&encryption=none&headerType=none&type=tcp&flow=xtls-rprx-direct#Vless-tcp-xtls" | qrencode -s 10 -m 1 -t UTF8

echo "Vless gRPC 二维码"
echo "vless://${uuid_init}@${domain}:${tPORT}?mode=gun&security=tls&encryption=none&headerType=grpc&serviceName=/7GB14QT#Vless-gRPC" | qrencode -s 10 -m 1 -t UTF8

