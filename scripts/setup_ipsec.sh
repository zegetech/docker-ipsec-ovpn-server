#!/bin/sh
#
# Docker script to configure and start an IPsec VPN server
#
# DO NOT RUN THIS SCRIPT ON YOUR PC OR MAC! THIS IS ONLY MEANT TO BE RUN
# IN A DOCKER CONTAINER!
#
# This file is part of IPsec VPN Docker image, available at:
# https://github.com/hwdsl2/docker-ipsec-vpn-server
#
# Copyright (C) 2019 Kariuki Gathitu <kgathi2@gmail.com>
# Based on the work of Lin Song (Copyright 2016-2019) 
# and Thomas Sarlandie (Copyright 2012)
#
# This work is licensed under the Creative Commons Attribution-ShareAlike 3.0
# Unported License: http://creativecommons.org/licenses/by-sa/3.0/
#
# Attribution required: please include my name in any derivative and let me
# know how you have improved it!
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

exiterr()  { echo "Error: $1" >&2; exit 1; }
nospaces() { printf '%s' "$1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }
onespace() { printf '%s' "$1" | tr -s ' '; }
noquotes() { printf '%s' "$1" | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"; }
noquotes2() { printf '%s' "$1" | sed -e 's/" "/ /g' -e "s/' '/ /g"; }

check_ip() {
  IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

if [ ! -f "/.dockerenv" ]; then
  exiterr "This script ONLY runs in a Docker container."
fi

if ip link add dummy0 type dummy 2>&1 | grep -q "not permitted"; then
cat 1>&2 <<'EOF'
Error: This Docker image must be run in privileged mode.

For detailed instructions, please visit:
https://github.com/hwdsl2/docker-ipsec-vpn-server

EOF
  exit 1
fi
ip link delete dummy0 >/dev/null 2>&1

mkdir -p /opt/src
vpn_env="/opt/src/vpn.env"
vpn_gen_env="/opt/src/vpn-gen.env"
if [ -z "$VPN_IPSEC_PSK" ] && [ -z "$VPN_USER" ] && [ -z "$VPN_PASSWORD" ]; then
  if [ -f "$vpn_env" ]; then
    echo
    echo 'Retrieving VPN credentials...'
    . "$vpn_env"
  elif [ -f "$vpn_gen_env" ]; then
    echo
    echo 'Retrieving previously generated VPN credentials...'
    . "$vpn_gen_env"
  else
    echo
    echo 'VPN credentials not set by user. Generating random PSK and password...'
    VPN_IPSEC_PSK=$(LC_CTYPE=C tr -dc 'A-HJ-NPR-Za-km-z2-9' < /dev/urandom | head -c 20)
    VPN_USER=vpnuser
    VPN_PASSWORD=$(LC_CTYPE=C tr -dc 'A-HJ-NPR-Za-km-z2-9' < /dev/urandom | head -c 16)

    printf '%s\n' "VPN_IPSEC_PSK='$VPN_IPSEC_PSK'" > "$vpn_gen_env"
    printf '%s\n' "VPN_USER='$VPN_USER'" >> "$vpn_gen_env"
    printf '%s\n' "VPN_PASSWORD='$VPN_PASSWORD'" >> "$vpn_gen_env"
    chmod 600 "$vpn_gen_env"
  fi
fi

# Remove whitespace and quotes around VPN variables, if any
VPN_IPSEC_PSK=$(nospaces "$VPN_IPSEC_PSK")
VPN_IPSEC_PSK=$(noquotes "$VPN_IPSEC_PSK")
VPN_USER=$(nospaces "$VPN_USER")
VPN_USER=$(noquotes "$VPN_USER")
VPN_PASSWORD=$(nospaces "$VPN_PASSWORD")
VPN_PASSWORD=$(noquotes "$VPN_PASSWORD")

if [ -n "$VPN_ADDL_USERS" ] && [ -n "$VPN_ADDL_PASSWORDS" ]; then
  VPN_ADDL_USERS=$(nospaces "$VPN_ADDL_USERS")
  VPN_ADDL_USERS=$(noquotes "$VPN_ADDL_USERS")
  VPN_ADDL_USERS=$(onespace "$VPN_ADDL_USERS")
  VPN_ADDL_USERS=$(noquotes2 "$VPN_ADDL_USERS")
  VPN_ADDL_PASSWORDS=$(nospaces "$VPN_ADDL_PASSWORDS")
  VPN_ADDL_PASSWORDS=$(noquotes "$VPN_ADDL_PASSWORDS")
  VPN_ADDL_PASSWORDS=$(onespace "$VPN_ADDL_PASSWORDS")
  VPN_ADDL_PASSWORDS=$(noquotes2 "$VPN_ADDL_PASSWORDS")
else
  VPN_ADDL_USERS=""
  VPN_ADDL_PASSWORDS=""
fi

if [ -z "$VPN_IPSEC_PSK" ] || [ -z "$VPN_USER" ] || [ -z "$VPN_PASSWORD" ]; then
  exiterr "All VPN credentials must be specified. Edit your 'env' file and re-enter them."
fi

if printf '%s' "$VPN_IPSEC_PSK $VPN_USER $VPN_PASSWORD $VPN_ADDL_USERS $VPN_ADDL_PASSWORDS" | LC_ALL=C grep -q '[^ -~]\+'; then
  exiterr "VPN credentials must not contain non-ASCII characters."
fi

case "$VPN_IPSEC_PSK $VPN_USER $VPN_PASSWORD $VPN_ADDL_USERS $VPN_ADDL_PASSWORDS" in
  *[\\\"\']*)
    exiterr "VPN credentials must not contain these special characters: \\ \" '"
    ;;
esac

if printf '%s' "$VPN_USER $VPN_ADDL_USERS" | tr ' ' '\n' | sort | uniq -c | grep -qv '^ *1 '; then
  exiterr "VPN usernames must not contain duplicates."
fi

# Check DNS servers and try to resolve hostnames to IPs
if [ -n "$VPN_DNS_SRV1" ]; then
  VPN_DNS_SRV1=$(nospaces "$VPN_DNS_SRV1")
  VPN_DNS_SRV1=$(noquotes "$VPN_DNS_SRV1")
  check_ip "$VPN_DNS_SRV1" || VPN_DNS_SRV1=$(dig -t A -4 +short "$VPN_DNS_SRV1")
  check_ip "$VPN_DNS_SRV1" || exiterr "Invalid DNS server 'VPN_DNS_SRV1'. Please check your 'env' file."
fi

if [ -n "$VPN_DNS_SRV2" ]; then
  VPN_DNS_SRV2=$(nospaces "$VPN_DNS_SRV2")
  VPN_DNS_SRV2=$(noquotes "$VPN_DNS_SRV2")
  check_ip "$VPN_DNS_SRV2" || VPN_DNS_SRV2=$(dig -t A -4 +short "$VPN_DNS_SRV2")
  check_ip "$VPN_DNS_SRV2" || exiterr "Invalid DNS server 'VPN_DNS_SRV2'. Please check your 'env' file."
fi

echo
echo 'Trying to auto discover IP of this server...'

# In case auto IP discovery fails, manually define the public IP
# of this server in your 'env' file, as variable 'VPN_PUBLIC_IP'.
PUBLIC_IP=${VPN_PUBLIC_IP:-''}

# Try to auto discover IP of this server
[ -z "$PUBLIC_IP" ] && PUBLIC_IP=$(dig @resolver1.opendns.com -t A -4 myip.opendns.com +short)

# Check IP for correct format
check_ip "$PUBLIC_IP" || PUBLIC_IP=$(wget -t 3 -T 15 -qO- http://ipv4.icanhazip.com)
check_ip "$PUBLIC_IP" || exiterr "Cannot detect this server's public IP. Define it in your 'env' file as 'VPN_PUBLIC_IP'."

L2TP_NET=${VPN_L2TP_NET:-'192.168.42.0/24'}
L2TP_LOCAL=${VPN_L2TP_LOCAL:-'192.168.42.1'}
L2TP_POOL=${VPN_L2TP_POOL:-'192.168.42.10-192.168.42.250'}
XAUTH_NET=${VPN_XAUTH_NET:-'192.168.43.0/24'}
XAUTH_POOL=${VPN_XAUTH_POOL:-'192.168.43.10-192.168.43.250'}
DNS_SRV1=${VPN_DNS_SRV1:-'8.8.8.8'}
DNS_SRV2=${VPN_DNS_SRV2:-'8.8.4.4'}
DNS_SRVS="\"$DNS_SRV1 $DNS_SRV2\""
[ -n "$VPN_DNS_SRV1" ] && [ -z "$VPN_DNS_SRV2" ] && DNS_SRVS="$DNS_SRV1"

# MTU=${OVPN_MTU:-$(cat /sys/class/net/eth0/mtu)}

# Create IPsec (Libreswan) config
cat > /etc/ipsec.conf <<EOF
config setup
  virtual-private=%v4:10.0.0.0/8,%v4:192.168.0.0/16,%v4:172.16.0.0/12,%v4:!192.168.42.0/24,%v4:!192.168.43.0/24,%v4:!$PGW_NET:!$OVPN_NET
  protostack=netkey
  interfaces=%defaultroute
  uniqueids=no
  keep-alive=60
  logfile=/var/log/ipsec.log

include /etc/ipsec.d/*.conf
EOF

cat > /etc/ipsec.d/defaults.conf <<EOF
conn shared
  left=%defaultroute
  leftid=$PUBLIC_IP
  right=%any
  encapsulation=yes
  authby=secret
  pfs=no
  rekey=no
  keyingtries=5
  dpddelay=30
  dpdtimeout=120
  dpdaction=clear
  ikev2=never
  ike=aes256-sha2,aes128-sha2,aes256-sha1,aes128-sha1,aes256-sha2;modp1024,aes128-sha1;modp1024
  phase2alg=aes_gcm-null,aes128-sha1,aes256-sha1,aes256-sha2_512,aes128-sha2,aes256-sha2
  sha2-truncbug=yes

conn l2tp-psk
  auto=add
  leftprotoport=17/1701
  rightprotoport=17/%any
  type=transport
  phase2=esp
  also=shared

conn xauth-psk
  auto=add
  leftsubnet=0.0.0.0/0
  rightaddresspool=$XAUTH_POOL
  modecfgdns=$DNS_SRVS
  leftxauthserver=yes
  rightxauthclient=yes
  leftmodecfgserver=yes
  rightmodecfgclient=yes
  modecfgpull=yes
  xauthby=file
  ike-frag=yes
  cisco-unity=yes
  also=shared
EOF

cat > /etc/ipsec.d/${PGW_NAME}.conf <<EOF
conn $PGW_NAME
  type=tunnel
  # Left security gateway, subnet behind it, nexthop toward right.
  left=%defaultroute
  leftsubnets={$OVPN_NET}
  leftnexthop=%defaultroute

  # Right security gateway, subnet behind it, nexthop toward left.
  right=$PGW_IP # Public Remote IP
  rightsubnets={$PGW_RIGHT_SUBNETS}

  # Phase 1
  keyexchange=ike
  ikev2=never
  authby=secret
  ike=3des-sha1;dh2
  # ike=aes_gcm-sha2 # faster algo but not MPESA VPN supported
  # Algorithm: 3DES(168) / Hash: SHA1 / Group: DH 2 (1024)
  ikelifetime=86400s

  # Phase 2
  phase2=esp
  # Algorithm: AES(128) / Hash: SHA1 / Group: DH 2 (1024)
  phase2alg=aes128-sha1;dh2
  # phase2alg=aes_gcm128-null # faster algo but not MPESA VPN supported
  salifetime=43200s

  # MTU should be set on Client to tunnel. 
  # mtu eth0 1460 # G2 1362
  # mtu=$MTU 
  replay-window=0
  pfs=no
  auto=start
  aggrmode=no
  nat-keepalive=yes
  dpddelay=60
  dpdtimeout=120
  dpdaction=hold
  # dpdaction=restart

EOF

if uname -r | grep -qi 'coreos'; then
  sed -i '/phase2alg/s/,aes256-sha2_512//' /etc/ipsec.d/*.conf
fi

# Specify IPsec PSK
cat > /etc/ipsec.d/default.secrets <<EOF
%any  %any  : PSK "$VPN_IPSEC_PSK"
EOF

cat > /etc/ipsec.d/${PGW_NAME}.secrets <<EOF
%any $PGW_IP : PSK "$PGW_PSK"
EOF

# Create xl2tpd config
cat > /etc/xl2tpd/xl2tpd.conf <<EOF
[global]
port = 1701

[lns default]
ip range = $L2TP_POOL
local ip = $L2TP_LOCAL
require chap = yes
refuse pap = yes
require authentication = yes
name = l2tpd
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
EOF

# Set xl2tpd options
cat > /etc/ppp/options.xl2tpd <<EOF
+mschap-v2
ipcp-accept-local
ipcp-accept-remote
noccp
auth
mtu 1280
mru 1280
proxyarp
lcp-echo-failure 4
lcp-echo-interval 30
connect-delay 5000
ms-dns $DNS_SRV1
EOF

if [ -z "$VPN_DNS_SRV1" ] || [ -n "$VPN_DNS_SRV2" ]; then
cat >> /etc/ppp/options.xl2tpd <<EOF
ms-dns $DNS_SRV2
EOF
fi

# Create VPN credentials
cat > /etc/ppp/chap-secrets <<EOF
"$VPN_USER" l2tpd "$VPN_PASSWORD" *
EOF

VPN_PASSWORD_ENC=$(openssl passwd -1 "$VPN_PASSWORD")
cat > /etc/ipsec.d/passwd <<EOF
$VPN_USER:$VPN_PASSWORD_ENC:xauth-psk
EOF

if [ -n "$VPN_ADDL_USERS" ] && [ -n "$VPN_ADDL_PASSWORDS" ]; then
  count=1
  addl_user=$(printf '%s' "$VPN_ADDL_USERS" | cut -d ' ' -f 1)
  addl_password=$(printf '%s' "$VPN_ADDL_PASSWORDS" | cut -d ' ' -f 1)
  while [ -n "$addl_user" ] && [ -n "$addl_password" ]; do
    addl_password_enc=$(openssl passwd -1 "$addl_password")
cat >> /etc/ppp/chap-secrets <<EOF
"$addl_user" l2tpd "$addl_password" *
EOF
cat >> /etc/ipsec.d/passwd <<EOF
$addl_user:$addl_password_enc:xauth-psk
EOF
    count=$((count+1))
    addl_user=$(printf '%s' "$VPN_ADDL_USERS" | cut -s -d ' ' -f "$count")
    addl_password=$(printf '%s' "$VPN_ADDL_PASSWORDS" | cut -s -d ' ' -f "$count")
  done
fi

# Update sysctl settings
SYST='/sbin/sysctl -e -q -w'
if [ "$(getconf LONG_BIT)" = "64" ]; then
  SHM_MAX=68719476736
  SHM_ALL=4294967296
else
  SHM_MAX=4294967295
  SHM_ALL=268435456
fi
$SYST kernel.msgmnb=65536
$SYST kernel.msgmax=65536
$SYST kernel.shmmax=$SHM_MAX
$SYST kernel.shmall=$SHM_ALL
$SYST net.ipv4.ip_forward=1
$SYST net.ipv4.conf.all.accept_source_route=0
$SYST net.ipv4.conf.all.accept_redirects=0
$SYST net.ipv4.conf.all.send_redirects=0
$SYST net.ipv4.conf.all.rp_filter=0
$SYST net.ipv4.conf.default.accept_source_route=0
$SYST net.ipv4.conf.default.accept_redirects=0
$SYST net.ipv4.conf.default.send_redirects=0
$SYST net.ipv4.conf.default.rp_filter=0
$SYST net.ipv4.conf.eth0.send_redirects=0
$SYST net.ipv4.conf.eth0.rp_filter=0
$SYST net.ipv4.conf.lo.rp_filter=0

# Create IPTables rules
# iptables -N LOG_DROP
# iptables -A LOG_DROP -j LOG --log-prefix "iptables denied: "
# iptables -A LOG_DROP -j DROP
# iptables -N LOG_ACCEPT
# iptables -A ACCEPT -j LOG --log-prefix "iptables accepted: "
# iptables -A ACCEPT -j ACCEPT

# Speed Boost: Don't track UDP as well as traffic between OVPN and PGW
iptables -t raw -I PREROUTING -p udp -m multiport --dports 500,4500,1194 -j NOTRACK
iptables -t raw -I PREROUTING -s "$OVPN_NET" -d "$PGW_NET"  -j NOTRACK
iptables -t raw -I PREROUTING -s "$PGW_NET" -d "$OVPN_NET"  -j NOTRACK

iptables -A INPUT -p udp -m multiport --dports 500,4500,1194 -j ACCEPT
iptables -A INPUT -p udp --dport 1701 -m policy --dir in --pol none -j DROP
iptables -A INPUT -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT
iptables -A INPUT -p udp --dport 1701 -j DROP
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# When MTU is properly set in PGW tunnel and vpnclient config, this is not needed
# iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS  --clamp-mss-to-pmtu
iptables -A FORWARD -s "$OVPN_NET" -d "$PGW_NET" -j ACCEPT
iptables -A FORWARD -s "$PGW_NET" -d "$OVPN_NET" -j ACCEPT
iptables -A FORWARD -s "$OVPN_NET" -d "$OVPN_NET" -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP
# When conntrack is tracking tun traffic, this will be relevant
# iptables -A FORWARD -i tun+ -o eth+ -j ACCEPT
# iptables -A FORWARD -i eth+ -o tun+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -p tcp -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -i ppp+ -o eth+ -j ACCEPT
iptables -A FORWARD -i eth+ -o ppp+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -s "$XAUTH_NET" -o eth+ -j ACCEPT
iptables -A FORWARD -i eth+ -d "$XAUTH_NET" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i ppp+ -o ppp+ -s "$L2TP_NET" -d "$L2TP_NET" -j ACCEPT
# Uncomment if you wish to disallow traffic between VPN clients themselves
# iptables -A FORWARD -i ppp+ -o ppp+ -s "$L2TP_NET" -d "$L2TP_NET" -j DROP
# iptables -A FORWARD -s "$XAUTH_NET" -d "$XAUTH_NET" -j DROP
iptables -A FORWARD -j DROP

iptables -t nat -I POSTROUTING -s "$XAUTH_NET" -o eth+ -m policy --dir out --pol none -j MASQUERADE
iptables -t nat -I POSTROUTING -s "$L2TP_NET" -o eth+ -j MASQUERADE

# Update file attributes
chmod 600 /etc/ipsec.d/*.secrets /etc/ppp/chap-secrets /etc/ipsec.d/passwd

cat <<EOF

================================================

IPsec VPN server is now ready for use!

Connect to your new VPN with these details:

Server IP: $PUBLIC_IP
IPsec PSK: $VPN_IPSEC_PSK
Username: $VPN_USER
Password: $VPN_PASSWORD
EOF

if [ -n "$VPN_ADDL_USERS" ] && [ -n "$VPN_ADDL_PASSWORDS" ]; then
  count=1
  addl_user=$(printf '%s' "$VPN_ADDL_USERS" | cut -d ' ' -f 1)
  addl_password=$(printf '%s' "$VPN_ADDL_PASSWORDS" | cut -d ' ' -f 1)
cat <<'EOF'

Additional VPN users (username | password):
EOF
  while [ -n "$addl_user" ] && [ -n "$addl_password" ]; do
cat <<EOF
$addl_user | $addl_password
EOF
    count=$((count+1))
    addl_user=$(printf '%s' "$VPN_ADDL_USERS" | cut -s -d ' ' -f "$count")
    addl_password=$(printf '%s' "$VPN_ADDL_PASSWORDS" | cut -s -d ' ' -f "$count")
  done
fi

cat <<'EOF'

Write these down. You'll need them to connect!

Important notes:   https://git.io/vpnnotes2
Setup VPN clients: https://git.io/vpnclients

================================================

EOF