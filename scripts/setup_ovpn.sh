#!/bin/bash
# Make the Client Config Directory
mkdir -p $OPENVPN/ccd

conf=${OPENVPN:-}/server.conf
if [ -f "$conf" ]; then
    bak=$conf.$(date +%s).bak
    echo "Backing up $conf -> $bak"
    mv "$conf" "$bak"
fi

cat > "$conf" <<EOF
# Secure OpenVPN Server Config

# Basic Connection Config
dev tun0
proto udp
port 1194
keepalive 10 60
max-clients 8

# Certs
ca $EASYRSA_PKI/ca.crt
cert $EASYRSA_PKI/issued/server.crt
key $EASYRSA_PKI/private/server.key
dh $EASYRSA_PKI/dh.pem
tls-auth $EASYRSA_PKI/ta.key 0

# Ciphers and Hardening
reneg-sec 0
remote-cert-tls client
crl-verify $EASYRSA_PKI/crl.pem
tls-version-min 1.2
cipher AES-256-CBC
auth SHA512
tls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-256-CBC-SHA256:TLS-DHE-RSA-WITH-AES-128-GCM-SHA256:TLS-DHE-RSA-WITH-AES-128-CBC-SHA256

# Drop Privs
user nobody
group nogroup

# IP pool
# server ${OVPN_SERVER_GATEWAY_IP} ${OVPN_CONF_SUBNET}
mode server
tls-server
ifconfig ${OVPN_CONF_IFCONFIG_INET} ${OVPN_CONF_IFCONFIG_DEST}
ifconfig-pool ${OVPN_CONF_IFCONFIG_POOL_START} ${OVPN_CONF_IFCONFIG_POOL_END}
ifconfig-pool-persist $EASYRSA_PKI/index.txt
client-config-dir $OPENVPN/ccd

# Server routes
route ${OVPN_CONF_ROUTE} ${OVPN_CONF_SUBNET}
route ${OVPN_CONF_LAN_ROUTE_IP} ${OVPN_CONF_SUBNET}

# Client routes DHCP Push options 
# push "redirect-gateway def1 bypass-dhcp" # force all traffic through VPN
push block-outside-dns
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "route ${OVPN_CONF_ROUTE} ${OVPN_CONF_SUBNET}"
push "route ${OVPN_CONF_PGW_ROUTE} ${OVPN_CONF_SUBNET}"

# Logging
log-append /var/log/openvpn.log
status /tmp/openvpn-status.log
verb 3
mute 10

# Misc
persist-key
persist-tun
comp-lzo
EOF

# Clean-up duplicate configs
if diff -q "${bak:-}" "$conf" 2>/dev/null; then
    echo "Removing duplicate back-up: $bak"
    rm -fv "$bak"
fi

echo "Successfully generated config"