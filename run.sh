#!/bin/bash
# Setup
echo "Docker Image version refreshed at $REFRESHED_AT"
echo "Setting Up Easy RSA $EASYRSA_VER"
/opt/src/scripts/setup_easyrsa.sh

echo "Setting Up OpenVPN"
/opt/src/scripts/setup_ovpn.sh

echo "Setting Up Libreswan $SWAN_VER and L2TP $L2TP_VER"
/opt/src/scripts/setup_ipsec.sh

# Start services
mkdir -p /run/pluto /var/run/pluto /var/run/xl2tpd
rm -f /run/pluto/pluto.pid /var/run/pluto/pluto.pid /var/run/xl2tpd.pid

echo "Starting Libreswan (IPSEC) and XL2TPD"
/usr/local/sbin/ipsec start
/usr/sbin/xl2tpd -c /etc/xl2tpd/xl2tpd.conf

echo "Starting the OpenVPN"
exec openvpn --config $OPENVPN/server.conf #--daemon