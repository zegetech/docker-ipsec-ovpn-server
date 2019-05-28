#!/bin/bash
# Setup
echo "Setting Up Easy RSA"
/opt/src/scripts/setup_easyrsa.sh

echo "Setting Up OpenVPN"
/opt/src/scripts/setup_ovpn.sh

echo "Setting Up IPsec"
/opt/src/scripts/setup_ipsec.sh

# Start services
openvpn --config $OPENVPN/server.conf --daemon
echo "Starting the OpenVPN"


mkdir -p /run/pluto /var/run/pluto /var/run/xl2tpd
rm -f /run/pluto/pluto.pid /var/run/pluto/pluto.pid /var/run/xl2tpd.pid

echo "Starting the OpenVPN, Libreswan (IPSEC) and XL2TPD"
/usr/local/sbin/ipsec start
exec /usr/sbin/xl2tpd -D -c /etc/xl2tpd/xl2tpd.conf