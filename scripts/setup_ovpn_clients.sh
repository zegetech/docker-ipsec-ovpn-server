#!/bin/bash
# Specify Static IP for OVPN clients
cat > ${OPENVPN}/ccd/${OVPN_INTEGRATOR_NAME} <<EOF
ifconfig-push $OVPN_INTEGRATOR_STATIC_IP $OVPN_SERVER_GATEWAY_IP
EOF


easyrsa build-client-full vpn-client-01 nopass