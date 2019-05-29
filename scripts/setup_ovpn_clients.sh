#!/bin/bash
# Specify Static IP for OVPN clients
cat > ${OPENVPN}/ccd/${OVPN_INTEGRATOR_NAME} <<EOF
ifconfig-push $OVPN_INTEGRATOR_STATIC_IP $OVPN_CONF_IFCONFIG_INET
EOF


easyrsa build-client-full vpn-client-01 nopass
ovpn_getclient vpn-client-01 combined
ovpn_getclient vpn-client-01 combined-save
ovpn_getclient vpn-client-01 separated

https://medium.com/@nnilesh7756/copy-directories-and-files-to-and-from-kubernetes-container-pod-19612fa74660
copy config

kubectl cp <some-namespace>/<some-pod>:/etc/openvpn/clients/vpn-client-01 /tmp/clients/vpn-client-01

