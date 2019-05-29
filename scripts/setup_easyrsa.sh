#!/bin/bash

# https://github.com/OpenVPN/easy-rsa/blob/v3.0.6/README.quickstart.md
if [ ! -d "$EASYRSA_PKI" ]; then
# Create /etc/openvpn/pki
easyrsa init-pki

# Create /etc/openvpn/pki/ca.crt
easyrsa --batch build-ca nopass

# Create /etc/openvpn/pki/dh.pem
easyrsa gen-dh

# Create /etc/openvpn/pki/crl.pem
easyrsa gen-crl

# Create /etc/openvpn/pki/ta.key
openvpn --genkey --secret $EASYRSA_PKI/ta.key

# Create /etc/openvpn/pki/issued/server.crt
# Create /etc/openvpn/pki/private/server.key
easyrsa build-server-full server nopass
fi