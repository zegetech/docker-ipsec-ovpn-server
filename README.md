# VPN Docker Container
Implements 
1. Libreswan IPsec L2tp and Xauth server
2. Libreswan IPsec Payment gateway client
3. OpenVPN Server

The image sets up the following on debian stretch docker image
1. [IPsec VPN](https://github.com/hwdsl2/docker-ipsec-vpn-server) (IPsec/L2TP and Cisco IPsec) 
2. [OpenVPN](https://www.github.com/adamwalach/docker-openvpn) server

## Adaptation
The image is adapted from 
1. https://www.github.com/adamwalach/docker-openvpn
2. https://github.com/hwdsl2/docker-ipsec-vpn-server/blob/master/Dockerfile

## Dockerhub image
 https://hub.docker.com/r/kgathi2/ipsec-ovpn-server

## Requirements to run
1. docker-compose.yaml
2. vpn.env file for environmental variables

## Open VPN Certificates
### Generating Open VPN client certificates
You may generate client certificates by running the following in the container
```bash
CLIENT_CERT=vpn-client-01

# Build the client certificate
easyrsa build-client-full $CLIENT_CERT nopass

# Get a combined certificate printed on stdout
ovpn_getclient $CLIENT_CERT combined

# Get a combined certificate saved on the server
ovpn_getclient $CLIENT_CERT combined-save

# Get a combined certificate saved on the server
ovpn_getclient $CLIENT_CERT separated
```
### Specify Static IP for client (optional)
Specify a static ip for a client
```bash
# Specify Static IP for OVPN clients
CLIENT_CERT=vpn-client-01
CLIENT_STATIC_IP=173.12.2.90
cat > ${OPENVPN}/ccd/${CLIENT_CERT} <<EOF
ifconfig-push $CLIENT_STATIC_IP $OVPN_CONF_IFCONFIG_INET
EOF
```

### Retrieve client certificate from docker container or Kubernetes pod
On your docker/kubectl localhost, copy the files if selected separated or combined-save
```bash
kubectl cp <some-namespace>/<some-pod>:/etc/openvpn/clients/vpn-client-01 /tmp/clients/vpn-client-01

docker cp <container>:/etc/openvpn/clients/vpn-client-01 /tmp/clients/vpn-client-01
```

## IPsec client connectivity troubleshooting
Some links useful in troubleshooting IPsec client conectivity 
- [Host to host Libreswan](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/sec-Host-To-Host_VPN_Using_Libreswan#Verify_Host-To-Host_VPN_Using_Libreswan)

- [Site to Site Libreswan](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/site-to-site_vpn_using_libreswan)

- [Troubleshooting IPsec](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/ipsec-troubleshooting.html)

- [IPsec config options](https://libreswan.org/man/ipsec.conf.5.html)

For Further troubleshooting please see [original repos](#adaptation). Also for configuring aditional Lt2pD or CISCO Xauth client users [here](https://github.com/hwdsl2/docker-ipsec-vpn-server#how-to-use-this-image)

## Note on Peer IP SNATing
When connecting the IPsec client, the IPSEC peer IP has to expect a static IP address from your pod/host. Kubernetes pods SNAT the IP of the node that they are spawned in. So in order to have all your cluster pods have one static IP, the pods need to be behind a NAT gateway that will SNAT all pods traffic within the cluster. 