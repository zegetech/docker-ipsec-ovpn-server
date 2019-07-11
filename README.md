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

## Issue faced
Disabling rf_filter for ipsec. To check configs do
```bash
sysctl -a | grep \\.ip_forward
sysctl -a | grep \\.rp_filter

# If the flag is wrong use similar to this
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf

```
Forwarding traffic between subnets. OVPN_NET <> PGW_NET
Added the following in iptables file
```bash
iptables -I FORWARD 7 -s "$OVPN_NET" -d "$PGW_NET" -j ACCEPT
iptables -I FORWARD 8 -s "$PGW_NET" -d "$OVPN_NET" -j ACCEPT
iptables -t nat -I POSTROUTING -s "$OVPN_NET" -o tun+ -j MASQUERADE
iptables -t nat -I POSTROUTING -s "$PGW_NET" -o tun+ -j MASQUERADE
```


## Note on Peer IP SNATing through Firewall whitelist
When connecting the IPsec client behind a firewall, the IPSEC peer IP has to expect a static IP address from your pod/host configured in its firewall. Kubernetes pods SNAT the IP of the node that they are spawned in which is not consistent. So in order to have all your cluster pods have one static IP, the pods need to be behind a NAT gateway that will SNAT all pods traffic within the cluster. 
Attempted a couple of options
1. https://github.com/nirmata/kube-static-egress-ip
2. https://ritazh.com/whitelist-egress-traffic-from-kubernetes-8a3adefd94b2
3. https://medium.com/google-cloud/using-cloud-nat-with-gke-cluster-c82364546d9e
4. https://itnext.io/benchmark-results-of-kubernetes-network-plugins-cni-over-10gbit-s-network-36475925a560
5. https://kubernetes.io/docs/concepts/cluster-administration/networking/
6. https://medium.com/bluekiri/setup-a-kubernetes-cluster-on-gcp-with-cloud-nat-efe6aa5780c6
7. https://medium.com/bluekiri/high-availability-nat-gateway-at-google-cloud-platform-with-cloud-nat-8a792b1c4cc4
8. https://cloud.google.com/kubernetes-engine/docs/how-to/ip-masquerade-agent
9. https://cloud.google.com/nat/docs/using-nat
10. https://cloud.google.com/nat/docs/gke-example

Eventually went for quick win with Google NAT gateway. 

## Todo
1. Check Ip packets are not being SNATed to the VPN gatway and that the OVPN client can be seen at PGW end 
2. Get CNI NATing working on Flannel
3. [Kubernetes Security best practises](https://github.com/freach/kubernetes-security-best-practice/blob/master/README.md)