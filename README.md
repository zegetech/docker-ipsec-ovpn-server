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

## System requirements
This server/node will be running Open VPN as well as Libreswan. Below are the requirements 

1. CPU requirments is high due to encryption and decryption. As a rule of thumb you should assume that on a modern CPU with AES-NI chipset, for every megabit per second of data traffic (in one direction) you need about 20MHz
2. Memory dependent on number of connected devices. Start at 1GB anc could go lower
3. Bandwidth requirements are completely dependent on how much data you wish to push through the VPN tunnels in total
4. Disk requirements are fairly low. A minimal Linux installation could fit on even 2 gigabytes.

[References](https://openvpn.net/vpn-server-resources/openvpn-access-server-system-requirements/)

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
```bash
# Specify Static IP for OVPN clients
CLIENT_CERT=vpn-client-01
CLIENT_STATIC_IP=173.12.2.90
cat > ${OPENVPN}/ccd/${CLIENT_CERT} <<EOF
ifconfig-push $CLIENT_STATIC_IP $OVPN_CONF_IFCONFIG_INET
EOF
```

### Retrieve client certificate from docker container or Kubernetes pod
On your docker/kubectl localhost, copy the files if selected `separated` or `combined-save`
```bash
kubectl cp <some-namespace>/<some-pod>:/etc/openvpn/clients/vpn-client-01 /tmp/clients/vpn-client-01

docker cp <container>:/etc/openvpn/clients/vpn-client-01 /tmp/clients/vpn-client-01
```

### Logging
Logging is important for troubleshooting iptables and other things. However `LOG` does not work as presecribed on the internet using rsyslog and family  for iptables. Had to use netfilter log `NFLOG`. Here is a good [reference](https://blog.sleeplessbeastie.eu/2018/08/01/how-to-log-dropped-connections-from-iptables-firewall-using-netfilter-userspace-logging-daemon/).

`NFLOG` uses kernel modules so we need to mount the `/lib/modules` on docker/kubernetes host. For Kubernetes, use an `UBUNTU` node type. 

Then in the container/pod install `ulogd2`
```bash
apt-get update && apt-get install -y ulogd2
```

Then copy `extra/ulogd.conf` to the container ulog config file `/etc/ulogd.conf`. This sets up 2 netfilter `nflog` interfaces `nflog:11` and `nflog:12`. You can add more if needed
```bash
kubectl cp path_to/extra/ulogd.conf container_id:/etc/ulogd.conf
```

To log `iptables` add the `LOG_DROP` chain for example as follows
```bash
iptables -N LOG_DROP
iptables -A LOG_DROP -j NFLOG --nflog-prefix "[fw-inc-drop]:" --nflog-group 12
iptables -A LOG_DROP -j DROP

iptables -A FORWARD -m conntrack --ctstate INVALID -j LOG_DROP
```

Then you can capture the logs generated using `tail -f` or `tcpdump` on the netfilter interface.
```bash
# The capture tcpdump on the interface. Daemon has to be off
tcpdump -i nflog:11 
tcpdump -i nflog:12

# Capture tail logs
service ulogd2 start
tail -f /var/log/ulog/firewall.log /var/log/ulog/firewall-ssh-drop.log
```

## MTU (Maximum transmission unit) config
In order to make sure that the VPN as well as the tunnel is workng well, care must be taken to set a proper MTU value. MTU is the largest packet size that can be transmitted without fragmentation.

Discovering the correct MTU is very straightforward and can be achieved using ping. Use the respective following commands (change www.example.com to suit the `PGW` ip)

*On Windows*
```bash
ping -n 1 -l 1500 -f www.example.com
```
*On Linux*
```bash
ping -M do -s 1500 -c 1 www.example.com
```
*On Mac*
```bash
ping -D -v -s 1500 -c 1 www.example.com
```
Decrease the 1500 value by ~10 each time, until the ping succeeds. Once the ping succeeds(the highest value at which the ping succeeds) the value used is the MTU you should use.

Then set the MTU value in the `vpn.env` variable `OVPN_MTU`

## iptables
Configure [iptables](https://linux.die.net/man/8/iptables) for your usecase if needed. Important to note are the ipsec issue [here](https://libreswan.org/wiki/FAQ#My_ssh_sessions_hang_or_connectivity_is_very_slow) and [here](https://www.zeitgeist.se/2013/11/26/mtu-woes-in-ipsec-tunnels-how-to-fix/). Also important to optimise your ipsec tunnel and `iptables` for speed

Forwarding traffic between subnets. OVPN_NET <> PGW_NET as well as fix ipsec MTU configuration.
Added the following in `iptables` configuration
```bash
iptables -I FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS  --clamp-mss-to-pmtu
iptables -I FORWARD 7 -s "$OVPN_NET" -d "$PGW_NET" -j ACCEPT
iptables -I FORWARD 8 -s "$PGW_NET" -d "$OVPN_NET" -j ACCEPT
```

`iptables` are edited and take effect immediately they are saved. While logged into the terminal via `kubectl`, you can run the commands and test different settings. Here are a few helpful commands
```bash
# Reset  Iptables
iptables -F
iptables -X

# Reset all chains
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t raw -F
iptables -t raw -X
iptables -t security -F
iptables -t security -X

# Set default accept policies. No firewall if these are the only rules
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Save IP tables
iptables-save

# List iptables stats including packet counter
iptables -L -nv --line-numbers
```
### Faster IPSEC and IPTABLES
The following [benchmarking and performance testing link](https://libreswan.org/wiki/Benchmarking_and_Performance_testing) is also important in helping to optimize ipsec speed for packet transfer

Here's a link for [faster iptables](https://blog.cloudflare.com/how-to-drop-10-million-packets/) and [about stateless firewall](https://strongarm.io/blog/linux-stateless-firewall/) here


## Issue faced
Disabling `rf_filter` for ipsec. To check configs do
```bash
sysctl -a | grep \\.ip_forward
sysctl -a | grep \\.rp_filter

# If the flag is wrong use similar to this
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf

```

## IPsec client connectivity troubleshooting
Some links useful in troubleshooting IPsec client conectivity 
- [Host to host Libreswan](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/sec-Host-To-Host_VPN_Using_Libreswan#Verify_Host-To-Host_VPN_Using_Libreswan)

- [Site to Site Libreswan](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/site-to-site_vpn_using_libreswan)

- [Troubleshooting IPsec](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/ipsec-troubleshooting.html)

- [IPsec config options](https://libreswan.org/man/ipsec.conf.5.html)

For Further troubleshooting please see [original repos](#adaptation). Also for configuring aditional Lt2pD or CISCO Xauth client users [here](https://github.com/hwdsl2/docker-ipsec-vpn-server#how-to-use-this-image)

## Packet Troubleshooting
You may run into some issues when setting up the tunnel. Here is an [example](https://github.com/hwdsl2/docker-ipsec-vpn-server/issues/152). In most cases you need to analyse the raw traffic to and from your servers and clients

You may use some tools to troubleshoot like
1. `tcpdump`
2. `ssldump`
3. `ulogd`
4. Wireshark or `tshark`

For packet tracing use `tcpdump` and `ssldump` to check for issues and troubleshoot `iptables`. 

examples
```bash
apt-get update && apt-get install -y tcpdump ssldump

# TCP DUMP
tcpdump -D
tcpdump -i tun0 -nn -A
tcpdump -i tun0 -c 5
tcpdump -i tun0 -nn "src host X.X.X.X" or "dst host X.X.X.X"
tcpdump -i tun0 -nn -w webserver.pcap # for analysis on wiresharl

# SSL DUMP
ssldump -i tun0 port 18423
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
1. Get CNI NATing working on Flannel
2. [Kubernetes Security best practises](https://github.com/freach/kubernetes-security-best-practice/blob/master/README.md)