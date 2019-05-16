# Adapted from  
# https://www.github.com/adamwalach/docker-openvpn
# https://github.com/hwdsl2/docker-ipsec-vpn-server/blob/master/Dockerfile

FROM debian:stretch
LABEL maintainer="Kariuki Gathitu <kgathi2@gmail.com>"

ENV REFRESHED_AT 2019-05-15
ENV SWAN_VER 3.27
ENV L2TP_VER 1.3.12

ENV OPENVPN /etc/openvpn
ENV EASYRSA /usr/share/easy-rsa
ENV EASYRSA_PKI $OPENVPN/pki
ENV EASYRSA_VARS_FILE $OPENVPN/vars

WORKDIR /opt/src

RUN apt-get -yqq update \
     && DEBIAN_FRONTEND=noninteractive \
     apt-get -yqq --no-install-recommends install \
     wget dnsutils openssl ca-certificates kmod \
     iproute gawk grep sed net-tools iptables \
     bsdmainutils libcurl3-nss \
     libnss3-tools libevent-dev libcap-ng0 xl2tpd \
     libnss3-dev libnspr4-dev pkg-config libpam0g-dev \
     libcap-ng-dev libcap-ng-utils libselinux1-dev \
     libcurl4-nss-dev libpcap0.8-dev flex bison gcc make \
     openvpn iptables bash easy-rsa libpam-google-authenticator pamtester \
     && wget -t 3 -T 30 -nv -O libreswan.tar.gz "https://github.com/libreswan/libreswan/archive/v${SWAN_VER}.tar.gz" \
     || wget -t 3 -T 30 -nv -O libreswan.tar.gz "https://download.libreswan.org/libreswan-${SWAN_VER}.tar.gz" \
     && tar xzf libreswan.tar.gz \
     && rm -f libreswan.tar.gz \
     && cd "libreswan-${SWAN_VER}" \
     && printf 'WERROR_CFLAGS =\nUSE_DNSSEC = false\nUSE_DH31 = false\n' > Makefile.inc.local \
     && printf 'USE_GLIBC_KERN_FLIP_HEADERS = true\nUSE_SYSTEMD_WATCHDOG = false\n' >> Makefile.inc.local \
     && make -s base \
     && make -s install-base \
     && cd /opt/src \
     && rm -rf "/opt/src/libreswan-${SWAN_VER}" \
     && wget -t 3 -T 30 -nv -O xl2tpd.tar.gz "https://github.com/xelerance/xl2tpd/archive/v${L2TP_VER}.tar.gz" \
     || wget -t 3 -T 30 -nv -O xl2tpd.tar.gz "https://debian.osuosl.org/debian/pool/main/x/xl2tpd/xl2tpd_${L2TP_VER}.orig.tar.gz" \
     && tar xzf xl2tpd.tar.gz \
     && rm -f xl2tpd.tar.gz \
     && cd "xl2tpd-${L2TP_VER}" \
     && make -s \
     && PREFIX=/usr make -s install \
     && cd /opt/src \
     && rm -rf "/opt/src/xl2tpd-${L2TP_VER}" \
     && apt-get -yqq remove \
     libnss3-dev libnspr4-dev pkg-config libpam0g-dev \
     libcap-ng-dev libcap-ng-utils libselinux1-dev \
     libcurl4-nss-dev libpcap0.8-dev flex bison gcc make \
     perl-modules perl \
     && apt-get -yqq autoremove \
     && apt-get -y clean \
     && rm -rf /var/lib/apt/lists/*

COPY ./run.sh /opt/src/run.sh
RUN chmod 755 /opt/src/run.sh

# COPY OpenVPN executables
COPY ./bin /usr/local/bin
RUN chmod a+x /usr/local/bin/*

# Add support for OTP authentication using a PAM module
COPY ./otp/openvpn /etc/pam.d/

# OpenVPN Internally uses port 1194/udp, 
# remap using `docker run -p 443:1194/tcp`
# OpenVPN Management interface on 2080/tcp
# Libreswan uses
# port 500/udp for the Internet Key Exchange (IKE) protocol
# port 4500/udp for IKE NAT-Traversal
EXPOSE 1194/udp 2080/tcp
EXPOSE 500/udp 4500/udp 

VOLUME ["/etc/openvpn"]
VOLUME ["/etc/ipsec.d"]
VOLUME ["/lib/modules"]

CMD ["/opt/src/run.sh"]
