#!/bin/bash

# AmneziaWG server installer
# https://github.com/romikb/amneziawg-install

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

AMNEZIAWG_DIR="/etc/amnezia/amneziawg"

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function checkVirt() {
	if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
	fi

	if [ "$(systemd-detect-virt)" == "lxc" ]; then
		echo "LXC is not supported (yet)."
		echo "WireGuard can technically run in an LXC container,"
		echo "but the kernel module has to be installed on the host,"
		echo "the container has to be run with some specific parameters"
		echo "and only the tools need to be installed in the container."
		exit 1
	fi
}

function checkOS() {
	source /etc/os-release
	OS="${ID}"
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ ${VERSION_ID} -lt 11 ]]; then
			echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 11 Bullseye or later"
			exit 1
		fi
		OS=debian # overwrite if raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if [[ ${RELEASE_YEAR} -lt 20 ]]; then
			echo "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 20.04 or later"
			exit 1
		fi
	elif [[ ${OS} == "fedora" ]]; then
		if [[ ${VERSION_ID} -lt 39 ]]; then
			echo "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 39 or later"
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 7* ]] || [[ ${VERSION_ID} == 8* ]]; then
			echo "Your version of CentOS (${VERSION_ID}) is not supported. Please use CentOS 9 or later"
			exit 1
		fi
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, AlmaLinux or Rocky Linux system"
		exit 1
	fi
}

function getHomeDirForClient() {
	local CLIENT_NAME=$1

	if [ -z "${CLIENT_NAME}" ]; then
		echo "Error: getHomeDirForClient() requires a client name as argument"
		exit 1
	fi

	# Home directory of the user, where the client configuration will be written
	if [ -e "/home/${CLIENT_NAME}" ]; then
		# if $1 is a user name
		HOME_DIR="/home/${CLIENT_NAME}"
	elif [ "${SUDO_USER}" ]; then
		# if not, use SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# If running sudo as root
			HOME_DIR="/root"
		else
			HOME_DIR="/home/${SUDO_USER}"
		fi
	else
		# if not SUDO_USER, use /root
		HOME_DIR="/root"
	fi

	echo "$HOME_DIR"
}

function initialCheck() {
	isRoot
	checkVirt
	checkOS
}

function readJminAndJmax() {
	SERVER_AWG_JMIN=0
	SERVER_AWG_JMAX=0
	until [[ ${SERVER_AWG_JMIN} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_JMIN} >= 1 )) && (( ${SERVER_AWG_JMIN} <= 1280 )); do
		read -rp "Server AmneziaWG Jmin [1-1280]: " -e -i 50 SERVER_AWG_JMIN
	done
	until [[ ${SERVER_AWG_JMAX} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_JMAX} >= 1 )) && (( ${SERVER_AWG_JMAX} <= 1280 )); do
		read -rp "Server AmneziaWG Jmax [1-1280]: " -e -i 1000 SERVER_AWG_JMAX
	done
}

function generateS1AndS2() {
	RANDOM_AWG_S1=$(shuf -i15-150 -n1)
	RANDOM_AWG_S2=$(shuf -i15-150 -n1)
}

function readS1AndS2() {
	SERVER_AWG_S1=0
	SERVER_AWG_S2=0
	until [[ ${SERVER_AWG_S1} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_S1} >= 15 )) && (( ${SERVER_AWG_S1} <= 150 )); do
		read -rp "Server AmneziaWG S1 [15-150]: " -e -i ${RANDOM_AWG_S1} SERVER_AWG_S1
	done
	until [[ ${SERVER_AWG_S2} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_S2} >= 15 )) && (( ${SERVER_AWG_S2} <= 150 )); do
		read -rp "Server AmneziaWG S2 [15-150]: " -e -i ${RANDOM_AWG_S2} SERVER_AWG_S2
	done
}

function generateH1AndH2AndH3AndH4() {
	RANDOM_AWG_H1=$(shuf -i5-2147483647 -n1)
	RANDOM_AWG_H2=$(shuf -i5-2147483647 -n1)
	RANDOM_AWG_H3=$(shuf -i5-2147483647 -n1)
	RANDOM_AWG_H4=$(shuf -i5-2147483647 -n1)
}

function readH1AndH2AndH3AndH4() {
	SERVER_AWG_H1=0
	SERVER_AWG_H2=0
	SERVER_AWG_H3=0
	SERVER_AWG_H4=0
	until [[ ${SERVER_AWG_H1} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_H1} >= 5 )) && (( ${SERVER_AWG_H1} <= 2147483647 )); do
		read -rp "Server AmneziaWG H1 [5-2147483647]: " -e -i ${RANDOM_AWG_H1} SERVER_AWG_H1
	done
	until [[ ${SERVER_AWG_H2} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_H2} >= 5 )) && (( ${SERVER_AWG_H2} <= 2147483647 )); do
		read -rp "Server AmneziaWG H2 [5-2147483647]: " -e -i ${RANDOM_AWG_H2} SERVER_AWG_H2
	done
	until [[ ${SERVER_AWG_H3} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_H3} >= 5 )) && (( ${SERVER_AWG_H3} <= 2147483647 )); do
		read -rp "Server AmneziaWG H3 [5-2147483647]: " -e -i ${RANDOM_AWG_H3} SERVER_AWG_H3
	done
	until [[ ${SERVER_AWG_H4} =~ ^[0-9]+$ ]] && (( ${SERVER_AWG_H4} >= 5 )) && (( ${SERVER_AWG_H4} <= 2147483647 )); do
		read -rp "Server AmneziaWG H4 [5-2147483647]: " -e -i ${RANDOM_AWG_H4} SERVER_AWG_H4
	done
}

function installQuestions() {
    echo "AmneziaWG server installer (https://github.com/romikb/amneziawg-install)"
    echo ""
    echo "I need to ask you a few questions before starting the setup."
    echo "You can keep the default options and just press enter if you are ok with them."
    echo ""

    # Detect public IPv4 or IPv6 address and pre-fill for the user
    SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
    if [[ -z ${SERVER_PUB_IP} ]]; then
        # Detect public IPv6 address
        SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
    fi
    read -rp "Public IPv4 or IPv6 address or domain: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

    # Prompt for DNS settings
    echo "Choose DNS provider:"
    echo "1) Google DNS"
    echo "2) Cloudflare DNS"
    echo "3) AdGuard DNS"
    until [[ ${DNS_CHOICE} =~ ^[1-3]$ ]]; do
        read -rp "DNS choice [1-3]: " -e -i 1 DNS_CHOICE
    done

    case ${DNS_CHOICE} in
        1)
            CLIENT_DNS_1="8.8.8.8"
            CLIENT_DNS_2="8.8.4.4"
            ;;
        2)
            CLIENT_DNS_1="1.1.1.1"
            CLIENT_DNS_2="1.0.0.1"
            ;;
        3)
            CLIENT_DNS_1="94.140.14.14"
            CLIENT_DNS_2="94.140.15.15"
            ;;
    esac

    # Prompt for port number
    until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
        read -rp "Server AmneziaWG port [1-65535]: " -e -i 443 SERVER_PORT
    done

    # Use default values for other settings
    SERVER_PUB_NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    SERVER_AWG_NIC="awg0"
    SERVER_AWG_IPV4="10.66.66.1"
    SERVER_AWG_IPV6="fd42:42:42::1"
    ALLOWED_IPS=""0.0.0.0/3, 32.0.0.0/4, 48.0.0.0/5, 56.0.0.0/8, 57.0.0.0/10, 57.64.0.0/12, 57.80.0.0/13, 57.88.0.0/15, 57.90.0.0/17, 57.90.128.0/20, 57.90.144.0/22, 57.90.148.0/23, 57.90.152.0/21, 57.90.160.0/19, 57.90.192.0/18, 57.91.0.0/16, 57.92.0.0/14, 57.96.0.0/11, 57.128.0.0/9, 58.0.0.0/7, 60.0.0.0/6, 64.0.0.0/5, 72.0.0.0/6, 76.0.0.0/8, 77.0.0.0/10, 77.64.0.0/12, 77.80.0.0/15, 77.82.0.0/16, 77.83.0.0/19, 77.83.32.0/20, 77.83.48.0/21, 77.83.56.0/23, 77.83.58.0/24, 77.83.60.0/22, 77.83.64.0/18, 77.83.128.0/17, 77.84.0.0/14, 77.88.0.0/13, 77.96.0.0/11, 77.128.0.0/9, 78.0.0.0/7, 80.0.0.0/6, 84.0.0.0/8, 85.0.0.0/9, 85.128.0.0/12, 85.144.0.0/13, 85.152.0.0/16, 85.153.0.0/19, 85.153.32.0/21, 85.153.40.0/22, 85.153.44.0/24, 85.153.46.0/23, 85.153.48.0/20, 85.153.64.0/18, 85.153.128.0/17, 85.154.0.0/15, 85.156.0.0/14, 85.160.0.0/11, 85.192.0.0/10, 86.0.0.0/7, 88.0.0.0/7, 90.0.0.0/8, 91.0.0.0/9, 91.128.0.0/10, 91.192.0.0/13, 91.200.0.0/15, 91.202.0.0/17, 91.202.128.0/18, 91.202.192.0/19, 91.202.224.0/21, 91.202.233.0/24, 91.202.234.0/23, 91.202.236.0/22, 91.202.240.0/20, 91.203.0.0/16, 91.204.0.0/14, 91.208.0.0/12, 91.224.0.0/11, 92.0.0.0/8, 93.0.0.0/9, 93.128.0.0/11, 93.160.0.0/13, 93.168.0.0/15, 93.170.0.0/16, 93.171.0.0/17, 93.171.128.0/19, 93.171.160.0/21, 93.171.168.0/22, 93.171.172.0/23, 93.171.175.0/24, 93.171.176.0/20, 93.171.192.0/20, 93.171.208.0/21, 93.171.216.0/22, 93.171.224.0/19, 93.172.0.0/14, 93.176.0.0/12, 93.192.0.0/10, 94.0.0.0/10, 94.64.0.0/11, 94.96.0.0/14, 94.100.0.0/15, 94.102.0.0/17, 94.102.128.0/19, 94.102.160.0/20, 94.102.192.0/18, 94.103.0.0/16, 94.104.0.0/13, 94.112.0.0/12, 94.128.0.0/9, 95.0.0.0/10, 95.64.0.0/12, 95.80.0.0/14, 95.84.0.0/16, 95.85.0.0/18, 95.85.64.0/19, 95.85.128.0/17, 95.86.0.0/15, 95.88.0.0/13, 95.96.0.0/11, 95.128.0.0/9, 96.0.0.0/6, 100.0.0.0/7, 102.0.0.0/8, 103.0.0.0/9, 103.128.0.0/10, 103.192.0.0/12, 103.208.0.0/16, 103.209.0.0/17, 103.209.128.0/18, 103.209.192.0/19, 103.209.224.0/22, 103.209.228.0/23, 103.209.231.0/24, 103.209.232.0/21, 103.209.240.0/20, 103.210.0.0/15, 103.212.0.0/14, 103.216.0.0/14, 103.220.4.0/22, 103.220.8.0/21, 103.220.16.0/20, 103.220.32.0/19, 103.220.64.0/18, 103.220.128.0/17, 103.221.0.0/16, 103.222.0.0/15, 103.224.0.0/11, 104.0.0.0/5, 112.0.0.0/6, 116.0.0.0/7, 118.0.0.0/8, 119.0.0.0/9, 119.128.0.0/10, 119.192.0.0/11, 119.224.0.0/13, 119.232.0.0/15, 119.234.0.0/16, 119.235.0.0/18, 119.235.64.0/19, 119.235.96.0/20, 119.235.128.0/17, 119.236.0.0/14, 119.240.0.0/12, 120.0.0.0/5, 128.0.0.0/4, 144.0.0.0/5, 152.0.0.0/7, 154.0.0.0/12, 154.16.0.0/13, 154.24.0.0/14, 154.28.0.0/15, 154.30.0.0/20, 154.30.16.0/21, 154.30.24.0/22, 154.30.28.0/24, 154.30.30.0/23, 154.30.32.0/19, 154.30.64.0/18, 154.30.128.0/17, 154.31.0.0/16, 154.32.0.0/11, 154.64.0.0/10, 154.128.0.0/9, 155.0.0.0/8, 156.0.0.0/6, 160.0.0.0/4, 176.0.0.0/8, 177.0.0.0/10, 177.64.0.0/12, 177.80.0.0/13, 177.88.0.0/14, 177.92.0.0/16, 177.93.0.0/17, 177.93.128.0/21, 177.93.136.0/22, 177.93.140.0/23, 177.93.142.0/24, 177.93.144.0/20, 177.93.160.0/19, 177.93.192.0/18, 177.94.0.0/15, 177.96.0.0/11, 177.128.0.0/9, 178.0.0.0/9, 178.128.0.0/11, 178.160.0.0/13, 178.168.0.0/15, 178.170.0.0/16, 178.171.0.0/18, 178.171.64.0/23, 178.171.68.0/22, 178.171.72.0/21, 178.171.80.0/20, 178.171.96.0/19, 178.171.128.0/17, 178.172.0.0/14, 178.176.0.0/12, 178.192.0.0/10, 179.0.0.0/8, 180.0.0.0/6, 184.0.0.0/8, 185.0.0.0/10, 185.64.0.0/14, 185.68.0.0/16, 185.69.0.0/17, 185.69.128.0/19, 185.69.160.0/20, 185.69.176.0/21, 185.69.188.0/22, 185.69.192.0/18, 185.70.0.0/15, 185.72.0.0/13, 185.80.0.0/12, 185.96.0.0/11, 185.128.0.0/10, 185.192.0.0/11, 185.224.0.0/12, 185.240.0.0/14, 185.244.0.0/15, 185.246.0.0/18, 185.246.64.0/21, 185.246.76.0/22, 185.246.80.0/20, 185.246.96.0/19, 185.246.128.0/17, 185.247.0.0/16, 185.248.0.0/13, 186.0.0.0/7, 188.0.0.0/6, 192.0.0.0/4, 208.0.0.0/5, 216.0.0.0/9, 216.128.0.0/10, 216.192.0.0/11, 216.224.0.0/12, 216.240.0.0/13, 216.248.0.0/15, 216.250.0.0/21, 216.250.16.0/20, 216.250.32.0/19, 216.250.64.0/18, 216.250.128.0/17, 216.251.0.0/16, 216.252.0.0/14, 217.0.0.0/13, 217.8.0.0/18, 217.8.64.0/19, 217.8.96.0/20, 217.8.112.0/22, 217.8.116.0/24, 217.8.118.0/23, 217.8.120.0/21, 217.8.128.0/17, 217.9.0.0/16, 217.10.0.0/15, 217.12.0.0/14, 217.16.0.0/12, 217.32.0.0/11, 217.64.0.0/10, 217.128.0.0/11, 217.160.0.0/13, 217.168.0.0/14, 217.172.0.0/15, 217.174.0.0/17, 217.174.128.0/18, 217.174.192.0/19, 217.174.240.0/20, 217.175.0.0/16, 217.176.0.0/12, 217.192.0.0/10, 218.0.0.0/7, 220.0.0.0/6, 224.0.0.0/3""
    SERVER_AWG_JC=$(shuf -i3-10 -n1)
    SERVER_AWG_JMIN=50
    SERVER_AWG_JMAX=1000
    SERVER_AWG_S1=$(shuf -i15-150 -n1)
    SERVER_AWG_S2=$(shuf -i15-150 -n1)
    SERVER_AWG_H1=$(shuf -i5-2147483647 -n1)
    SERVER_AWG_H2=$(shuf -i5-2147483647 -n1)
    SERVER_AWG_H3=$(shuf -i5-2147483647 -n1)
    SERVER_AWG_H4=$(shuf -i5-2147483647 -n1)

    echo ""
    echo "Okay, that was all I needed. We are ready to setup your AmneziaWG server now."
    echo "You will be able to generate a client at the end of the installation."
    read -n1 -r -p "Press any key to continue..."
}



function installAmneziaWG() {
	# Run setup questions first
	installQuestions

	# Install AmneziaWG tools and module
	if [[ ${OS} == 'ubuntu' ]]; then
		if [[ -e /etc/apt/sources.list.d/ubuntu.sources ]]; then
			if ! grep -q "deb-src" /etc/apt/sources.list.d/ubuntu.sources; then
				cp /etc/apt/sources.list.d/ubuntu.sources /etc/apt/sources.list.d/amneziawg.sources
				sed -i 's/deb/deb-src/' /etc/apt/sources.list.d/amneziawg.sources
			fi
		else
			if ! grep -q "^deb-src" /etc/apt/sources.list; then
				cp /etc/apt/sources.list /etc/apt/sources.list.d/amneziawg.sources.list
				sed -i 's/^deb/deb-src/' /etc/apt/sources.list.d/amneziawg.sources.list
			fi
		fi
		apt install -y software-properties-common
		add-apt-repository -y ppa:amnezia/ppa
		apt install -y amneziawg amneziawg-tools qrencode
	elif [[ ${OS} == 'debian' ]]; then
		if ! grep -q "^deb-src" /etc/apt/sources.list; then
			cp /etc/apt/sources.list /etc/apt/sources.list.d/amneziawg.sources.list
			sed -i 's/^deb/deb-src/' /etc/apt/sources.list.d/amneziawg.sources.list
		fi
		apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 57290828
		echo "deb https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" >>/etc/apt/sources.list.d/amneziawg.sources.list
		echo "deb-src https://ppa.launchpadcontent.net/amnezia/ppa/ubuntu focal main" >>/etc/apt/sources.list.d/amneziawg.sources.list
		apt update
		apt install -y amneziawg amneziawg-tools qrencode iptables
	elif [[ ${OS} == 'fedora' ]]; then
		dnf config-manager --set-enabled crb
		dnf install -y epel-release
		dnf copr enable -y amneziavpn/amneziawg
		dnf install -y amneziawg-dkms amneziawg-tools qrencode iptables
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		dnf config-manager --set-enabled crb
		dnf install -y epel-release
		dnf copr enable -y amneziavpn/amneziawg
		dnf install -y amneziawg-dkms amneziawg-tools qrencode iptables
	fi

	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"

	SERVER_PRIV_KEY=$(awg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | awg pubkey)

	# Save WireGuard settings
	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_AWG_NIC=${SERVER_AWG_NIC}
SERVER_AWG_IPV4=${SERVER_AWG_IPV4}
SERVER_AWG_IPV6=${SERVER_AWG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}
SERVER_AWG_JC=${SERVER_AWG_JC}
SERVER_AWG_JMIN=${SERVER_AWG_JMIN}
SERVER_AWG_JMAX=${SERVER_AWG_JMAX}
SERVER_AWG_S1=${SERVER_AWG_S1}
SERVER_AWG_S2=${SERVER_AWG_S2}
SERVER_AWG_H1=${SERVER_AWG_H1}
SERVER_AWG_H2=${SERVER_AWG_H2}
SERVER_AWG_H3=${SERVER_AWG_H3}
SERVER_AWG_H4=${SERVER_AWG_H4}" >"${AMNEZIAWG_DIR}/params"

	# Add server interface
	echo "[Interface]
Address = ${SERVER_AWG_IPV4}/24,${SERVER_AWG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
Jc = ${SERVER_AWG_JC}
Jmin = ${SERVER_AWG_JMIN}
Jmax = ${SERVER_AWG_JMAX}
S1 = ${SERVER_AWG_S1}
S2 = ${SERVER_AWG_S2}
H1 = ${SERVER_AWG_H1}
H2 = ${SERVER_AWG_H2}
H3 = ${SERVER_AWG_H3}
H4 = ${SERVER_AWG_H4}" >"${SERVER_AWG_CONF}"

	if pgrep firewalld; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_AWG_IPV4}" | cut -d"." -f1-3)".0"
		FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_AWG_IPV6}" | sed 's/:[^:]*$/:0/')
		echo "PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"${SERVER_AWG_CONF}"
	else
		echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = ip6tables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j ACCEPT
PostUp = ip6tables -I FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_AWG_NIC} -j ACCEPT
PostDown = ip6tables -D FORWARD -i ${SERVER_AWG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"${SERVER_AWG_CONF}"
	fi

	# Enable routing on the server
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/awg.conf

	sysctl --system

	systemctl start "awg-quick@${SERVER_AWG_NIC}"
	systemctl enable "awg-quick@${SERVER_AWG_NIC}"

	newClient
	echo -e "${GREEN}If you want to add more clients, you simply need to run this script another time!${NC}"

	# Check if AmneziaWG is running
	systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"
	AWG_RUNNING=$?

	# AmneziaWG might not work if we updated the kernel. Tell the user to reboot
	if [[ ${AWG_RUNNING} -ne 0 ]]; then
		echo -e "\n${RED}WARNING: AmneziaWG does not seem to be running.${NC}"
		echo -e "${ORANGE}You can check if AmneziaWG is running with: systemctl status awg-quick@${SERVER_AWG_NIC}${NC}"
		echo -e "${ORANGE}If you get something like \"Cannot find device ${SERVER_AWG_NIC}\", please reboot!${NC}"
	else # AmneziaWG is running
		echo -e "\n${GREEN}AmneziaWG is running.${NC}"
		echo -e "${GREEN}You can check the status of AmneziaWG with: systemctl status awg-quick@${SERVER_AWG_NIC}\n\n${NC}"
		echo -e "${ORANGE}If you don't have internet connectivity from your client, try to reboot the server.${NC}"
	fi
}

function newClient() {
    # If SERVER_PUB_IP is IPv6, add brackets if missing
    if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
        if [[ ${SERVER_PUB_IP} != *"["* ]] || [[ ${SERVER_PUB_IP} != *"]"* ]]; then
            SERVER_PUB_IP="[${SERVER_PUB_IP}]"
        fi
    fi
    ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

    echo ""
    echo "Client configuration"
    echo ""
    echo "The client name must consist of alphanumeric character(s). It may also include underscores or dashes and can't exceed 15 chars."

    until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
        read -rp "Client name: " -e CLIENT_NAME
        CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "${SERVER_AWG_CONF}")

        if [[ ${CLIENT_EXISTS} != 0 ]]; then
            echo ""
            echo -e "${ORANGE}A client with the specified name was already created, please choose another name.${NC}"
            echo ""
        fi
    done

    for DOT_IP in {2..254}; do
        DOT_EXISTS=$(grep -c "${SERVER_AWG_IPV4::-1}${DOT_IP}" "${SERVER_AWG_CONF}")
        if [[ ${DOT_EXISTS} == '0' ]]; then
            CLIENT_AWG_IPV4="${SERVER_AWG_IPV4::-1}${DOT_IP}"
            break
        fi
    done

    if [[ ${DOT_EXISTS} == '1' ]]; then
        echo ""
        echo "The subnet configured supports only 253 clients."
        exit 1
    fi

    BASE_IP=$(echo "$SERVER_AWG_IPV6" | awk -F '::' '{ print $1 }')
    for DOT_IP in {2..254}; do
        IPV6_EXISTS=$(grep -c "${BASE_IP}::${DOT_IP}/128" "${SERVER_AWG_CONF}")
        if [[ ${IPV6_EXISTS} == '0' ]]; then
            CLIENT_AWG_IPV6="${BASE_IP}::${DOT_IP}"
            break
        fi
    done

    # Generate key pair for the client
    CLIENT_PRIV_KEY=$(awg genkey)
    CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | awg pubkey)
    CLIENT_PRE_SHARED_KEY=$(awg genpsk)

    HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")

    # Create client file and add the server as a peer
    echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_AWG_IPV4}/32,${CLIENT_AWG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}
Jc = ${SERVER_AWG_JC}
Jmin = ${SERVER_AWG_JMIN}
Jmax = ${SERVER_AWG_JMAX}
S1 = ${SERVER_AWG_S1}
S2 = ${SERVER_AWG_S2}
H1 = ${SERVER_AWG_H1}
H2 = ${SERVER_AWG_H2}
H3 = ${SERVER_AWG_H3}
H4 = ${SERVER_AWG_H4}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}" >"${HOME_DIR}/${CLIENT_NAME}.conf"

    # Add the client as a peer to the server
    echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_AWG_IPV4}/32,${CLIENT_AWG_IPV6}/128" >>"${SERVER_AWG_CONF}"

    awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}")

    echo -e "${GREEN}Your client config file is in ${HOME_DIR}/${CLIENT_NAME}.conf${NC}"
}




function listClients() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "${SERVER_AWG_CONF}")
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | nl -s ') '
}

function revokeClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "${SERVER_AWG_CONF}")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		echo ""
		echo "You have no existing clients!"
		exit 1
	fi

	echo ""
	echo "Select the existing client you want to revoke"
	grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			read -rp "Select one client [1]: " CLIENT_NUMBER
		else
			read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
		fi
	done

	# match the selected number to a client name
	CLIENT_NAME=$(grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	# remove [Peer] block matching $CLIENT_NAME
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "${SERVER_AWG_CONF}"

	# remove generated client file
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	rm -f "${HOME_DIR}/${SERVER_AWG_NIC}-client-${CLIENT_NAME}.conf"

	# restart AmneziaWG to apply changes
	awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}")
}

function uninstallAmneziaWG() {
	echo ""
	echo -e "\n${RED}WARNING: This will uninstall AmneziaWG and remove all the configuration files!${NC}"
	echo -e "${ORANGE}Please backup the /etc/amnezia/amneziawg directory if you want to keep your configuration files.\n${NC}"
	read -rp "Do you really want to remove AmneziaWG? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
	if [[ $REMOVE == 'y' ]]; then
		checkOS

		systemctl stop "awg-quick@${SERVER_AWG_NIC}"
		systemctl disable "awg-quick@${SERVER_AWG_NIC}"

		# Disable routing
		rm -f /etc/sysctl.d/awg.conf
		sysctl --system

		# Remove config files
		rm -rf ${AMNEZIAWG_DIR}/*

		if [[ ${OS} == 'ubuntu' ]]; then
			apt remove -y amneziawg amneziawg-tools
			add-apt-repository -ry ppa:amnezia/ppa
			if [[ -e /etc/apt/sources.list.d/ubuntu.sources ]]; then
				rm -f /etc/apt/sources.list.d/amneziawg.sources
			else
				rm -f /etc/apt/sources.list.d/amneziawg.sources.list
			fi
		elif [[ ${OS} == 'debian' ]]; then
			apt-get remove -y amneziawg amneziawg-tools
			rm -f /etc/apt/sources.list.d/amneziawg.sources.list
			apt-key del 57290828
			apt update
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y amneziawg-dkms amneziawg-tools
			dnf copr disable -y amneziavpn/amneziawg
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			dnf remove -y amneziawg-dkms amneziawg-tools
			dnf copr disable -y amneziavpn/amneziawg
		fi

		# Check if AmneziaWG is running
		systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"
		AWG_RUNNING=$?

		if [[ ${AWG_RUNNING} -eq 0 ]]; then
			echo "AmneziaWG failed to uninstall properly."
			exit 1
		else
			echo "AmneziaWG uninstalled successfully."
			exit 0
		fi
	else
		echo ""
		echo "Removal aborted!"
	fi
}

function loadParams() {
	source "${AMNEZIAWG_DIR}/params"
	SERVER_AWG_CONF="${AMNEZIAWG_DIR}/${SERVER_AWG_NIC}.conf"
}

function manageMenu() {
	echo "AmneziaWG server installer (https://github.com/romikb/amneziawg-install)"
	echo ""
	echo "It looks like AmneziaWG is already installed."
	echo ""
	echo "What do you want to do?"
	echo "   1) Add a new user"
	echo "   2) List all users"
	echo "   3) Revoke existing user"
	echo "   4) Uninstall AmneziaWG"
	echo "   5) Exit"
	until [[ ${MENU_OPTION} =~ ^[1-5]$ ]]; do
		read -rp "Select an option [1-5]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
	1)
		newClient
		;;
	2)
		listClients
		;;
	3)
		revokeClient
		;;
	4)
		uninstallAmneziaWG
		;;
	5)
		exit 0
		;;
	esac
}

# Check for root, virt, OS...
initialCheck

# Check if AmneziaWG is already installed and load params
if [[ -e "${AMNEZIAWG_DIR}/params" ]]; then
	loadParams
	manageMenu
else
	installAmneziaWG
fi
