#!/bin/bash
# AmneziaWG server installer
# https://github.com/romikb/amneziawg-install

set -euo pipefail

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
		OS=debian
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

	if [ -e "/home/${CLIENT_NAME}" ]; then
		HOME_DIR="/home/${CLIENT_NAME}"
	elif [ "${SUDO_USER-}" ]; then
		if [ "${SUDO_USER}" == "root" ]; then
			HOME_DIR="/root"
		else
			HOME_DIR="/home/${SUDO_USER}"
		fi
	else
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
	until [[ ${SERVER_AWG_JMIN} =~ ^[0-9]+$ ]] && (( SERVER_AWG_JMIN >= 1 )) && (( SERVER_AWG_JMIN <= 1280 )); do
		read -rp "Server AmneziaWG Jmin [1-1280]: " -e -i 50 SERVER_AWG_JMIN
	done
	until [[ ${SERVER_AWG_JMAX} =~ ^[0-9]+$ ]] && (( SERVER_AWG_JMAX >= 1 )) && (( SERVER_AWG_JMAX <= 1280 )); do
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
	until [[ ${SERVER_AWG_S1} =~ ^[0-9]+$ ]] && (( SERVER_AWG_S1 >= 15 )) && (( SERVER_AWG_S1 <= 150 )); do
		read -rp "Server AmneziaWG S1 [15-150]: " -e -i ${RANDOM_AWG_S1} SERVER_AWG_S1
	done
	until [[ ${SERVER_AWG_S2} =~ ^[0-9]+$ ]] && (( SERVER_AWG_S2 >= 15 )) && (( SERVER_AWG_S2 <= 150 )); do
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
	until [[ ${SERVER_AWG_H1} =~ ^[0-9]+$ ]] && (( SERVER_AWG_H1 >= 5 )) && (( SERVER_AWG_H1 <= 2147483647 )); do
		read -rp "Server AmneziaWG H1 [5-2147483647]: " -e -i ${RANDOM_AWG_H1} SERVER_AWG_H1
	done
	until [[ ${SERVER_AWG_H2} =~ ^[0-9]+$ ]] && (( SERVER_AWG_H2 >= 5 )) && (( SERVER_AWG_H2 <= 2147483647 )); do
		read -rp "Server AmneziaWG H2 [5-2147483647]: " -e -i ${RANDOM_AWG_H2} SERVER_AWG_H2
	done
	until [[ ${SERVER_AWG_H3} =~ ^[0-9]+$ ]] && (( SERVER_AWG_H3 >= 5 )) && (( SERVER_AWG_H3 <= 2147483647 )); do
		read -rp "Server AmneziaWG H3 [5-2147483647]: " -e -i ${RANDOM_AWG_H3} SERVER_AWG_H3
	done
	until [[ ${SERVER_AWG_H4} =~ ^[0-9]+$ ]] && (( SERVER_AWG_H4 >= 5 )) && (( SERVER_AWG_H4 <= 2147483647 )); do
		read -rp "Server AmneziaWG H4 [5-2147483647]: " -e -i ${RANDOM_AWG_H4} SERVER_AWG_H4
	done
}

function installQuestions() {
    echo "AmneziaWG server installer (https://github.com/romikb/amneziawg-install)"
    echo ""
    echo "I need to ask you a few questions before starting the setup."
    echo "You can keep the default options and just press enter if you are ok with them."
    echo ""

    SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
    if [[ -z ${SERVER_PUB_IP} ]]; then
        SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
    fi
    read -rp "Public IPv4 or IPv6 address or domain: " -e -i "${SERVER_PUB_IP}" SERVER_PUB_IP

    echo "Choose DNS provider:"
    echo "1) Google DNS"
    echo "2) Cloudflare DNS"
    echo "3) AdGuard DNS"
    until [[ ${DNS_CHOICE-} =~ ^[1-3]$ ]]; do
        read -rp "DNS choice [1-3]: " -e -i 1 DNS_CHOICE
    done

    case ${DNS_CHOICE} in
        1) CLIENT_DNS_1="8.8.8.8";   CLIENT_DNS_2="8.8.4.4" ;;
        2) CLIENT_DNS_1="1.1.1.1";   CLIENT_DNS_2="1.0.0.1" ;;
        3) CLIENT_DNS_1="94.140.14.14"; CLIENT_DNS_2="94.140.15.15" ;;
    esac

    until [[ ${SERVER_PORT-} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
        read -rp "Server AmneziaWG port [1-65535]: " -e -i 443 SERVER_PORT
    done

    SERVER_PUB_NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    SERVER_AWG_NIC="awg0"
    SERVER_AWG_IPV4="10.66.66.1"
    SERVER_AWG_IPV6="fd42:42:42::1"
    ALLOWED_IPS="0.0.0.0/0"
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
    echo ""
}

function installAmneziaWG() {
	installQuestions
	mkdir -p "${AMNEZIAWG_DIR}"

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
		apt update
		apt install -y software-properties-common
		add-apt-repository -y ppa:amnezia/ppa
		apt update
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

	# Save settings
	cat > "${AMNEZIAWG_DIR}/params" <<-EOF
SERVER_PUB_IP=${SERVER_PUB_IP}
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
SERVER_AWG_H4=${SERVER_AWG_H4}
EOF

	# Server interface
	cat > "${SERVER_AWG_CONF}" <<-EOF
[Interface]
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
H4 = ${SERVER_AWG_H4}
EOF

	if pgrep -x firewalld >/dev/null 2>&1; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_AWG_IPV4}" | cut -d"." -f1-3)".0"
		FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_AWG_IPV6}" | sed 's/:[^:]*$/:0/')
		cat >> "${SERVER_AWG_CONF}" <<-EOF
PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
EOF
	else
		cat >> "${SERVER_AWG_CONF}" <<-EOF
PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
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
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
EOF
	fi

	# Enable routing
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/awg.conf
	sysctl --system

	systemctl start "awg-quick@${SERVER_AWG_NIC}"
	systemctl enable "awg-quick@${SERVER_AWG_NIC}"

	newClient
	echo -e "${GREEN}If you want to add more clients, you simply need to run this script another time!${NC}"

	if ! systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"; then
		echo -e "\n${RED}WARNING: AmneziaWG does not seem to be running.${NC}"
		echo -e "${ORANGE}You can check if AmneziaWG is running with: systemctl status awg-quick@${SERVER_AWG_NIC}${NC}"
		echo -e "${ORANGE}If you get something like \"Cannot find device ${SERVER_AWG_NIC}\", please reboot!${NC}"
	else
		echo -e "\n${GREEN}AmneziaWG is running.${NC}"
		echo -e "${GREEN}You can check the status of AmneziaWG with: systemctl status awg-quick@${SERVER_AWG_NIC}\n\n${NC}"
		echo -e "${ORANGE}If you don't have internet connectivity from your client, try to reboot the server.${NC}"
	fi
}

function allocate_client_ips() {
	# Prints two lines: IPv4 then IPv6
	local CLIENT_AWG_IPV4=""
	local CLIENT_AWG_IPV6=""

	for DOT_IP in {2..254}; do
		local DOT_EXISTS
		DOT_EXISTS=$(grep -c "${SERVER_AWG_IPV4::-1}${DOT_IP}" "${SERVER_AWG_CONF}" || true)
		if [[ ${DOT_EXISTS} == '0' ]]; then
			CLIENT_AWG_IPV4="${SERVER_AWG_IPV4::-1}${DOT_IP}"
			break
		fi
	done
	if [[ -z "${CLIENT_AWG_IPV4}" ]]; then
		echo "The subnet configured supports only 253 clients." >&2
		exit 1
	fi

	local BASE_IP
	BASE_IP=$(echo "$SERVER_AWG_IPV6" | awk -F '::' '{ print $1 }')
	for DOT_IP in {2..254}; do
		local IPV6_EXISTS
		IPV6_EXISTS=$(grep -c "${BASE_IP}::${DOT_IP}/128" "${SERVER_AWG_CONF}" || true)
		if [[ ${IPV6_EXISTS} == '0' ]]; then
			CLIENT_AWG_IPV6="${BASE_IP}::${DOT_IP}"
			break
		fi
	done
	if [[ -z "${CLIENT_AWG_IPV6}" ]]; then
		echo "No free IPv6 found in /64 pool." >&2
		exit 1
	fi

	echo "${CLIENT_AWG_IPV4}"
	echo "${CLIENT_AWG_IPV6}"
}

function newClient() {
	# Add brackets for IPv6 endpoint if missing:
	if [[ ${SERVER_PUB_IP} == *:* && ${SERVER_PUB_IP} != \[* ]]; then
		SERVER_PUB_IP="[${SERVER_PUB_IP}]"
	fi
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	echo ""
	echo "Client configuration"
	echo ""
	echo "The client name must consist of alphanumeric character(s). It may also include underscores or dashes and can't exceed 15 chars."

	# Ask: one or many
	ADD_MODE=""
	until [[ "${ADD_MODE}" =~ ^(1|m|M)$ ]]; do
		read -rp "Add one client or many? [1/m]: " -e -i 1 ADD_MODE
	done

	# Prompt for client base name (without number)
	CLIENT_EXISTS=0
	until [[ ${CLIENT_NAME-} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
		read -rp "Client base name: " -e CLIENT_NAME
		CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "${SERVER_AWG_CONF}" || true)
		if [[ ${CLIENT_EXISTS} != 0 ]]; then
			echo ""
			echo -e "${ORANGE}A client with the specified name already exists, please choose another name.${NC}"
			echo ""
		fi
	done

	# Decide count
	if [[ "${ADD_MODE}" == "1" ]]; then
		KEYS_TO_GENERATE=1
	else
		read -rp "How many clients to create for base \"${CLIENT_NAME}\"? (1-253): " KEYS_TO_GENERATE
		until [[ ${KEYS_TO_GENERATE} =~ ^[0-9]+$ ]] && (( KEYS_TO_GENERATE >= 1 )) && (( KEYS_TO_GENERATE <= 253 )); do
			read -rp "Please enter a valid number (1-253): " KEYS_TO_GENERATE
		done
	fi

	for ((i=1; i<=KEYS_TO_GENERATE; i++)); do
		CLIENT_NAME_SEQ="${i}${CLIENT_NAME}"  # e.g., 1tr, 2tr, 3tr

		# allocate IPs
		mapfile -t IP_LINES < <(allocate_client_ips)
		CLIENT_AWG_IPV4="${IP_LINES[0]}"
		CLIENT_AWG_IPV6="${IP_LINES[1]}"

		# keys
		CLIENT_PRIV_KEY=$(awg genkey)
		CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | awg pubkey)
		CLIENT_PRE_SHARED_KEY=$(awg genpsk)

		HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME_SEQ}")

		# client file
		cat > "${HOME_DIR}/${CLIENT_NAME_SEQ}.conf" <<-EOF
[Interface]
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
AllowedIPs = ${ALLOWED_IPS}
EOF

		# add to server
		cat >> "${SERVER_AWG_CONF}" <<-EOF

### Client ${CLIENT_NAME_SEQ}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_AWG_IPV4}/32,${CLIENT_AWG_IPV6}/128
EOF

		awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}")
		echo -e "${GREEN}Your client config file is in ${HOME_DIR}/${CLIENT_NAME_SEQ}.conf${NC}"
	done
}

function revokeClient() {
    NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "${SERVER_AWG_CONF}" || true)
    if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
        echo ""
        echo "You have no existing clients!"
        exit 1
    fi

    echo ""
    echo "Select the existing client you want to revoke"
    grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | nl -s ') '
    until [[ ${CLIENT_NUMBER-} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
        if [[ ${CLIENT_NUMBER-} == '1' ]]; then
            read -rp "Select one client [1]: " CLIENT_NUMBER
        else
            read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
        fi
    done

    CLIENT_NAME=$(grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)
    sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "${SERVER_AWG_CONF}"

    HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
    rm -f "${HOME_DIR}/${CLIENT_NAME}.conf"

    awg syncconf "${SERVER_AWG_NIC}" <(awg-quick strip "${SERVER_AWG_NIC}")
}

function listClients() {
    echo "Listing all clients:"
    grep -E "^### Client" "${SERVER_AWG_CONF}" | cut -d ' ' -f 3
}

function uninstallAmneziaWG() {
	echo ""
	echo -e "\n${RED}WARNING: This will uninstall AmneziaWG and remove all the configuration files!${NC}"
	echo -e "${ORANGE}Please backup the /etc/amnezia/amneziawg directory if you want to keep your configuration files.\n${NC}"
	read -rp "Do you really want to remove AmneziaWG? [y/n]: " -e REMOVE
	REMOVE=${REMOVE:-n}
	if [[ $REMOVE == 'y' ]]; then
		checkOS

		systemctl stop "awg-quick@${SERVER_AWG_NIC}" || true
		systemctl disable "awg-quick@${SERVER_AWG_NIC}" || true

		rm -f /etc/sysctl.d/awg.conf
		sysctl --system

		rm -rf "${AMNEZIAWG_DIR:?}/"*

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
			apt-key del 57290828 || true
			apt update
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y amneziawg-dkms amneziawg-tools
			dnf copr disable -y amneziavpn/amneziawg
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			dnf remove -y amneziawg-dkms amneziawg-tools
			dnf copr disable -y amneziavpn/amneziawg
		fi

		if systemctl is-active --quiet "awg-quick@${SERVER_AWG_NIC}"; then
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
	until [[ ${MENU_OPTION-} =~ ^[1-5]$ ]]; do
		read -rp "Select an option [1-5]: " MENU_OPTION
	done
	case "${MENU_OPTION}" in
		1) newClient ;;
		2) listClients ;;
		3) revokeClient ;;
		4) uninstallAmneziaWG ;;
		5) exit 0 ;;
	esac
}

# ===== main =====
initialCheck

if [[ -e "${AMNEZIAWG_DIR}/params" ]]; then
	loadParams
	manageMenu
else
	installAmneziaWG
fi
