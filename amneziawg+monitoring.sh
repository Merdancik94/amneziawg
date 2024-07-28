#!/bin/bash

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

AMNEZIAWG_DIR=/opt/amneziawg

function isRoot() {
    if [ "${EUID}" -ne 0 ]; then
        echo -e "${RED}You need to run this script as root.${NC}"
        exit 1
    fi
}

function checkVirt() {
    if [ "$(systemd-detect-virt)" == "openvz" ]; then
        echo -e "${RED}OpenVZ is not supported.${NC}"
        exit 1
    fi
    if [ "$(systemd-detect-virt)" == "lxc" ]; then
        echo -e "${RED}LXC is not supported.${NC}"
        exit 1
    fi
}

function checkOS() {
    if [ -e /etc/debian_version ]; then
        OS="debian"
        source /etc/os-release
        if [[ ${ID} == "debian" || ${ID} == "ubuntu" ]]; then
            OS=${ID}
            VERSION_ID=$(echo "${VERSION_ID}" | cut -d '.' -f 1)
        fi
    elif [ -e /etc/fedora-release ]; then
        OS="fedora"
    elif [ -e /etc/centos-release ]; then
        OS="centos"
    elif [ -e /etc/almalinux-release ]; then
        OS="almalinux"
    elif [ -e /etc/rocky-release ]; then
        OS="rocky"
    else
        echo -e "${RED}Your distribution is not supported (yet).${NC}"
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
    # Your existing implementation or placeholder
}

function readS1AndS2() {
    # Your existing implementation or placeholder
}

function readH1AndH2AndH3AndH4() {
    # Your existing implementation or placeholder
}

function installQuestions() {
    # Your existing implementation or placeholder
}

function installApacheMonitoring() {
    echo -e "${GREEN}Installing Apache monitoring tools...${NC}"
    if [[ ${OS} == 'ubuntu' || ${OS} == 'debian' ]]; then
        apt update
        apt install -y apache2 apache2-utils
        a2enmod status
    elif [[ ${OS} == 'fedora' || ${OS} == 'centos' || ${OS} == 'almalinux' || ${OS} == 'rocky' ]]; then
        dnf install -y httpd httpd-tools
        echo "LoadModule status_module modules/mod_status.so" >> /etc/httpd/conf.modules.d/00-base.conf
    fi
}

function configureModStatus() {
    echo -e "${GREEN}Configuring Apache mod_status...${NC}"
    if [[ ${OS} == 'ubuntu' || ${OS} == 'debian' ]]; then
        echo "
        <Location /server-status>
            SetHandler server-status
            Require local
        </Location>
        " > /etc/apache2/conf-available/status.conf
        a2enconf status
        systemctl restart apache2
    elif [[ ${OS} == 'fedora' || ${OS} == 'centos' || ${OS} == 'almalinux' || ${OS} == 'rocky' ]]; then
        echo "
        <Location /server-status>
            SetHandler server-status
            Require host example.com
            Require ip 192.168.0.0/16
        </Location>
        " > /etc/httpd/conf.d/status.conf
        systemctl restart httpd
    fi
}

function installAmneziaWG() {
    # Run setup questions first
    installQuestions

    # Existing installation steps for AmneziaWG
    if [[ ${OS} == 'ubuntu' || ${OS} == 'debian' ]]; then
        apt update
        apt install -y somepackage
    elif [[ ${OS} == 'fedora' || ${OS} == 'centos' || ${OS} == 'almalinux' || ${OS} == 'rocky' ]]; then
        dnf install -y somepackage
    fi

    # Install and configure Apache monitoring
    installApacheMonitoring
    configureModStatus

    echo -e "${GREEN}AmneziaWG and Apache monitoring setup completed.${NC}"
}

# Main execution
initialCheck
installAmneziaWG
