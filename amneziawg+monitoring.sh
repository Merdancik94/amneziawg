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
    elif [ -e /etc/almali
