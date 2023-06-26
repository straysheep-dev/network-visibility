#!/bin/bash

# MIT License

# Setup bettercap and services for intercepting and inspecting traffic
# Version=0.6 (Tested on 20.04.x Desktop)

# shellcheck disable=SC2181
# shellcheck disable=SC2166
# shellcheck disable=SC1091
# shellcheck disable=SC2016

# Thanks to the following projects for code, ideas, and guidance:
# https://github.com/activecm/rita
# https://github.com/zeek/zeek
# https://github.com/g0tmi1k/OS-Scripts
# https://github.com/angristan/wireguard-install

# Resources:
# https://www.activecountermeasures.com/why-is-my-program-running-slowly/
# docker-zeek https://github.com/activecm/docker-zeek/tree/master/etc
# gen-node-cfg.sh https://raw.githubusercontent.com/activecm/bro-install/master/gen-node-cfg.sh"
# node.cfg-template https://raw.githubusercontent.com/activecm/bro-install/master/node.cfg-template"
# networks.cfg https://raw.githubusercontent.com/activecm/docker-zeek/master/etc/networks.cfg
# node.cfg     https://raw.githubusercontent.com/activecm/docker-zeek/master/etc/node.example.cfg
# zeekctl.cfg  https://raw.githubusercontent.com/activecm/docker-zeek/master/etc/zeekctl.cfg


#=====
# Vars
#=====

BLUE="\033[01;34m"   # information
GREEN="\033[01;32m"  # information
YELLOW="\033[01;33m" # warnings
RED="\033[01;31m"    # errors
BOLD="\033[01;01m"   # highlight
RESET="\033[00m"     # reset

PUB_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)" # Public Network Interface Card

ZEEK_VER="${zeek_ver:-5.2.2}"                                                          # Replace this variable when latest release is available: https://github.com/zeek/zeek/releases/
ZEEK_GPG='E9690B2B7D8AC1A19F921C4AC68B494DF56ACC7E'                                    # Replace this variable when a new key is available: https://github.com/zeek/zeek-docs/blob/master/install.rst#binary-packages, https://keyserver.ubuntu.com/pks/lookup?search=E9690B2B7D8AC1A19F921C4AC68B494DF56ACC7E&fingerprint=on&op=index
ZEEK_DOCKER_HASH='ebb0949dc6df908fecb9997f5ddcca70be3b2ed18c9af47076742d641eaa9fc2'    # Replace variable when latest release is available: https://github.com/activecm/docker-zeek/blob/master/zeek
ZEEK_GEN_CFG_HASH='1b13b9cb0ee1bc7662ad9c2551181e012d07d83848727f9277c64086d9ec330e'   # This value should never change
ZEEK_NODE_CFG_HASH='73fb4894fba81d5a52c9cb8160e0b73c116c311648ecc6dda7921bdd2b7b6721'  # This value should never change

RITA_VER="${rita_ver:-4.8.0}"                                                          # Replace variable when latest release is available: https://github.com/activecm/rita/releases
RITA_HASH='aa4b8b0c4076f4a9c3ff519eed2467cde9ae79abe05b6e97c1a8f55f979dc3f7'           # Replace variable when latest release is available: install.sh
RITA_CONF_HASH='f2b06436a581977608b514f7caa68ecc431465bb0d935fa2a05ac1e0d139effe'      # Replace variable when latest release is available: https://github.com/activecm/rita/blob/master/etc/rita.yaml
RITA_COMPOSE_HASH='82abd8565ba0aa7022e1d4d2cb17c6e63172e2bca78c4518a3967760f921ebfe'   # Replace variable when latest release is available: https://github.com/activecm/rita/blob/master/docker-compose.yml

GO_VER="${go_ver:-1.20.5}"                                                             # Replace this variable when latest binary release is available: https://go.dev/doc/install
GO_BIN=''                                                                              # Leave blank
GO_HASH=''                                                                             # Leave blank

BETTERCAP_BIN=''                                                                       # Leave blank
BETTERCAP_VER="${bettercap_ver:-2.31.1}"                                               # Replace this variable when latest binary release is available: https://github.com/bettercap/bettercap/releases/
BETTERCAP_HASH=''                                                                      # Leave blank

HTTP_CONF='/usr/local/share/bettercap/caplets/http-ui.cap'                             # Default path to http(s) conf files that contain credentials
HTTPS_CONF='/usr/local/share/bettercap/caplets/https-ui.cap'                           # Default path to http(s) conf files that contain credentials

# Arch Check
if (dpkg --print-architecture | grep -qx 'amd64'); then
    ARCH='amd64'
    BETTERCAP_BIN="bettercap_linux_amd64_v$BETTERCAP_VER"
    BETTERCAP_HASH='74e85473d8cbeaa79b3c636032cbd0967387c4e9f95e253b4ae105eccd208a4f'
    GO_BIN="go$GO_VER.linux-amd64.tar.gz"
    GO_HASH='d7ec48cde0d3d2be2c69203bc3e0a44de8660b9c09a6e85c4732a3f7dc442612'                # Use the amd64 binary
elif (dpkg --print-architecture | grep -qx 'arm64'); then
    ARCH='arm64'
    BETTERCAP_BIN="bettercap_linux_aarch64_v$BETTERCAP_VER"
    BETTERCAP_HASH='a278b191f7d36419d390dfca4af651daf1e9f1c7900ec1b3f627ab6c2f7b57e2'
    GO_BIN="go$GO_VER.linux-arm64.tar.gz"
    GO_HASH='aa2fab0a7da20213ff975fa7876a66d47b48351558d98851b87d1cfef4360d09'                # Use the arm64 binary
else
    echo "${BOLD}[i]Currently supported architectures: x86_64 (amd64), aarch64 (arm64)${RESET}" && exit 1
fi


#===============================
# Installers and Setup Functions
#===============================


function IsRoot() {
	# Root EUID check
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function CheckOS() {
	# Check OS version
	OS="$(grep -E "^ID=" /etc/os-release | cut -d '=' -f 2)"
	CODENAME="$(grep VERSION_CODENAME /etc/os-release | cut -d '=' -f 2)" # debian or ubuntu
	echo -e "${BLUE}[i]${RESET}$OS ${GREEN}$CODENAME${RESET} detected."
	if [[ $OS == "ubuntu" ]]; then
		UBUNTU_VERSION=$(grep VERSION_ID /etc/os-release | cut -d '"' -f2)
		MAJOR_UBUNTU_VERSION=$(grep VERSION_ID /etc/os-release | cut -d '"' -f2 | cut -d '.' -f 1)
		if [[ $MAJOR_UBUNTU_VERSION -lt 18 ]]; then
			echo "⚠️ Your version of Ubuntu is not supported."
			echo ""
			echo "18.04 or greater is required to run RITA + MongoDB + Zeek."
			echo ""
			until [[ $CONTINUE =~ ^(y|n)$ ]]; do
				read -rp "Continue? [y/n]: " -e CONTINUE
			done
			if [[ $CONTINUE == "n" ]]; then
				exit 1
			fi
		fi
	elif [[ $OS == "kali" ]]; then
		echo -e "[${YELLOW}i${RESET}]Kali support is currently in development. ${YELLOW}Not all features will work as expected.${RESET}"
		echo ""
#		until [[ $CONTINUE =~ ^(y|n)$ ]]; do
#			read -rp "Continue? [y/n]: " -e CONTINUE
#		done
#		if [[ $CONTINUE == "n" ]]; then
			exit 1
#		fi
	fi
}

function CheckInterface() {

    PUB_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
    echo -e ""
    echo -e "Is ${BOLD}$PUB_NIC${RESET} the correct capture interface?"
    echo -e "Enter the correct interface if not."
    echo -e ""
    until [[ ${CAPTURE_IFACE} =~ ^[a-zA-Z0-9_]+$ ]]; do
        read -rp "Capture interface: " -e -i "${PUB_NIC}" CAPTURE_IFACE
    done
    echo -e "${BLUE}[i]${RESET}Using: ${BOLD}$CAPTURE_IFACE${RESET}"
    
    sleep 2

}

function MakeTemp() {

    # Make a temporary working directory
#    if [ -d /tmp/antidote/ ]; then
#        rm -rf /tmp/antidote
#    fi

    if ! [ -d /tmp/antidote ]; then
        mkdir /tmp/antidote
    fi

    SETUPDIR=/tmp/antidote
    export SETUPDIR

    cd "$SETUPDIR" || (echo "Failed changing into setup directory. Quitting." && exit 1)
    echo -e "${BLUE}[*]Changing working directory to $SETUPDIR${RESET}"

}

function InstallEssentialPackages() {
    echo -e "${BLUE}[*]Installing essential packages from apt-get...${RESET}"
    apt install -y ca-certificates curl git gnupg lsb-release libpcap0.8 libusb-1.0-0 libnetfilter-queue1 unzip wget
    echo -e "${BLUE}[✓]Done.${RESET}"
    sleep 2
}

function InstallDocker() {

    # For changes, check the following link:
    # https://docs.docker.com/engine/install/
    # https://docs.docker.com/engine/install/ubuntu/

    echo -e "${BLUE}[>]Installing Docker from download.docker.com...${RESET}"

    if ! [ -e /etc/apt/keyrings/docker.gpg ]; then

        apt-get install -y ca-certificates curl gnupg lsb-release

        curl -fsSL 'https://download.docker.com/linux/ubuntu/gpg' > "$SETUPDIR"/docker-archive-keyring.gpg

        # We're only using apt-key to read the key fingerprint, nothing else
        apt-key adv --with-fingerprint --keyid-format long "$SETUPDIR"/docker-archive-keyring.gpg 2>/dev/null| grep -P "9DC8\s?5822\s?9FC7\s?DD38\s?854A\s?\s?E2D8\s?8D81\s?803C\s?0EBF\s?CD88"

        # User to manually compare keyid's
        # If the key changes, review the following link for references to the new key:
        # https://keyserver.ubuntu.com/pks/lookup?search=9DC858229FC7DD38854AE2D88D81803C0EBFCD88&fingerprint=on&op=index
        echo -e ""
        echo -e " Expected fingerprint = ${BOLD}9DC8 5822 9FC7 DD38 854A  E2D8 8D81 803C 0EBF CD88${RESET}"
        until [[ ${DOCKER_SIG_OK} =~ ^(y|n)$ ]]; do
        read -rp "Do they match? [y/n]: " -e DOCKER_SIG_OK
        done
        if [[ "$DOCKER_SIG_OK" == "n" ]]; then
        echo "Quitting..."
        exit 1
        fi

        sudo mkdir -p /etc/apt/keyrings

        gpg --dearmor < "$SETUPDIR"/docker-archive-keyring.gpg | tee /etc/apt/keyrings/docker.gpg > /dev/null
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    fi

    if ! (command -v docker > /dev/null); then
        apt-get update
        # Allow user to confirm
        apt-get install docker-ce docker-ce-cli containerd.io
    fi
    
    if ! (systemctl is-active docker); then
        sleep 5
        systemctl restart docker
    fi

    if (command -v docker > /dev/null); then
        echo -e "${BLUE}[*]Getting docker version information...${RESET}"
        sleep 1
        docker version
        echo -e "${BLUE}[✓]docker installed.${RESET}"
    else
        echo "No version detected, quitting..."
        exit 1
    fi

}

function InstallMongoDBFromApt() {

    # Install MongoDB manually (requires v4.2):
    # https://docs.mongodb.com/v4.2/installation/

    # REMINDER: MongoDB v4.2 only works up to version 18.04 LTS on Ubuntu
    # https://docs.mongodb.com/v4.2/administration/production-notes/#prod-notes-supported-platforms-arm64

    echo -e "${BLUE}[>]Installing MongoDB from repo.mongodb.org...${RESET}"

    if ! [ -e /etc/apt/sources.list.d/mongodb-org-4.2.list ]; then
        curl -fsSLO https://www.mongodb.org/static/pgp/server-4.2.asc

        apt-key adv --with-fingerprint --keyid-format long "$SETUPDIR/server-4.2.asc" 2>/dev/null | grep 'E162 F504 A20C DF15 827F  718D 4B7C 549A 058F 8B6B'

        # User to manually compare keyid's
        # If the key changes, review the following link for references to the new key:
        # https://keyserver.ubuntu.com/pks/lookup?search=E162F504A20CDF15827F718D4B7C549A058F8B6B&fingerprint=on&op=index
        echo ""
        echo -e " Expected fingerprint = ${BOLD}E162 F504 A20C DF15 827F  718D 4B7C 549A 058F 8B6B${RESET}"
        until [[ ${MONGO_SIG_OK} =~ ^(y|n)$ ]]; do
        read -rp "Do they match? [y/n]: " -e MONGO_SIG_OK
        done
        if [[ "$MONGO_SIG_OK" == "n" ]]; then
            echo "Quitting..."
            exit 1
        fi

        apt-key add "$SETUPDIR"/server-4.2.asc

        echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.2 multiverse" | tee /etc/apt/sources.list.d/mongodb-org-4.2.list > /dev/null
    fi

    apt-get update
    # Allow user to confirm
    apt-get install mongodb-org

    # Potentially hold package versions back?
    # https://docs.mongodb.com/v4.2/tutorial/install-mongodb-on-ubuntu/#install-the-mongodb-packages

    systemctl start mongod

    if [ "$?" -ne "0" ]; then
        systemctl daemon-reload
    fi

    # Ensure MongoDB is running
    if ! (systemctl is-active mongod); then
        systemctl unmask mongod
        systemctl enable mongod
        systemctl restart mongod
    fi

    echo -e "${BLUE}[✓]MongoDB installed and running.${RESET}"

}

function InstallZeekFromApt() {

    echo -e "${BLUE}[>]Installing zeek dependancies via apt-get...${RESET}"
    
    apt-get update
    # https://docs.zeek.org/en/v4.1.1/install.html
    apt-get -y install python3-git python3-semantic-version

    echo -e "${BLUE}[>]Installing zeek from download.opensuse.org via apt-get...${RESET}"

    ZEEK_PATH="${zeek_path:-/opt/zeek}"

    if ! [ -e /etc/apt/trusted.gpg.d/security_zeek.gpg ]; then
        # Check both of the following links for latest instructions on adding the repo:
        # https://github.com/zeek/zeek-docs/blob/master/install.rst#binary-packages
        # https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek
        # Check here when the key signature changes for reference to the new key:
        # https://keyserver.ubuntu.com/pks/lookup?search=E9690B2B7D8AC1A19F921C4AC68B494DF56ACC7E&fingerprint=on&op=index
        curl -fsSL "https://download.opensuse.org/repositories/security:zeek/xUbuntu_$UBUNTU_VERSION/Release.key" > "$SETUPDIR/zeek-release.key"

        apt-key adv --with-fingerprint --keyid-format long "$SETUPDIR"/zeek-release.key 2>/dev/null | grep 'AAF3 EB04 4C49 C402 A9E7  B9AE 69D1 B2AA EE3D 166A'

        # User to manually compare keyid's
        echo ""
        echo -e " Expected fingerprint = ${BOLD}AAF3 EB04 4C49 C402 A9E7  B9AE 69D1 B2AA EE3D 166A${RESET}"
        echo "NOTE: this key is different from the key used to verify the source tar archives."
        until [[ ${ZEEK_SIG_OK} =~ ^(y|n)$ ]]; do
        read -rp "Do they match? [y/n]: " -e ZEEK_SIG_OK
        done
        if [[ "$ZEEK_SIG_OK" == "n" ]]; then
            echo "Quitting..."
            exit 1
        fi

        # If keyid OK add it to apt sources
        echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_$UBUNTU_VERSION/ /" | tee /etc/apt/sources.list.d/security:zeek.list > /dev/null
        gpg --dearmor < "$SETUPDIR"/zeek-release.key | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
    fi

    apt-get update
    apt-get install -y zeek

    # Check to see if Zeek install was canceled
    if ! [ -e /opt/zeek/bin/zeek ]; then
        exit 1
    fi

}

function InstallZeekFromSource() {
    # NOTE: this function is not yet used, and is only here for information

    echo -e "${BLUE}[>]${RESET}Installing Zeek via source (GitHub)..."

    ZEEK_PATH="${zeek_path:-/usr/local/zeek}"

    # https://docs.zeek.org/en/v4.1.1/install.html#installing-from-source

    # Optional dependancies:
    # * libmaxminddb (for geolocating IP addresses)
    # * sendmail (enables Zeek and ZeekControl to send mail)
    # * curl (used by a Zeek script that implements active HTTP)
    # * gperftools (tcmalloc is used to improve memory and CPU usage)
    # * jemalloc (https://github.com/jemalloc/jemalloc)
    # * PF_RING (Linux only, see PF_RING Cluster Configuration)
    # * krb5 libraries and headers
    # * ipsumdump (for trace-summary; https://github.com/kohler/ipsumdump)

    # Download latest release + signature
    cd ~/Documents || exit 2
    curl -LfO https://github.com/zeek/zeek/releases/download/v"$ZEEK_VER"/zeek-"$ZEEK_VER".tar.gz && \
    curl -LfO https://github.com/zeek/zeek/releases/download/v"$ZEEK_VER"/zeek-"$ZEEK_VER".tar.gz.asc

    echo -e "${BLUE}[*]${RESET}Checking signature..."

    gpg --keyid-format long --keyserver hkps://keyserver.ubuntu.com:443 --recv-keys "$ZEEK_GPG"
    gpg --verify --keyid-format long zeek-"$ZEEK_VER".tar.gz.asc zeek-"$ZEEK_VER".tar.gz

    # User to manually compare keyid's
    echo ""
    echo "NOTE: this key is different from the release key used to install zeek from apt-get."
    echo ""
    until [[ ${ZEEK_SIG_OK} =~ ^(y|n)$ ]]; do
        read -rp "Do they match? [y/n]: " -e ZEEK_SIG_OK
    done
    if [[ "$ZEEK_SIG_OK" == "n" ]]; then
        echo "Quitting..."
        exit 1
    fi

    sleep 2

    echo -e "${BLUE}[*]${RESET}Installing dependancies..."

    # Need to check if these are required when building from source...
    apt-get install python3-git python3-semantic-version

    # Required dependancies
    apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python3 python3-dev swig zlib1g-dev

    sleep 2

    echo -e "${BLUE}[*]${RESET}Unpacking archive..."

    # Unpack the archive
    tar -xzvf zeek-"$ZEEK_VER".tar.gz
    sleep 2
    cd zeek-"$ZEEK_VER"/ || exit 1

    # NOTE: `make` takes a very long time on Raspberry Pi
    # Use https://github.com/activecm/docker-zeek which is precompiled for arm64 and ready to go in seconds.

    # Otherwise, cross-compiling requires pre-built dependancies from the target system already available...
    # https://docs.zeek.org/en/v4.1.1/install.html#id3

    echo -e "${BLUE}[*]${RESET}Running ./configure..."
    # ./configure --help
    ./configure

    sleep 2

    echo -e "${BLUE}[*]${RESET}Running make..."
    make

    sleep 2

    echo -e "${BLUE}[*]${RESET}Running make install..."
    make install

    sleep 2

    echo -e "${BLUE}[*]${RESET}Adding Zeek binaries to system PATH..."

    # Add zeek binaries to PATH for this script to use:
    export PATH="$ZEEK_PATH"/bin:$PATH

    # Add Zeek to PATH
    {
    echo ""
    echo "# set PATH so it includes user's zeek installation if it exists"
    echo "if [ -d $ZEEK_PATH ] ; then"
    echo "    PATH=\"$ZEEK_PATH/bin:$PATH\""
    echo "fi"
    } >> /etc/profile.d/zeek-path.sh

    # Make Zeek binaries available to sudo's PATH:
    # Need a better way to do this...
    if ! (grep -q '^Defaults[[:space:]]secure_path=.*/usr/local/zeek/bin:.*"'  '/etc/sudoers'); then
        sed -i 's/\(^Defaults[[:space:]]secure_path=.*\)"/\1:\/usr\/local\/zeek\/bin"/' '/etc/sudoers'
    fi

}

function InstallZeekFromDocker() {

    echo -e "${BLUE}[>]Installing docker-zeek using the activecm management script...${RESET}"

    ZEEK_PATH="${zeek_path:-/opt/zeek/}"

    # Download the management script and move it to /usr/local/bin/zeek
    if ! [ -e /usr/local/bin/zeek ]; then
        curl -Lf 'https://raw.githubusercontent.com/activecm/docker-zeek/master/zeek' > zeek
        echo -e "${BLUE}[*]Checking sha256sum...${RESET}"
        if ! (sha256sum "$SETUPDIR/zeek" | grep -x  "$ZEEK_DOCKER_HASH  $SETUPDIR/zeek"); then
            echo -e "${RED}[i]Bad checksum. Quitting.${RESET}"
            exit 1
        else
            echo -e "${GREEN}OK${RESET}"
        fi
    fi
    for installer in "$SETUPDIR"/zeek; do
        chown root:root "$installer"
        chmod 755 "$installer"
        mv "$installer" /usr/local/bin

        mkdir -p /opt/zeek/etc
    done

    # Pull the docker image
    docker pull "activecm/zeek:${zeek_release:-4.2.0}"

}

function AddZeekToPath() {
    # APT
    if [ -e "$ZEEK_PATH"/bin/zeek ] && ! (grep -q 'zeek' '/etc/profile.d/zeek-path.sh'); then
        # Add Zeek to PATH
        {
        echo ""
        echo "# set PATH so it includes user's zeek installation if it exists"
        echo "if [ -d $ZEEK_PATH ] ; then"
        echo "    PATH=\"$ZEEK_PATH/bin:$PATH\""
        echo "fi"
        } > /etc/profile.d/zeek-path.sh
    fi
    # DOCKER
    # https://github.com/activecm/docker-zeek#zeek-version
    if [ -e '/usr/local/bin/zeek' ]; then
        echo "export zeek_release=latest" | tee /etc/profile.d/zeek.sh
        source /etc/profile.d/zeek.sh
    fi
}

function InstallNodeCfgScript() {

	if ! [ -e "$ZEEK_PATH"/share/zeek-cfg ]; then
		mkdir -p "$ZEEK_PATH"/share/zeek-cfg
	fi

	if ! [ -e "$ZEEK_PATH"/share/zeek-cfg/gen-node-cfg.sh ]; then
		echo -e "${BLUE}[*]Downloading gen-node-cfg.sh...${RESET}"
		curl -sSL "https://raw.githubusercontent.com/activecm/bro-install/master/gen-node-cfg.sh" -o "$SETUPDIR/gen-node-cfg.sh"

		echo -e "${BLUE}[*]Checking sha256sum...${RESET}"
		if ! (sha256sum "$SETUPDIR/gen-node-cfg.sh" | grep -x "$ZEEK_GEN_CFG_HASH  $SETUPDIR/gen-node-cfg.sh"); then
			echo "${RED}[i]Bad checksum, quitting...${RESET}"
			exit 1
		else
			echo -e "${GREEN}OK${RESET}"
			echo -e "${YELLOW}[*]Moving $SETUPDIR/gen-node-cfg.sh    ->  $ZEEK_PATH/share/zeek-cfg/gen-node-cfg.sh${RESET}"
			chmod 755 "$SETUPDIR"/gen-node-cfg.sh
			mv "$SETUPDIR"/gen-node-cfg.sh "$ZEEK_PATH"/share/zeek-cfg/gen-node-cfg.sh
		fi
	fi
	if ! [ -e "$ZEEK_PATH"/share/zeek-cfg/node.cfg-template ]; then
		echo -e "${BLUE}[*]Downloading node.cfg-template...${RESET}"
		curl -sSL "https://raw.githubusercontent.com/activecm/bro-install/master/node.cfg-template" -o "$SETUPDIR/node.cfg-template"

		echo -e "${BLUE}[*]Checking sha256sum...${RESET}"
		if ! (sha256sum "$SETUPDIR/node.cfg-template" | grep -x "$ZEEK_NODE_CFG_HASH  $SETUPDIR/node.cfg-template"); then
			echo "${RED}[i]Bad checksum, quitting...${RESET}"
			exit 1
		else
			echo -e "${GREEN}OK${RESET}"
			echo -e "${YELLOW}[*]Moving $SETUPDIR/node.cfg-template  ->  $ZEEK_PATH/share/zeek-cfg/node.cfg-template${RESET}"
			chmod 644 "$SETUPDIR"/node.cfg-template
			mv "$SETUPDIR"/node.cfg-template "$ZEEK_PATH"/share/zeek-cfg/node.cfg-template
		fi
	fi

}

function ConfigureNode() {
    # APT & DOCKER
    # Attempt to detect if Zeek is already configured away from it's defaults
    # Taken directly from: https://github.com/activecm/rita/blob/4a4b6394a6fb2619ba91e0112e94a54f0653808a/install.sh#L317
#    if ! (grep -q '^type=worker' "$ZEEK_PATH/etc/node.cfg") ; then
 
    "$ZEEK_PATH"/share/zeek-cfg/gen-node-cfg.sh
}

function InstallZkgPackages() {
    # APT
    if [[ -e "$ZEEK_PATH"/bin/zeek ]]; then
        # Edit $ZEEK_PATH/site/local.zeek file so that it contains the following line
        if ! (grep -qx "^@load packages$" "$ZEEK_PATH"/share/zeek/site/local.zeek); then
            sed -i 's/^.*@load packages.*$/@load packages/' "$ZEEK_PATH"/share/zeek/site/local.zeek
        fi

        # Install zeek-open-connections plugin for monitoring long-running, open connections
        if ! ("$ZEEK_PATH"/bin/zkg list installed | grep -q 'zeek/activecm/zeek-open-connections'); then
            echo -e "${BLUE}[*]Refreshing zkg packages...${RESET}"
            "$ZEEK_PATH"/bin/zkg refresh
            echo -e "${BLUE}[*]Installing zeek-open-connections...${RESET}"
            "$ZEEK_PATH"/bin/zkg install zeek/activecm/zeek-open-connections
        fi
    #DOCKER
    elif [[ -e '/usr/local/bin/zeek' ]]; then
        # To install the plugin for open or long-running connections:
        # https://github.com/activecm/docker-zeek#install-a-plugin
        if ! (docker exec -it zeek zkg list installed | grep -q 'zeek/activecm/zeek-open-connections'); then
            echo -e "${BLUE}[*]Refreshing zkg packages...${RESET}"
            docker exec -it zeek zkg refresh
            echo -e "${BLUE}[*]Installing zeek-open-connections...${RESET}"
            docker exec -it zeek zkg install zeek/activecm/zeek-open-connections
        fi
    fi
}

function StartZeek() {
    # APT
    if [[ -e "$ZEEK_PATH"/bin/zeek ]]; then
        # Check the configuration
        "$ZEEK_PATH"/bin/zeekctl check
        # Deploy the configuration
        "$ZEEK_PATH"/bin/zeekctl deploy

        sleep 2
        # Print status
        echo -e "${BLUE}[*]Getting Zeekctl status...${RESET}"
        "$ZEEK_PATH"/bin/zeekctl status
        if [ "$?" -eq "0" ]; then
            echo -e "${BLUE}[✓]Zeek installed and running.${RESET}"
        else
            echo -e "${RED}[i]Error getting Zeek status, quitting...${RESET}"
            exit 1
        fi
    # DOCKER
    elif [[ -e '/usr/local/bin/zeek' ]]; then
        sleep 2
        /usr/local/bin/zeek start
        sleep 2
        # Print status
        echo -e "${BLUE}[*]Getting Zeekctl status...${RESET}"
        /usr/local/bin/zeek status
        if [ "$?" -eq "0" ]; then
            sleep 2
            echo -e "${BLUE}[✓]Docker-Zeek installed and running.${RESET}"
        else
            echo -e "${RED}[i]Error getting Docker-Zeek status, quitting...${RESET}"
            exit 1
        fi
    fi
}

function ConfigureZeek() {

	# https://docs.zeek.org/en/v4.1.1/quickstart.html

	AddZeekToPath

	InstallNodeCfgScript

	until [[ $CONFIGURE_NODE_CHOICE =~ ^(y|n)$ ]]; do
		read -rp "Run Zeek node configuration script? (It's the same one RITA uses) [y/n]: " -e CONFIGURE_NODE_CHOICE
	done
	if [[ "$CONFIGURE_NODE_CHOICE" == "y" ]]; then
		ConfigureNode
	fi

	InstallZkgPackages

	echo -e "[*]Getting Zeek status..."

	if [[ -e "$ZEEK_PATH"/bin/zeek ]]; then
		"$ZEEK_PATH"/bin/zeekctl status
	# DOCKER
	elif [[ -e '/usr/local/bin/zeek' ]]; then
		/usr/local/bin/zeek status
	fi

	until [[ $START_ZEEK_CHOICE =~ ^(y|n)$ ]]; do
		read -rp "Restart Zeek now? [y/n]: " -e START_ZEEK_CHOICE
	done
	if [[ "$START_ZEEK_CHOICE" == "y" ]]; then
		StartZeek
	fi
}

function InstallRITAFromScript() {

    echo -e "${BLUE}[>]Installing RITA via installer script...${RESET}"

    curl -Lf 'https://raw.githubusercontent.com/activecm/rita/v'"$RITA_VER"'/install.sh' > rita-installer.sh && \
    echo -e "${BLUE}[*]Checking sha256sum...${RESET}"
    if ! (sha256sum "$SETUPDIR/rita-installer.sh" | grep -x  "$RITA_HASH  $SETUPDIR/rita-installer.sh"); then
        echo -e "${RED}[i]Bad checksum. Quitting.${RESET}"
        exit 1
    else
        echo -e "${GREEN}OK${RESET}"
    fi
    for installer in "$(pwd)"/rita-installer.sh; do 
        chown root:root "$installer"
        chmod 755 "$installer"
        sleep 2
        "$installer" --disable-zeek
        sleep 2
    done

    if (command -v rita > /dev/null); then
        rita test-config
        echo -e "${BLUE}[✓]Rita installed.${RESET}"
    else
        echo -e "${RED}[i]Error in /etc/rita/config.yaml, quitting...${RESET}"
        exit 1
    fi

}

function InstallRITAFromSource() {

    echo -e "${BLUE}[*]Installing RITA from source...${RESET}"
    sleep 1
    echo -e "${BLUE}[*]Downloading go from https://go.dev/dl/...${RESET}"
    
    # https://github.com/activecm/rita/blob/master/docs/Manual%20Installation.md

    ## Install go and add to PATH

    # Using the apt version (not recommended):
#    apt-get install -y golang-"$GO_VER"

    # or

    # https://go.dev/doc/install (previously https://golang.org/doc/install)
    curl -LfO "https://go.dev/dl/$GO_BIN" && \

    echo -e "${BLUE}[*]Checking sha256sum...${RESET}"
    if ! (sha256sum "$SETUPDIR/$GO_BIN" | grep -x "$GO_HASH  $SETUPDIR/$GO_BIN"); then
        echo -e "${RED}[i]Bad checksum. Quitting.${RESET}"
        exit 1
    else
        echo -e "${GREEN}OK${RESET}"
    fi

    # Remove any previous installations
    if [ -e /usr/local/go ]; then
        rm -rf /usr/local/go
    fi

    # Add go binary to PATH
    echo -e "${BLUE}[*]Unpacking archive and adding go to PATH...${RESET}"
    sleep 2
    tar -C /usr/local -xzf "$SETUPDIR/$GO_BIN"

    {
    echo ''
    echo '# set PATH so it includes go installation if it exists'
    echo 'if [ -d "/usr/local/go" ] ; then'
    echo '    PATH="$PATH:/usr/local/go/bin"'
    echo 'fi' 
    } >> /etc/profile.d/go-path.sh
    
    source /etc/profile.d/go-path.sh

    # Don't want to always script this, give user the option
    echo -e "${YELLOW}[i]Use 'sudo visudo' to add '/usr/local/go/bin:' to the 'secure_path=...' variable${RESET}"

    sleep 3

    export PATH=$PATH:/usr/local/go/bin

    # Ensure PATH exported correctly for script
    if (go version); then
        echo -e "${BLUE}[✓]go installed successfully.${RESET}"
        sleep 2
    else
        echo -e "${RED}[i]go binary not found, quitting...${RESET}"
        exit 1
    fi

    # Ensure make is installed to build RITA
    echo -e "${BLUE}[*]Ensuring make is installed to build RITA...${RESET}"
    apt-get -y install make
    sleep 2

    # Clone RITA from GitHub
    echo -e "${BLUE}[*]Cloning RITA source from GitHub...${RESET}"
    git clone 'https://github.com/activecm/rita.git'
    cd rita || exit 1

    echo -e "${BLUE}[*]Building and installing RITA...${RESET}"
    sleep 2

    # this yields a rita binary in cwd
    if ! (make); then
        echo -e "${RED}[i]Issue running 'make'. Quitting.${RESET}"
        exit 1
    fi

    # to install the binary to /usr/local/bin/rita
    if ! (make install); then
        echo -e "${RED}[i]Issue running 'make install'. Quitting.${RESET}"
        exit 1
    fi

    echo -e "${BLUE}[✓]Done.${RESET}"
    sleep 3

    # RITA requires a few directories to be created for it to function correctly.
    # https://github.com/activecm/rita/blob/master/docs/Manual%20Installation.md#configuring-the-system
    echo -e "${BLUE}[*]Creating necessary directories...${RESET}"
    sleep 2

    mkdir /etc/rita && chmod 755 /etc/rita
    mkdir -p /var/lib/rita/logs && chmod -R 755 /var/lib/rita
    cp ./etc/rita.yaml /etc/rita/config.yaml && chmod 644 /etc/rita/config.yaml

    # modify the config file as needed and test using the rita test-config command
    if (command -v rita > /dev/null); then
        echo -e "${BLUE}[*]Testing RITA configuration...${RESET}"
        sleep 2
        rita test-config
        sleep 1
        echo -e "${BLUE}[✓]Done.${RESET}"
        sleep 1
        rita --version
        echo -e "${BLUE}[✓]Rita installed.${RESET}"
    else
        echo -e "${RED}[i]Error in /etc/rita/config.yaml, quitting...${RESET}"
        exit 1
    fi


}

function InstallRITAFromDocker() {

    if ! (docker image list | grep -iq rita); then

        echo -e "${BLUE}[*]Installing RITA via docker...${RESET}"

        # Check for Zeek PATH
        if [ -e /opt/zeek ]; then
        ZEEK_PATH=/opt/zeek
        elif [ -e /usr/local/zeek ]; then
        ZEEK_PATH=/usr/local/zeek
        else
            echo "No known PATH for Zeek exists."
            echo "Where should the LOGS variable in /etc/rita/rita.env point to?"
            echo "Note: only use [a-zA-Z0-9_-] in the PATH"

            until [[ $SET_ZEEK_PATH =~ ^(/[a-zA-Z0-9_-]+){1,}$ ]]; do
                read -rp "Path to Zeek logs: " SET_ZEEK_PATH
            done
            ZEEK_PATH="$SET_ZEEK_PATH"
            echo "ZEEK_PATH=$ZEEK_PATH"
            echo ""
            echo -e "${BOLD}[i]Change this value later in ${YELLOW}/etc/rita/rita.env${RESET}"
        fi

        # https://github.com/activecm/rita/blob/master/docs/Docker%20Usage.md

        docker pull quay.io/activecm/rita
        
        # Make a working directory for the configuration as well as docker compose files
        mkdir /etc/rita

        echo "CONFIG=/etc/rita/config.yaml
VERSION=v$RITA_VER
LOGS=$ZEEK_PATH/logs/current" > /etc/rita/rita.env

        echo -e ""
        echo -e "[${BLUE}i${RESET}]LOG variable set to ${YELLOW}$ZEEK_PATH/logs/current${RESET}"
        echo -e ""
        echo -e "${BOLD}   This variable must be an exact log path, such as ${YELLOW}/opt/zeek/logs/yyyy-mm-dd${BOLD} or ${YELLOW}/opt/zeek/logs/current${RESET}"
        echo -e "${BOLD}   and is then called from the CLI as ${YELLOW}/logs${RESET}"
        echo -e ""
        echo -e "[${BLUE}i${RESET}]$ZEEK_PATH/logs/current works well for scheduled cron jobs."
        echo -e "${BOLD}See: https://github.com/activecm/rita/blob/master/docs/Rolling%20Datasets.md for more details${RESET}"
        echo -e ""
        sleep 2
    fi
    if ! [[ -e '/etc/rita/config.yaml' && -e '/etc/rita/docker-compose.yml' ]]; then
        curl -fsSL 'https://raw.githubusercontent.com/activecm/rita/master/etc/rita.yaml' > /etc/rita/config.yaml
        curl -fsSL 'https://raw.githubusercontent.com/activecm/rita/master/docker-compose.yml' > /etc/rita/docker-compose.yml
        
        echo -e "${BLUE}[*]Checking sha256sum...${RESET}"
        if ! (sha256sum /etc/rita/config.yaml | grep -x  "$RITA_CONF_HASH  /etc/rita/config.yaml"); then
            echo -e "${RED}[i]Bad checksum. Quitting.${RESET}"
            exit 1
        else
            echo -e "${GREEN}OK${RESET}"
        fi
        if ! (sha256sum /etc/rita/docker-compose.yml | grep -x  "$RITA_COMPOSE_HASH  /etc/rita/docker-compose.yml"); then
            echo -e "${RED}[i]Bad checksum. Quitting.${RESET}"
            exit 1
        else
            echo -e "${GREEN}OK${RESET}"
        fi
    fi

    # This needs to run twice initially with Docker for some reason
    if ! (docker compose -f /etc/rita/docker-compose.yml --env-file /etc/rita/rita.env run --rm rita --version); then
        if ! (docker compose -f /etc/rita/docker-compose.yml --env-file /etc/rita/rita.env run --rm rita --version); then
            echo -e "[${YELLOW}i${RESET}]Cannot obtain rita --verison information..."
            echo -e ""
            echo -e "${BOLD}TEST RITA WITH THE FOLLOWING:${RESET}"
            echo -e ""
            echo -e "${YELLOW}sudo docker compose -f /etc/rita/docker-compose.yml --env-file /etc/rita/rita.env run --rm rita --version${RESET}"
            echo -e "${YELLOW}sudo docker compose -f /etc/rita/docker-compose.yml --env-file /etc/rita/rita.env run --rm rita test-config${RESET}"
        fi
    fi

    # Examples
    echo -e ""
    echo -e "${BOLD}EXAMPLE USAGE:${RESET}"
    echo -e ""
    echo -e "Import a directory of *.gz or *.log Zeek log files to databse db_1:"
    echo -e "${YELLOW}sudo su${RESET}"
    echo -e "${YELLOW}export LOGS=/path/to/logs/YYYY-MM-DD${RESET}"
    echo -e "${YELLOW}docker compose -f /etc/rita/docker-compose.yml --env-file /etc/rita/rita.env run --rm rita import /logs db_1${RESET}"
    echo -e ""
    echo -e "Import multiple diretories of *.gz or *.log Zeek log files to database db_1:"
    echo -e "For example, if all of the log folders are named 'fedora-YYYYmmdd-HHMMSS', use 'for logs in /path/to/logs/fedora-*'"
    echo -e "${YELLOW}sudo su${RESET}"
    echo -e "${YELLOW}for logs in /path/to/logs/folder*; do export LOGS=\"\$logs\"; docker compose -f /etc/rita/docker-compose.yml --env-file /etc/rita/rita.env run --rm rita import --rolling /logs db_1; done${RESET}"
    sleep 5
}

function BettercapUIStatus() {
    if [ -e /usr/local/share/bettercap/caplets/http-ui.cap ]; then
        echo ""
        echo "=====================[ Web UI Credentials ]========================="
        echo -e "    ${BOLD}[http]username: $(grep 'api.rest.username' /usr/local/share/bettercap/caplets/http-ui.cap | cut -d ' ' -f 3)${RESET}"
        echo -e "    ${BOLD}[http]password: $(grep 'api.rest.password' /usr/local/share/bettercap/caplets/http-ui.cap | cut -d ' ' -f 3)${RESET}"
        echo ""
        echo -e "    ${BOLD}[https]username: $(grep 'api.rest.username' /usr/local/share/bettercap/caplets/https-ui.cap | cut -d ' ' -f 3)${RESET}"
        echo -e "    ${BOLD}[https]password: $(grep 'api.rest.password' /usr/local/share/bettercap/caplets/https-ui.cap | cut -d ' ' -f 3)${RESET}"
	echo "===================================================================="
        echo ""
    fi
}

function UpdateCaplets() {

    # Update caplets and web-ui
    echo ""
    echo -e "${BLUE}[*]Updating bettercap resources...${RESET}"
    bettercap -eval "caplets.update; ui.update; q" || (echo "Error updating bettercap resources. Quitting." && exit 1)

    sleep 2

}

function InstallBettercapFromRelease() {

    echo -e "${BLUE}[*]Installing bettercap from GitHub release...${RESET}"
 

    # Install bettercap pre-compiled binary from GitHub
    # Check for the latest version: https://github.com/bettercap/bettercap/releases/latest
 
    curl -fsSL 'https://github.com/bettercap/bettercap/releases/download/v'"$BETTERCAP_VER"'/'"$BETTERCAP_BIN"'.sha256' > "$SETUPDIR"/"$BETTERCAP_BIN"'.sha256'
    curl -fsSL 'https://github.com/bettercap/bettercap/releases/download/v'"$BETTERCAP_VER"'/'"$BETTERCAP_BIN"'.zip' > "$SETUPDIR"/"$BETTERCAP_BIN"'.zip'

    echo -e "${BLUE}[*]Extracting bettercap binary from archive...${RESET}"
    unzip "$SETUPDIR/$BETTERCAP_BIN".zip 'bettercap'

    sleep 1

    echo ""
    echo -e "${BLUE}[*]Checking sha256sum...${RESET}"
    # Check against known hash
    if ! (grep -xE "SHA256\(bettercap\)= $BETTERCAP_HASH" "$SETUPDIR/$BETTERCAP_BIN".sha256); then
        echo "${RED}Bad checksum, quitting...${RESET}"
        exit 1
    fi
    # Check against downloaded hash
    if ! (sha256sum -c "$SETUPDIR/$BETTERCAP_BIN".sha256); then
        echo "${RED}Bad checksum, quitting...${RESET}"
        exit 1
    fi
    # If 'bettercap: OK' add it to your path, otherwise exit, leaving the binary behind in $SETUPDIR to examine.

    sleep 2

    echo -e "${BLUE}[*]Installing bettercap...${RESET}"
    chmod 755 ./bettercap
    chown root:root ./bettercap
    mv ./bettercap -t /usr/local/bin/

    if (command -v bettercap > /dev/null); then
        echo -e "${BLUE}[✓]Bettercap installed.${RESET}"
    else
        echo "${BLUE}Bettercap not found in PATH. Quitting...${RESET}"
        exit 1
    fi

    # Perform error checks (will need tested as conditional statements here)
    # Tested on 10/22/21; no issues as of Ubuntu 18.04.6 LTS release, desktop-amd64, server-amd64, and server-arm64(raspberry pi 4B, 8GB)

    ## If you see 'libpcap.so.1 library is not available' you'll need to symbolicly link libpcacp.so to libpcacp.so.1.
    ## Additional packages required to resolve error:
    #sudo apt install -y libpcap-dev net-tools
    #find / -type f -name "libpcap.so" 2>/dev/null
    ## Note location of libpcap.so if yours is different than the following location:
    #sudo ln -s '/usr/lib/x86_64-linux-gnu/libpcacp.so' '/usr/lib/x86_64-linux-gnu/libpcacp.so.1'
    ## If you see the error 'libnetfilter_queue.so.1 is not available":
    #sudo apt install libnetfiler-queue-dev


    UpdateCaplets

    echo -e "${BLUE}[✓]Done.${RESET}"
}

function ChangeBettercapDefaultCredentials() {

	# Replace default http credentials if found
	if ! [ -e /usr/local/share/bettercap/caplets/http-ui.cap ]; then
		echo -e "${YELLOW}[i]http-ui.cap not found. Quitting...${RESET}"
		exit 1
	fi
	if (grep -Eqx "^set api.rest.(username user|password pass)$" "$HTTP_CONF"); then
		echo -e "${BLUE}[*]Changing bettercap http web interface credentials...${RESET}"
		sed -i 's/^set api.rest.password pass$/set api.rest.password '"$(tr -dc '[:alnum:]' < /dev/urandom | fold -w 32 | head -n 1)"'/' /usr/local/share/bettercap/caplets/http-ui.cap
		sed -i 's/^set api.rest.username user$/set api.rest.username '"$(tr -dc '[:alnum:]' < /dev/urandom | fold -w 32 | head -n 1)"'/' /usr/local/share/bettercap/caplets/http-ui.cap
	else
		echo ""
		echo -e "${BOLD}[i]http-ui credentials already randomized.${RESET}"
	fi
	# Replace default https credentials if found
	if ! [ -e /usr/local/share/bettercap/caplets/https-ui.cap ]; then
		echo -e "${YELLOW}[*]https-ui.cap not found. Quitting...${RESET}"
		exit 1
	fi
	if (grep -Eqx "^set api.rest.(username user|password pass)$" "$HTTPS_CONF"); then
		echo -e "${BLUE}[*]Changing bettercap https web interface credentials...${RESET}"
		sed -i 's/^set api.rest.password pass$/set api.rest.password '"$(tr -dc '[:alnum:]' < /dev/urandom | fold -w 32 | head -n 1)"'/' /usr/local/share/bettercap/caplets/https-ui.cap
		sed -i 's/^set api.rest.username user$/set api.rest.username '"$(tr -dc '[:alnum:]' < /dev/urandom | fold -w 32 | head -n 1)"'/' /usr/local/share/bettercap/caplets/https-ui.cap
	else
		echo ""
		echo -e "${BOLD}[i]https-ui credentials already randomized.${RESET}"
	fi

	# Restart bettercap for ui to accept new credentials
	if (systemctl is-active --quiet bettercap-arp-antidote.service); then
		systemctl restart bettercap-arp-antidote
	fi

}

function UpdateBettercapCredentials() {

	if ! [ -e /usr/local/share/bettercap/caplets/http-ui.cap ]; then
		echo -e "${YELLOW}[i]http-ui.cap not found. Quitting...${RESET}"
		exit 1
	fi
	echo -e "${BLUE}[*]Changing bettercap http web interface credentials...${RESET}"
	sed -i 's/^set api.rest.password .*$/set api.rest.password '"$(tr -dc '[:alnum:]' < /dev/urandom | fold -w 32 | head -n 1)"'/' /usr/local/share/bettercap/caplets/http-ui.cap
	sed -i 's/^set api.rest.username .*$/set api.rest.username '"$(tr -dc '[:alnum:]' < /dev/urandom | fold -w 32 | head -n 1)"'/' /usr/local/share/bettercap/caplets/http-ui.cap

	if ! [ -e /usr/local/share/bettercap/caplets/https-ui.cap ]; then
		echo -e "${YELLOW}[*]https-ui.cap not found. Quitting...${RESET}"
		exit 1
	fi
	echo -e "${BLUE}[*]Changing bettercap https web interface credentials...${RESET}"
	sed -i 's/^set api.rest.password .*$/set api.rest.password '"$(tr -dc '[:alnum:]' < /dev/urandom | fold -w 32 | head -n 1)"'/' /usr/local/share/bettercap/caplets/https-ui.cap
	sed -i 's/^set api.rest.username .*$/set api.rest.username '"$(tr -dc '[:alnum:]' < /dev/urandom | fold -w 32 | head -n 1)"'/' /usr/local/share/bettercap/caplets/https-ui.cap

	# Restart bettercap for ui to accept new credentials
	if (systemctl is-active --quiet bettercap-arp-antidote.service); then
		systemctl restart bettercap-arp-antidote
	fi

	BettercapUIStatus
}



#============================
# Network Visibility Services
#============================

function RemoveFirewallRules() {

	echo -e "${BLUE}[i] This script can remove all firewall rules for compatability.${RESET}"
	echo -e "    You can skip this if you have rules configured in a specific way you want to keep."
	echo -e "    Otherwise, it's recommended to do this to ensure all network traffic passes through."
	echo -e "    If docker is installed, it will be restarted to ensure the necessary rules are loaded."
	echo ""
	until [[ $REMOVE_FW_CHOICE =~ ^(y|n)$ ]]; do
		read -rp "Remove all firewall rules? [y/n]: " -e REMOVE_FW_CHOICE
	done
	if [[ $REMOVE_FW_CHOICE == "y" ]]; then
		if ! (ufw status verbose | grep -q "inactive"); then
			echo -e "${BLUE}[>]Disabling ufw...${RESET}"
			ufw disable
		fi
		if ! (iptables -S | grep -q "\-P INPUT ACCEPT" && iptables -S | grep -q "\-P FORWARD ACCEPT" && iptables -S | grep -q "\-P OUTPUT ACCEPT"); then
			echo -e "${BLUE}[>]Removing all iptables rules...${RESET}"
			iptables -F    # Flush all chains
			iptables -X    # Delete all user-defined chains
		fi
		if ! (ip6tables -S | grep -q "\-P INPUT ACCEPT" && ip6tables -S | grep -q "\-P FORWARD ACCEPT" && ip6tables -S | grep -q "\-P OUTPUT ACCEPT"); then
			echo -e "${BLUE}[>]Removing all ip6tables rules...${RESET}"
			ip6tables -F    # Flush all chains
			ip6tables -X    # Delete all user-defined chains
		fi
		if (command -v docker >/dev/null); then
			systemctl restart docker
		fi
	fi

}


function InstallForwardingService() {

    # Check if the forwarding service exists
    if [ -e /etc/systemd/system/packet-forwarding.service ]; then
        echo -e "${BLUE}[✓]Packet forwarding service already installed...${RESET}"
    else
        # Create a persistent sysctl service for packet forwarding rules from walkthrough
        # https://github.com/straysheep-dev/network-visibility#arp-poisoning-antidoting-the-network
        echo -e "${BLUE}[*]Creating a sysctl service for packet forwarding...${RESET}"

        sleep 2

        echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/20-packet-forwarding.conf
        echo 'net.ipv6.conf.all.forwarding=1' >>/etc/sysctl.d/20-packet-forwarding.conf
        sysctl --system

        if ! [ -d /etc/iptables ]; then
            mkdir /etc/iptables
        fi

        echo "#!/bin/sh
iptables -I FORWARD -i $PUB_NIC -o $PUB_NIC -j ACCEPT
ip6tables -I FORWARD -i $PUB_NIC -o $PUB_NIC -j ACCEPT" > /etc/iptables/enable-forwarding.sh

        echo "#!/bin/sh
iptables -D FORWARD -i $PUB_NIC -o $PUB_NIC -j ACCEPT
ip6tables -D FORWARD -i $PUB_NIC -o $PUB_NIC -j ACCEPT" > /etc/iptables/disable-forwarding.sh

        chmod +x /etc/iptables/enable-forwarding.sh
        chmod +x /etc/iptables/disable-forwarding.sh

        echo "[Unit]
Description=Packet forwarding for networking monitoring
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/enable-forwarding.sh
ExecStop=/etc/iptables/disable-forwarding.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" >/etc/systemd/system/packet-forwarding.service

        systemctl enable packet-forwarding

	echo ""
        echo -e "${BLUE}[?]Start the packet forwarding service now?${RESET}"
        until [[ $START_CHOICE_PACKET_FORWARDING =~ ^(y|n)$ ]]; do
            read -rp "[y/n]? " START_CHOICE_PACKET_FORWARDING
        done

        if [[ $START_CHOICE_PACKET_FORWARDING == "y" ]]; then
            # See https://www.bettercap.org/usage/scripting/
            # and https://github.com/bettercap/scripts
            # for some additional interesting uses.
            echo -e "${BLUE}[*]Starting packet forwarding service...${RESET}"
            systemctl start packet-forwarding
            echo -e "${BLUE}[✓]Done.${RESET}"
        else
            echo -e "${BLUE}[*]OK, packet forwarding won't start until next reboot or by running:${RESET}"
            echo -e "    ${YELLOW}sudo systemctl restart packet-forwarding${RESET}"
        fi
    fi

}

function InstallBettercapArpService() {

	# Check if the arp-cache antidoting service exists
	if [ -e /etc/systemd/system/bettercap-arp-antidote.service ]; then
		echo -e "${BLUE}[✓]Bettercap arp-antidote service already installed...${RESET}"
	elif (command -v bettercap > /dev/null); then
		echo -e "${BLUE}[*]Installing bettercap arp-antidote service...${RESET}"

		# Based on https://github.com/bettercap/bettercap/blob/master/bettercap.service
		# "set arp.spoof.fullduplex true" appears to break the capture on most networks
		# "http-ui on" and "api.rest on" are unnecessary for traffic capture, and also when firewall rules are likely off
		# If you need to debug capturing, disable the services and run bettercap from the shell manually
		echo "[Unit]
Description=Capture LAN traffic for network forensics
Documentation=https://bettercap.org, https://github.com/straysheep-dev/network-visibility
Wants=network.target
After=network.target

[Service]
Type=simple
PermissionsStartOnly=true
ExecStart=/usr/local/bin/bettercap -eval 'net.recon on; net.probe on; arp.spoof on; ndp.spoof on'
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target" >/etc/systemd/system/bettercap-arp-antidote.service
	
		systemctl daemon-reload
		systemctl enable bettercap-arp-antidote

		echo ""
		echo -e "${BLUE}[>]Start bettercap arp-cache antidoting the network now?${RESET}"
		until [[ $START_CHOICE_BETTERCAP_ARP =~ ^(y|n)$ ]]; do
			read -rp "[y/n]? " START_CHOICE_BETTERCAP_ARP
		done

		if [[ $START_CHOICE_BETTERCAP_ARP == "y" ]]; then
			# Start antidoting the local area network
			# See https://www.bettercap.org/usage/scripting/
			# and https://github.com/bettercap/scripts
			# for some additional interesting uses.
			echo -e "${BLUE}[*]Starting services...${RESET}"
			systemctl start bettercap-arp-antidote
		else
			echo -e "${BLUE}[i]OK, the bettercap service won't start until next reboot or by running:${RESET}"
			echo -e "    ${YELLOW}sudo systemctl restart bettercap-arp-antidote${RESET}"
			exit 0
		fi
	else
		echo -e "${YELLOW}[i]Bettercap not installed, skipping installation of bettercap-arp-antidote.service${RESET}"
	fi
}

function InstallServices() {

	until [[ $PACKET_FWD_CHOICE =~ ^(y|n)$ ]]; do
		read -rp "Install the packet forwarding service? [y/n]: " -e PACKET_FWD_CHOICE
	done
	if [[ $PACKET_FWD_CHOICE == 'y' ]]; then
		InstallForwardingService
	fi
	until [[ $BETTERCAP_SVC_CHOICE =~ ^(y|n)$ ]]; do
		read -rp "Install bettercap as a service? [y/n]: " -e BETTERCAP_SVC_CHOICE
	done
	if [[ $BETTERCAP_SVC_CHOICE == 'y' ]]; then
		InstallBettercapArpService
	fi
}

function StartServices() {

	# Check for bettercap
	if ! [ -e /usr/local/bin/bettercap ]; then
		echo -e "${YELLOW}bettercap not installed. Quitting...${RESET}"
		exit 1
	fi

	# Checks for packet-forwarding.service
	if [ -e /etc/systemd/system/packet-forwarding.service ]; then
		if (systemctl is-active --quiet packet-forwarding.service); then
			echo -e "${BLUE}[i]packet-forwarding.service already running.${RESET}"
		elif (systemctl is-enabled --quiet packet-forwarding.service); then
			echo -e "${BLUE}[*]Restarting packet-forwarding.service...${RESET}"
			systemctl restart packet-forwarding
		else
			systemctl enable packet-forwarding
			systemctl restart packet-forwarding
		fi
	fi

	# Checks for bettercap-arp-antidote.service
	if [ -e /etc/systemd/system/bettercap-arp-antidote.service ]; then
		if (systemctl is-active --quiet bettercap-arp-antidote.service); then
			echo -e "${BLUE}[i]bettercap-arp-antidote.service already running.${RESET}"
		elif (systemctl is-enabled --quiet bettercap-arp-antidote.service); then
			echo -e "${BLUE}[*]Restarting bettercap-arp-antidote.service...${RESET}"
			systemctl restart bettercap-arp-antidote
		else
			systemctl enable bettercap-arp-antidote
			systemctl restart bettercap-arp-antidote
		fi
	fi
	
	# If services aren't installed, then do the install walkthrough
	if ! [ -e /etc/systemd/system/bettercap-arp-antidote.service ] || ! [ -e /etc/systemd/system/packet-forwarding.service ]; then
		InstallServices
	fi

	echo -e "${BLUE}[✓]Done.${RESET}"

}

function StopServices() {

	echo -e "${YELLOW}[*]Stopping network visibility services...${RESET}"

	# Checks for bettercap-arp-antidote.service
	if [ -e /etc/systemd/system/bettercap-arp-antidote.service ]; then
		if ! (systemctl is-active --quiet bettercap-arp-antidote.service); then
			echo -e "${BLUE}[i]bettercap-arp-antidote.service already stopped.${RESET}"
			systemctl disable bettercap-arp-antidote
		else
			systemctl stop bettercap-arp-antidote
			systemctl disable bettercap-arp-antidote
		fi
	fi

	# Checks for packet-forwarding.service
	if [ -e /etc/systemd/system/packet-forwarding.service ]; then
		if ! (systemctl is-active --quiet packet-forwarding.service); then
			echo -e "${BLUE}[i]packet-forwarding.service already stopped.${RESET}"
			systemctl disable packet-forwarding
		else
			systemctl stop packet-forwarding
			systemctl disable packet-forwarding
		fi
	fi

	# Add or change your own additional service checks here

	echo -e "${BLUE}[✓]Done.${RESET}"

}



#===========
# Cron Tasks
#===========


function EnableRITACron() {

	if ! [ -e /etc/rita ]; then
		echo -e "${YELLOW}RITA not installed. Quitting...${RESET}"
		exit 1
	fi

	# https://github.com/activecm/rita/blob/master/docs/Rolling%20Datasets.md

	echo ""
	echo -e "${BLUE}[>]Schedule a cron task for a database? (RITA will import Zeek logs on an hourly basis to the given database)${RESET}"
	until [[ $RITA_CRON_CHOICE =~ ^(y|n)$ ]]; do
		read -rp "[y/n]? " RITA_CRON_CHOICE
	done

	if [[ $RITA_CRON_CHOICE == "y" ]]; then
		echo -e ""
		echo -e "Enter a name for the database."
		echo -e ""
		until [[ ${DB_NAME} =~ ^[a-zA-Z0-9_]+$ ]]; do
			read -rp "Database name: " -e -i db_name DB_NAME
		done

	if ! [ -e /etc/cron.d/rita ]; then
		echo "# /etc/cron.d/rita: crontab entries for rita to do rolling imports of zeek logs

SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin" > /etc/cron.d/rita
        fi

        if ! [[ "$DB_NAME" == "" ]]; then
            echo "
# RITA Database: $DB_NAME
59 *   * * *   root  rita import --rolling $ZEEK_PATH/logs/"'$(date --date="-1 hour" +\%Y-\%m-\%d)'"/ $DB_NAME" >> /etc/cron.d/rita
        else
            echo -e "${YELLOW}[i]Database name was empty, nothing to write.${RESET}"
        fi

        cat /etc/cron.d/rita
        echo ""
        echo -e "${BLUE}[✓]New task scheduled under /etc/cron.d/rita.${RESET}"

    fi

}

function ManageRITACron() {

	if [ -e /etc/cron.d/rita ]; then
		echo ""
		echo -e "${BLUE}[>]Delete /etc/cron.d/rita?${RESET}"
		echo ""
		until [[ $RITA_CRON_OPTION =~ ^(y|n)$ ]]; do
			read -rp "Select an option [y/n]: " RITA_CRON_OPTION
		done

		if [[ "$RITA_CRON_OPTION" == 'y' ]]; then
			rm /etc/cron.d/rita
			echo -e "${BLUE}[✓]Done.${RESET}"
		else
			exit 0
		fi
	else
		EnableRITACron
	fi

}

function EnableZeekCron() {

	if ! [ -e "$ZEEK_PATH"/bin/zeekctl ]; then
		echo -e "${YELLOW}Zeek not installed. Quitting...${RESET}"
		exit 1
	fi

	if [ -e /usr/local/bin/zeek ]; then
		echo -e "${BLUE}[i]${RESET}docker-zeek's cron task is enabled by default. Quitting..."
		exit 1
	fi

	# https://github.com/zeek/zeekctl/blob/master/doc/main.rst#zeekcontrol-cron-command

	echo ""
	echo -e "${BLUE}[>]Enable Zeek cron? (only for non-docker Zeek installations)${RESET}"
	echo -e "   This will check the Zeek process every 5 minutes, and restart it if it's crashed."
	echo -e "   https://github.com/zeek/zeekctl/blob/master/doc/main.rst#zeekcontrol-cron-command"
	until [[ $ZEEK_CRON_CHOICE =~ ^(y|n)$ ]]; do
		read -rp "[y/n]? " ZEEK_CRON_CHOICE
	done

	if [[ $ZEEK_CRON_CHOICE == "y" ]]; then

		"$ZEEK_PATH"/bin/zeekctl cron enable > /dev/null

		echo "# /etc/cron.d/zeek: crontab entries for non-docker zeek binaries to automatically restart if crashed

SHELL=/bin/bash
PATH=$ZEEK_PATH/bin:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

*/5 *   * * *   root  $ZEEK_PATH/bin/zeekctl cron" > /etc/cron.d/zeek
    
		echo ""
		cat /etc/cron.d/zeek

		echo ""
		echo -e "${BLUE}[✓]New task scheduled under /etc/cron.d/zeek${RESET}"
	elif [[ $ZEEK_CRON_CHOICE == "n" ]]; then

		echo -e "${BLUE}[>]Remove Zeek cron?${RESET}"
		until [[ $REMOVE_ZEEK_CRON_CHOICE =~ ^(y|n)$ ]]; do
			read -rp "[y/n]? " REMOVE_ZEEK_CRON_CHOICE
		done

		if [[ $REMOVE_ZEEK_CRON_CHOICE == "y" ]]; then
			"$ZEEK_PATH"/bin/zeekctl cron disable > /dev/null
			rm /etc/cron.d/zeek
			echo -e "${BLUE}[i]/etc/cron.d/zeek removed.${RESET}"
		fi
	fi


}

function ManageZeekCron() {

	if [ -e /etc/cron.d/zeek ]; then
		echo ""
		echo -e "${BLUE}[>]Delete /etc/cron.d/zeek?${RESET}"
		echo ""
		until [[ $ZEEK_CRON_OPTION =~ ^(y|n)$ ]]; do
			read -rp "Select an option [y/n]: " ZEEK_CRON_OPTION
		done

		if [[ "$ZEEK_CRON_OPTION" == 'y' ]]; then
			rm /etc/cron.d/zeek
			echo -e "${BLUE}[✓]Done.${RESET}"
		else
			exit 0
		fi
	else
		EnableZeekCron
	fi

}

function ManageCronTasks() {

    # To do:
    # This section will need improved functionality

	echo ""
	echo -e "${BLUE}[i]Currently scheduled cron tasks:${RESET}"
	echo ""
	echo -e "=========================[ ${BLUE}RITA${RESET} ]============================="
	if ! (cat /etc/cron.d/rita 2>/dev/null); then
		echo -e "${YELLOW}[i]No cron entry for RITA.${RESET}"
	fi
	echo ""
	echo -e "=========================[ ${BLUE}Zeek${RESET} ]============================="
	if ! (cat /etc/cron.d/zeek 2>/dev/null); then
		echo -e "${YELLOW}[i]No cron entry for Zeek.${RESET}"
	fi

	echo -e ""
	echo -e "What would you like to do?"
	echo -e ""
	echo -e "   1) Manage RITA cron tasks"
	echo -e "   2) Manage Zeek cron tasks"
	echo -e "   3) Exit"
	until [[ $CRON_MENU_OPTION =~ ^[1-3]$ ]]; do
		read -rp "Select an option [1-3]: " CRON_MENU_OPTION
	done

	case $CRON_MENU_OPTION in
	1)
		ManageRITACron
		;;
	2)
		ManageZeekCron
		;;
	3)
		exit 0
		;;
	esac

}

#==============================
# Uninstall / Removal Functions
#==============================


function RemoveServices() {

    StopServices

    rm -f /etc/systemd/system/bettercap-arp-antidote.service
    rm -f /etc/systemd/system/packet-forwarding.service
    rm -f /etc/iptables/enable-forwarding.sh
    rm -f /etc/iptables/disable-forwarding.sh
    rm -f /etc/sysctl.d/20-packet-forwarding.conf

    echo -e "${BLUE}Reloading system daemons...${RESET}"
    sleep 2
    sysctl --system
    systemctl daemon-reload
    echo -e "${BLUE}[✓]Done.${RESET}"

}

function UninstallBettercap() {

    if (command -v bettercap > /dev/null); then
        echo -e "${BOLD}Removing file: /usr/local/bin/bettercap${RESET}"
        echo -e "${BOLD}Removing dir: /usr/local/share/bettercap${RESET}"
        echo -e "${YELLOW}[i]NOTE: Not removing any bettercap.log files, review /var/log/, /root/, or ~/ if any exist.${RESET}"
        rm /usr/local/bin/bettercap
        rm -rf /usr/local/share/bettercap
    fi
    echo -e "${BLUE}[✓]Bettercap uninstalled.${RESET}"
 
}

function UninstallDocker() {

    if (command -v docker > /dev/null); then
        echo -e "${BLUE}[*]Uninstalling docker...${RESET}"
        apt-get autoremove --purge docker-ce docker-ce-cli containerd.io
     fi
     echo -e "${BLUE}[✓]docker uninstalled.${RESET}"

}

function UninstallMongoDBFromApt() {

    if (command -v mongod > /dev/null); then
        echo -e "${BLUE}[*]Uninstalling mongodb...${RESET}"
        systemctl stop mongod
        apt-get autoremove --purge mongodb-org
    fi
    echo -e "${BLUE}[✓]mongodb uninstalled.${RESET}"

}

function UninstallZeek() {

    if [ -e /opt/zeek/bin/zeekctl ]; then
        /opt/zeek/bin/zeekctl cron disable
        /opt/zeek/bin/zeekctl stop
        echo -e "${BLUE}[*]Waiting 30s for zeek processes to stop...${RESET}"
        sleep 30
        apt-get autoremove --purge zeek
        rm -rf /opt/zeek/etc/*
    fi

    if [ -e /usr/local/zeek/bin/zeekctl ]; then
        /usr/local/zeek/bin/zeekctl cron disable
        /usr/local/zeek/bin/zeekctl stop
        echo -e "${BLUE}[*]Waiting 30s for zeek processes to stop...${RESET}"
        sleep 30
        apt-get autoremove --purge zeek
        rm -rf /usr/local/zeek/etc/*
    fi

    if [ -e /usr/local/bin/zeek ]; then
        /usr/local/bin/zeek stop
        sleep 2
        docker image rm activecm/zeek
        sleep 2
        rm /usr/local/bin/zeek
    fi
    if [ -e /etc/cron.d/zeek ]; then
        rm /etc/cron.d/zeek
    fi
    echo -e "${BLUE}[✓]Zeek uninstalled.${RESET}"

}

function UninstallRITA() {

    if (command -v docker > /dev/null); then
        if (docker image list | grep -iq rita); then
            cd /etc/rita || exit 1
            docker compose -f ./docker-compose.yml --env-file ./rita.env down
            docker rmi quay.io/activecm/rita:latest
            docker rmi quay.io/activecm/rita:v"$RITA_VER"
            docker rmi mongo:4.2
        fi
    fi
    if [ -e /etc/rita -o -e /var/lib/rita -o -e /usr/local/bin/rita -o -e /usr/local/etc/rita -o -e /etc/cron.d/rita ]; then
        rm -rf /etc/rita 2>/dev/null
        rm -rf /var/lib/rita 2>/dev/null
        rm -rf /usr/local/bin/rita 2>/dev/null
        rm -rf /usr/local/etc/rita 2>/dev/null
        rm -rf /etc/cron.d/rita 2>/dev/null
    fi
    echo -e "${BLUE}[✓]RITA uninstalled.${RESET}"

}

function Uninstallntopng() {

	echo -e "${YELLOW}[i]NOTE: This function is not yet complete. Some components will remain installed.${RESET}"
	apt autoremove --purge -y apt-ntop-stable pfring-dkms nprobe ntopng n2disk cento
	echo -e "${YELLOW}[✓]ntopng uninstalled.${RESET}"

}

function CleanUp() {
	# CleanUp
	if [ -e "$SETUPDIR" ]; then
		rm -rf "$SETUPDIR"
	fi

	# To do:
	# Save / move this script to PATH for management
}



#===========================================================
# Management Functions (Status / Install / Uninstall / Menu)
#===========================================================

function FirewallStatus() {
	# ufw
	if (command -v ufw > /dev/null); then
		if (ufw status | grep -q 'Status: active'); then
			echo -e "    ${YELLOW}●${RESET} Firewall Status: active"
		elif (ufw status | grep -q 'Status: inactive'); then
			echo -e "    ${BLUE}●${RESET} Firewall Status: inactive"
		else
			echo -e "    ${YELLOW}●${RESET} Error reading firewall status"
		fi
	fi
	# iptables
	if (command -v iptables > /dev/null); then
		if (iptables -S | grep -q "\-P INPUT ACCEPT" && iptables -S | grep -q "\-P FORWARD ACCEPT" && iptables -S | grep -q "\-P OUTPUT ACCEPT"); then
			echo -e "    ${BLUE}●${RESET} iptables chains set to ACCEPT"
		else
			echo -e "    ${YELLOW}●${RESET} iptables has active rules"
		fi
	fi
	if (command -v ip6tables > /dev/null); then
		if (ip6tables -S | grep -q "\-P INPUT ACCEPT" && ip6tables -S | grep -q "\-P FORWARD ACCEPT" && ip6tables -S | grep -q "\-P OUTPUT ACCEPT"); then
			echo -e "    ${BLUE}●${RESET} ip6tables chains set to ACCEPT"
		else
			echo -e "    ${YELLOW}●${RESET} ip6tables has active rules"
		fi
	fi
}

function PacketForwardingStatus() {
	# packet-forwarding.service
	if ! [ -e /etc/systemd/system/packet-forwarding.service ]; then
		echo -e "    ${BOLD}●${RESET} packet-forwarding.service not installed"
	elif (systemctl is-active --quiet packet-forwarding.service); then
		echo -e "    ${BLUE}●${RESET} packet-forwarding.service ${GREEN}is active${RESET}"
	else
		echo -e "    ${BOLD}●${RESET} packet-forwarding.service ${YELLOW}inactive${RESET}"        
	fi
}

function ArpAntidoteStatus() {
	# bettercap-arp-forwarding.service
	if ! [ -e /etc/systemd/system/bettercap-arp-antidote.service ]; then
		echo -e "    ${BOLD}●${RESET} bettercap-arp-antidote.service not installed"
	elif (systemctl is-active --quiet bettercap-arp-antidote.service); then
		echo -e "    ${BLUE}●${RESET} bettercap-arp-antidote.service ${GREEN}is active${RESET}"
	else
		echo -e "    ${BOLD}●${RESET} bettercap-arp-antidote.service ${YELLOW}inactive${RESET}"        
	fi
}

function BettercapStatus() {
	# Bettercap
	if [ -e /usr/local/bin/bettercap ]; then
		echo -e "    ${BLUE}●${RESET} bettercap installed"
	else
		echo -e "    ${BOLD}●${RESET} bettercap not installed"
	fi
}

function DockerStatus() {
	# Docker
	if ! (command -v docker > /dev/null); then
		echo -e "    ${BOLD}●${RESET} docker not installed"
	elif (systemctl is-active --quiet docker.service); then
		echo -e "    ${BLUE}●${RESET} docker ${GREEN}is active${RESET}"
	else
		echo -e "    ${BOLD}●${RESET} docker ${YELLOW}inactive${RESET}"
	fi
}

function ZeekStatus() {
	# Zeek
	# Zeek Profile
	if [ -e /etc/profile.d/zeek-path.sh ]; then
		source /etc/profile.d/zeek-path.sh
	fi
	if [ -e /etc/profile.d/zeek.sh ]; then
		source /etc/profile.d/zeek.sh
	fi
	# Zeek PATH
	ZEEK_PATH=''
	if [ -e /usr/local/zeek/etc/node.cfg ]; then
		ZEEK_PATH=/usr/local/zeek
	elif [ -e /opt/zeek/etc/node.cfg ]; then
		ZEEK_PATH=/opt/zeek
	fi
	# Zeek Status
	if ! (command -v zeek > /dev/null); then
		echo -e "    ${BOLD}●${RESET} zeek not installed"
	elif [ -e /usr/local/bin/zeek ]; then
		if (docker exec -it zeek zeekctl status > /dev/null); then
			echo -e "    ${BLUE}●${RESET} zeek is ${GREEN}active & listening${RESET}    ZEEK_PATH=$ZEEK_PATH"
			# https://github.com/activecm/docker-zeek#readme
			echo -e "        ${BLUE}●${RESET} zeek cron enabled via docker image by default"
		else
			echo -e "    ${YELLOW}●${RESET} zeek inactive, crashed, or not shown    ZEEK_PATH=$ZEEK_PATH"
		fi
	elif (zeekctl status > /dev/null); then
		echo -e "    ${BLUE}●${RESET} zeek is ${GREEN}active & listening${RESET}    ZEEK_PATH=$ZEEK_PATH"
	else
		echo -e "    ${YELLOW}●${RESET} zeek inactive, crashed, or not shown    ZEEK_PATH=$ZEEK_PATH"
	fi
	if [ -e /etc/cron.d/zeek ]; then
		echo -e "        ${BLUE}●${RESET} zeek $($ZEEK_PATH/bin/zeekctl cron ?)"
	else
		echo -e "        ${BOLD}●${RESET} zeek cron not enabled"
	fi
}

function ntopngStatus() {
	# ntopng
	if ! (command -v ntopng > /dev/null); then
		echo -e "    ${BOLD}●${RESET} ntopng not installed"
	elif (systemctl is-active --quiet ntopng.service); then
		echo -e "    ${BLUE}●${RESET} ntopng ${GREEN}is active${RESET}"
	else
		echo -e "    ${BOLD}●${RESET} ntopng ${YELLOW}inactive${RESET}"
	fi
}

function RITAStatus() {
	# RITA
	if [ -e /usr/local/bin/rita ]; then
		echo -e "    ${BLUE}●${RESET} rita installed"
	elif (command -v docker > /dev/null && docker image list | grep -iq rita); then
		echo -e "    ${BLUE}●${RESET} rita docker image installed"
		echo -e "    ${BLUE}●${RESET} mongodb docker image installed"
	else
		echo -e "    ${BOLD}●${RESET} rita not installed"
	fi
	if [ -e /etc/cron.d/rita ]; then
		echo -e "        ${BLUE}●${RESET} rita cron enabled"
	else
		echo -e "        ${BOLD}●${RESET} rita cron not enabled"
	fi
}

function MongoDBStatus() {
	# MongoDB
	if (systemctl is-active --quiet mongod.service); then
		echo -e "    ${BLUE}●${RESET} mongodb ${GREEN}is active${RESET}"
	elif ! (command -v mongod > /dev/null); then
		echo -e "    ${BOLD}●${RESET} mongodb not installed"
	else
		echo -e "    ${BOLD}●${RESET} mongodb ${YELLOW}inactive${RESET}"
	fi
}

function EchoStatus() {

	# Final echo to terminal
	echo ""
	echo "Status:"

	FirewallStatus
	PacketForwardingStatus
	ArpAntidoteStatus
	BettercapStatus
	DockerStatus
	ntopngStatus
	ZeekStatus
	RITAStatus
	MongoDBStatus
	BettercapUIStatus


}

function InstallBettercap() {

    echo -e "${BLUE}[*]Checking path for bettercap...${RESET}"
    if ! (command -v bettercap > /dev/null); then
        CheckOS
        CheckInterface
        MakeTemp
        InstallEssentialPackages

        InstallBettercapFromRelease

        ChangeBettercapDefaultCredentials
        CleanUp
        EchoStatus
    else
        echo -e "${BLUE}[i]Bettercap already installed.${RESET}"
    fi

}

function InstallZeek() {

    if [ -e /etc/profile.d/zeek-path.sh ]; then
        source /etc/profile.d/zeek-path.sh
    fi

    echo -e "${BLUE}[*]Checking path for zeek...${RESET}"

    if (command -v zeek > /dev/null); then
    	echo -e "${BLUE}[i]Zeek found!${RESET}"
    	sleep 1
        ConfigureZeek
        exit 0
    fi
    if ! (command -v zeek > /dev/null); then
        CheckOS
#        CheckInterface
        MakeTemp
        InstallEssentialPackages

        echo -e "${BLUE}[>]Prefer using Docker for this?${RESET}"
        until [[ $DOCKER_PREF_ZEEK =~ ^(y|n)$ ]]; do
            read -rp "[y/n]? " DOCKER_PREF_ZEEK
        done

        # Check available Zeek binaries at:
        # https://build.opensuse.org/project/show/security:zeek
        if [ "$DOCKER_PREF_ZEEK" == 'n' ] && [ "$ARCH" == 'amd64' ]; then
            InstallZeekFromApt
            ConfigureZeek
        else
            InstallDocker
            InstallZeekFromDocker
            ConfigureZeek
        fi

        CleanUp
        EchoStatus
    else
        echo -e "${BLUE}[i]Zeek already installed.${RESET}"
    fi

}

function InstallRITA() {

    echo -e "${BLUE}[*]Checking path for rita...${RESET}"
    if ! (command -v rita > /dev/null || (command -v docker > /dev/null && (docker image list | grep -iq rita) && [[ -e '/etc/rita/config.yaml' && -e '/etc/rita/docker-compose.yml' ]])); then
        CheckOS
        MakeTemp
        InstallEssentialPackages

        echo -e "${BLUE}[>]Prefer using Docker for this?${RESET}"
        until [[ $DOCKER_PREF_RITA =~ ^(y|n)$ ]]; do
            read -rp "[y/n]? " DOCKER_PREF_RITA
        done

        # Check OS arch
        if [[ $DOCKER_PREF_RITA == 'n' ]] && [[ $MAJOR_UBUNTU_VERSION -eq 18 || $MAJOR_UBUNTU_VERSION -eq 20 ]]; then
            if [ "$ARCH" == 'amd64' ]; then
                InstallRITAFromScript
            elif  [ "$ARCH" == 'arm64' ]; then
                # Install MongoDB before RITA so `rita --version` check succeeds
                InstallMongoDBFromApt
                InstallRITAFromSource
            else
                echo -e "${BOLD}[i]Architecture not yes tested, quitting.${RESET}"
                exit 1
            fi
        else
                InstallDocker
                InstallRITAFromDocker
        fi

        CleanUp
        EchoStatus
    elif (command -v docker > /dev/null && (docker image list| grep -iq rita)); then
        echo -e "${BLUE}[i]RITA already installed.${RESET}"
        echo -e ""
        echo -e "${BLUE}[i]Test with:${RESET}"
        echo -e "${BOLD}   sudo docker compose -f /etc/rita/docker-compose.yml --env-file /etc/rita/rita.env run --rm rita --version${RESET}"
        echo -e "${BOLD}   sudo docker compose -f /etc/rita/docker-compose.yml --env-file /etc/rita/rita.env run --rm rita import /logs database_name_1${RESET}"
        echo -e "${BLUE}[i]Also be sure to try '-H | less -S' to view data manually.${RESET}"
        echo -e "${BOLD}   sudo docker compose -f /etc/rita/docker-compose.yml --env-file /etc/rita/rita.env run --rm rita show-exploded-dns db_1 -H | less -S${RESET}"
        echo -e "${YELLOW}   If the output is messed up, try all four arrow keys inside of 'less' to arrange it properly.${RESET}"
        echo -e ""
        echo -e "Import a directory of *.gz Zeek log files to databse db_1:"
        echo -e "${BOLD}    sudo su${RESET}"
        echo -e "${BOLD}    export LOGS=/path/to/logs/YYYY-MM-DD${RESET}"
        echo -e "${BOLD}    docker compose -f /etc/rita/docker-compose.yml --env-file /etc/rita/rita.env run --rm rita import /logs db_1${RESET}"
        echo -e ""
        echo -e "Import multiple diretories of YYYY-MM-DD/*.gz or *.log Zeek log files to database db_1:"
        echo -e "${BOLD}    sudo su${RESET}"
        echo -e "${BOLD}    for logs in /path/to/logs/YYYY-*; do export LOGS=\"\$logs\"; docker compose -f /etc/rita/docker-compose.yml --env-file /etc/rita/rita.env run --rm rita import --rolling /logs db_1; done${RESET}"
        echo -e ""
    else
        echo -e "${BLUE}[i]RITA already installed.${RESET}"
        echo ""
        echo "Try these commands to get started:"
        echo -e "${YELLOW}    [>]rita show-databases${RESET}"
        echo -e "${YELLOW}    [>]rita import /path/to/logs/YYYY-* test_db${RESET}"
        echo -e "${YELLOW}    [>]rita import /opt/zeek/logs/current/ test_db2${RESET}"
        echo -e "${YELLOW}    [>]rita show-exploded-dns test_db -H | less -S${RESET}"
    fi
    

}

function Installntopng() {

	echo -e "${BLUE}[*]Checking path for ntopng...${RESET}"
	if ! (command -v ntopng > /dev/null); then

		CheckOS
		MakeTemp

		echo -e "${BLUE}[*]Installing ntopng...${RESET}"

		# https://packages.ntop.org/apt-stable/
		apt update
		apt-get install -y software-properties-common wget
		add-apt-repository universe
		wget https://packages.ntop.org/apt-stable/"$UBUNTU_VERSION"/all/apt-ntop-stable.deb
		apt install ./apt-ntop-stable.deb
		apt-get clean all
		apt-get update
		apt-get install -y pfring-dkms nprobe ntopng n2disk cento

		echo -e "${BLUE}[✓]Done.${RESET}"

		echo -e "${YELLOW}[i]Recommended: Limit access to the ntopng admin panel.${RESET}"
		echo -e "    Go to: Settings > Preferences > User Interface > Access Control List"
		echo -e "    Set this value to: ${GREEN}+127.0.0.0/8${RESET}"
		echo -e "    Then click the 👤 user icon on the top right of the WebUI and choose '↻ Restart'"

		Sleep 3

		CleanUp
		EchoStatus
	else
		echo -e "${BLUE}[i]ntopng already installed.${RESET}"
	fi
}

function Uninstall() {

    # Needs a better solution...
    echo -e "${BLUE}[i]Ctrl+c to quit this dialogue at any time.${RESET}"
    sleep 1

    echo -e "${BLUE}[>]Uninstall current network visibility services?${RESET}"
    until [[ $REMOVE_NET_SERVICES =~ ^(y|n)$ ]]; do
        read -rp "[y/n]? " REMOVE_NET_SERVICES
    done

    if [[ $REMOVE_NET_SERVICES == "y" ]]; then
        RemoveServices
    fi

    echo -e "${BLUE}[>]Uninstall Bettercap?${RESET}"
    until [[ $REMOVE_BETTERCAP =~ ^(y|n)$ ]]; do
        read -rp "[y/n]? " REMOVE_BETTERCAP
    done

    if [[ $REMOVE_BETTERCAP == "y" ]]; then
        UninstallBettercap
    fi

    echo -e "${BLUE}[>]Uninstall ntopng?${RESET}"
    until [[ $REMOVE_NTOP =~ ^(y|n)$ ]]; do
        read -rp "[y/n]? " REMOVE_NTOP
    done

    if [[ $REMOVE_NTOP == "y" ]]; then
        Uninstallntopng
    fi

    echo -e "${BLUE}[>]Uninstall Zeek? (Removes any cron tasks)${RESET}"
    until [[ $REMOVE_ZEEK =~ ^(y|n)$ ]]; do
        read -rp "[y/n]? " REMOVE_ZEEK
    done

    if [[ $REMOVE_ZEEK == "y" ]]; then
        UninstallZeek
    fi

    echo -e "${BLUE}[>]Uninstall RITA? (Removes any cron tasks)${RESET}"
    until [[ $REMOVE_RITA =~ ^(y|n)$ ]]; do
        read -rp "[y/n]? " REMOVE_RITA
    done

    if [[ $REMOVE_RITA == "y" ]]; then
        UninstallRITA
    fi

    echo -e "${BLUE}[>]Uninstall MongoDB?${RESET}"
    until [[ $REMOVE_MONGODB =~ ^(y|n)$ ]]; do
        read -rp "[y/n]? " REMOVE_MONGODB
    done

    if [[ $REMOVE_MONGODB == "y" ]]; then
        UninstallMongoDBFromApt
    fi

    echo -e "${BLUE}[>]Uninstall Docker?${RESET}"
    until [[ $REMOVE_DOCKER =~ ^(y|n)$ ]]; do
        read -rp "[y/n]? " REMOVE_DOCKER
    done

    if [[ $REMOVE_DOCKER == "y" ]]; then
        UninstallDocker
    fi

}


function ManageMenu() {

    # Everything is called from the manage menu. Group functions into sets of functions for easier management.

    EchoStatus

    echo -e ""
    echo -e "What would you like to do?"
    echo -e ""
    echo -e "   1) Install Bettercap"
    echo -e "   2) Install RITA + MongoDB (if installed, shows command examples)" 
    echo -e "   3) Install Zeek / Reconfigure Zeek"
    echo -e "   4) Install ntopng"
    echo -e "   5) Install or start the network visibility services"
    echo -e "   6) Stop and disable the network visibility services"
    echo -e "   7) Remove firewall rules"
    echo -e "   8) Manage Cron Tasks"
    echo -e "   9) Randomize the Bettercap http(s)-ui credentials"
    echo -e "  10) Update Bettercap caplets"
    echo -e "  11) Uninstall network visibility services and optionally any installed packages"
    echo -e "   0) Exit"
    until [[ $MENU_OPTION =~ ^(1?[0-9])$ ]]; do
        read -rp "Select an option [1-11]: " MENU_OPTION
    done

    case $MENU_OPTION in
    1)
        InstallBettercap
        ;;
    2)
        InstallRITA
        ;;
    3)
        InstallZeek
        ;;
    4)
        Installntopng
        ;;
    5)
        StartServices
        ;;
    6)
        StopServices
        ;;
    7)
        RemoveFirewallRules
        ;;
    8)
        ManageCronTasks
        ;;
    9)
        UpdateBettercapCredentials
        ;;
    10)
        UpdateCaplets
        ;;
    11)
        Uninstall
        ;;
    0)
        exit 0
        ;;
    esac

}
IsRoot
ManageMenu
