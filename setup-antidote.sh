#!/bin/bash

# Setup bettercap and the necesary services for intercepting traffic on a RITA server or desktop vm
# Version=0.2 (tested on 18.04.6 Desktop and Server)

BLUE="\033[01;34m" # information
BOLD="\033[01;01m" # highlight
RESET="\033[00m"   # reset

UID1000="$(grep '1000' /etc/passwd | cut -d ':' -f 1)"                               # Normal user
PUB_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"     # Public Network Interface Card
HTTP_CONF='/usr/local/share/bettercap/caplets/http-ui.cap'                           # Default path to http(s) conf files that contain credentials
HTTPS_CONF='/usr/local/share/bettercap/caplets/https-ui.cap'

RITA_VER='4.4.0'                                                                     # Replace variable when latest release is available
RITA_HASH='2a707a9046ce7d0e83392f908fcebe6cacca57517437679303ab5b755a0294c1'         # Replace variable when latest release is available
BETTERCAP_VER='2.31.1'                                                               # Replace this variable when latest binary release is available
BETTERCAP_AARCH64_HASH='a278b191f7d36419d390dfca4af651daf1e9f1c7900ec1b3f627ab6c2f7b57e2' # Replace this variable when latest binary release is available
BETTERCAP_AMD64_HASH='74e85473d8cbeaa79b3c636032cbd0967387c4e9f95e253b4ae105eccd208a4f'   # Replace this variable when latest binary release is available

# System arch check
if (uname -mrs | grep -q 'x86_64'); then
	BETTERCAP_BIN="bettercap_linux_amd64_v$BETTERCAP_VER"
elif (uname -mrs | grep -q 'aarch64'); then
	BETTERCAP_BIN="bettercap_linux_aarch64_v$BETTERCAP_VER"
else
	echo "${BOLD}[i]Currently supported architectures: x86_64, aarch64${RESET}" && exit 1
fi



# Root EUID check
if [ "${EUID}" -ne 0 ]; then
	echo "You need to run this script as root"
	exit 1
fi

function makeTemp() {
		# Make a temporary working directory
		if [ -d /tmp/antidote/ ]; then
			rm -rf /tmp/antidote
		fi

		mkdir /tmp/antidote

		SETUPDIR=/tmp/antidote
		export SETUPDIR

		cd "$SETUPDIR" || (echo "Failed changing into setup directory. Quitting." && exit 1)
		echo -e "${BLUE}[i]Changing working directory to $SETUPDIR${RESET}"
}


function installRITA() {
	# Check if RITA is installed
	echo -e ""
	echo -e "${BLUE}[i]Checking path for RITA...${RESET}"
	if ! (command -v rita); then
		sleep 2
		echo -e "${BLUE}[i]RITA not installed, visit ${RESET}${BOLD}https://github.com/activecm/rita/releases/latest${RESET}"
		echo -e "${BLUE}[>]or use: ${RESET}${BOLD}curl -Lf 'https://raw.githubusercontent.com/activecm/rita/v$RITA_VER/install.sh' > rita-installer.sh${RESET}"

		echo ""
		echo -e "${BLUE}[?]Would you like to install RITA automatically with this script?${RESET}"
		until [[ $INSTALL_RITA =~ ^(y|n)$ ]]; do
			read -rp "[y/n]? " INSTALL_RITA
		done

		if [[ $INSTALL_RITA == "y" ]]; then
			echo -e "${BLUE}[i]Checking path for curl...${RESET}"
			if ! (command -v curl); then
				apt install -y curl
			fi
			sleep 1
			curl -Lf 'https://raw.githubusercontent.com/activecm/rita/v'"$RITA_VER"'/install.sh' > rita-installer.sh && \
			echo -e "${BLUE}[i]Checking sha256sum...${RESET}"
			if ! (sha256sum ./rita-installer.sh | grep -qx  "$RITA_HASH  ./rita-installer.sh"); then
				echo "Bad checksum. Quitting." && exit 1
			else
				echo 'OK'
			fi
			for installer in "$(pwd)"/rita-installer.sh; do 
				chown root:root "$installer"
				chmod 755 "$installer"
				echo -e "${BLUE}[>]Installing RITA..."
				sleep 2
				"$installer"
				sleep 2
			done
		fi
	fi
}

function installPackages() {
	# Check if bettercap is installed
	echo -e "${BLUE}[i]Checking path for bettercap...${RESET}"
	if ! (command -v bettercap); then
		echo -e "${BLUE}[i]Installing any essential packages required by bettercap and RITA from apt...${RESET}"
		# Install essential packages
		apt update
		apt install -y curl libpcap0.8 libusb-1.0-0 libnetfilter-queue1 unzip

		# Install bettercap pre-compiled binary from GitHub
		# Check for the latest version: https://github.com/bettercap/bettercap/releases/latest
		echo -e "${BLUE}[i]Fetching bettercap binary and checksum from GitHub with curl...${RESET}"
		curl -Lf 'https://github.com/bettercap/bettercap/releases/download/v'"$BETTERCAP_VER"'/'"$BETTERCAP_BIN"'.sha256' > "$SETUPDIR"/"$BETTERCAP_BIN"'.sha256'
		curl -Lf 'https://github.com/bettercap/bettercap/releases/download/v'"$BETTERCAP_VER"'/'"$BETTERCAP_BIN"'.zip' > "$SETUPDIR"/"$BETTERCAP_BIN"'.zip'

		echo -e "${BLUE}[i]Extracting bettercap binary from archive...${RESET}"
		unzip ./"$BETTERCAP_BIN".zip 'bettercap'

		sleep 1

		echo ""
		echo -e "${BLUE}[i]Checking sha256sum...${RESET}"
		# Check against known hash
		(grep -qxE "SHA256\(bettercap\)= ($BETTERCAP_AARCH64_HASH|$BETTERCAP_AMD64_HASH)" ./"$BETTERCAP_BIN".sha256 && \
		# Check against downloaded hash
		sha256sum -c ./"$BETTERCAP_BIN".sha256) || (echo "Bad checksum. Quitting." && exit 1)
		# If 'bettercap: OK' add it to your path, otherwise exit, leaving the binary behind in $SETUPDIR to examine.

		sleep 2

		echo -e "${BLUE}[i]Installing bettercap...${RESET}"
		chmod 755 ./bettercap
		chown root:root ./bettercap
		sudo mv ./bettercap -t /usr/local/bin/

		echo -e "${BLUE}[i]Ensuring bettercap is in current PATH...${RESET}"
		command -v bettercap || (echo "Bettercap not found in PATH. Quitting." && exit 1)


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


		# Update caplets and web-ui
		echo ""
		echo -e "${BLUE}[i]Updating bettercap resources...${RESET}"
		bettercap -eval "caplets.update; ui.update; q" || (echo "Error updating bettercap resources. Quitting." && exit 1)

		sleep 2 
	echo -e "${BLUE}[✓]Done.${RESET}"
	fi
}

function updateCredentials() {
	# Replace default http credentials if found
	if (grep -Eqx "^set api.rest.(username user|password pass)$" "$HTTP_CONF"); then
			echo -e "${BLUE}[i]Replacing default http web interface credentials (user::pass)...${RESET}"
			sudo sed -i 's/^set api.rest.password pass$/set api.rest.password '"$(tr -dc '[:alnum:]' < /dev/urandom | fold -w 32 | head -n 1)"'/' /usr/local/share/bettercap/caplets/http-ui.cap
			sudo sed -i 's/^set api.rest.username user$/set api.rest.username '"$(tr -dc '[:alnum:]' < /dev/urandom | fold -w 32 | head -n 1)"'/' /usr/local/share/bettercap/caplets/http-ui.cap
			# Restart bettercap for http-ui to accept new credentials
			if (systemctl is-active --quiet arp-antidote.service); then
				systemctl restart arp-antidote
			fi
	else
		echo ""
		echo -e "${BOLD}[i]http-ui credentials already randomized, current entries below.${RESET}"
	fi
	# Replace default https credentials if found
	if (grep -Eqx "^set api.rest.(username user|password pass)$" "$HTTPS_CONF"); then
			echo -e "${BLUE}[i]Replacing default https web interface credentials (user::pass)...${RESET}"
			sudo sed -i 's/^set api.rest.password pass$/set api.rest.password '"$(tr -dc '[:alnum:]' < /dev/urandom | fold -w 32 | head -n 1)"'/' /usr/local/share/bettercap/caplets/https-ui.cap
			sudo sed -i 's/^set api.rest.username user$/set api.rest.username '"$(tr -dc '[:alnum:]' < /dev/urandom | fold -w 32 | head -n 1)"'/' /usr/local/share/bettercap/caplets/https-ui.cap
			# Restart bettercap for https-ui to accept new credentials
			if (systemctl is-active --quiet arp-antidote.service); then
				systemctl restart arp-antidote
			fi
	else
		echo ""
		echo -e "${BOLD}[i]https-ui credentials already randomized, current entries below.${RESET}"
	fi
}

function installServices() {
	# Update the web-ui credentials before starting any services

	# Check if the forwarding service exists
	if [ -e /etc/systemd/system/bettercap-forwarding.service ]; then
		echo -e "${BLUE}[✓]Forwarding service already installed...${RESET}"
	else
		# Create a persistent sysctl service for packet forwarding rules from walkthrough
		# https://github.com/straysheep-dev/network-visibility#arp-poisoning-antidoting-the-network
		echo -e "${BLUE}[i]Creating a sysctl service for packet forwarding...${RESET}"

		sleep 2

		echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/20-bettercap.conf
		echo 'net.ipv6.conf.all.forwarding=1' >>/etc/sysctl.d/20-bettercap.conf
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
Description=Packet forwarding for bettercap
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/enable-forwarding.sh
ExecStop=/etc/iptables/disable-forwarding.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" >/etc/systemd/system/bettercap-forwarding.service

		echo -e "${BLUE}[✓]Done.${RESET}"
	fi

	# Check if the arp-cache antidoting service exists
	if [ -e /etc/systemd/system/arp-antidote.service ]; then
		echo -e "${BLUE}[✓]ARP-antidote service already installed...${RESET}"
	else
		# Create arp-cache antidote as a service to spin up at boot
		# Prompt for desktop or server usage
		# Currently the only difference is the desktop service allows the http-ui on localhost.
		# Will need to add the ability to setup ssl/tls for the https-ui to listen publicly.
		echo ""
		echo -e "${BOLD}[?]What type of machine is this?${RESET}"
		until [[ $MACHINE_TYPE =~ ^(desktop|server)$ ]]; do
			read -rp "[desktop/server]? " MACHINE_TYPE
		done

		echo -e "${BLUE}[i]Installing arp-cache antidoting as a service...${RESET}"

		if [[ $MACHINE_TYPE == "desktop" ]]; then
		# Based on https://github.com/bettercap/bettercap/blob/master/bettercap.service
			echo "[Unit]
Description=Capture LAN traffic for network forensics
Documentation=https://bettercap.org, https://github.com/straysheep-dev/network-visibility
Wants=network.target
After=network.target

[Service]
Type=simple
PermissionsStartOnly=true
ExecStart=/usr/local/bin/bettercap -eval 'net.recon on; net.probe on; arp.spoof on; set arp.spoof.fullduplex true; http-ui on'
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target" >/etc/systemd/system/arp-antidote.service

		elif [[ $MACHINE_TYPE == "server" ]]; then
		# Based on https://github.com/bettercap/bettercap/blob/master/bettercap.service
			echo "[Unit]
Description=Capture LAN traffic for network forensics
Documentation=https://bettercap.org, https://github.com/straysheep-dev/network-visibility
Wants=network.target
After=network.target

[Service]
Type=simple
PermissionsStartOnly=true
ExecStart=/usr/local/bin/bettercap -eval 'net.recon on; net.probe on; arp.spoof on; set arp.spoof.fullduplex true; api.rest on'
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target" >/etc/systemd/system/arp-antidote.service
		fi

		systemctl daemon-reload
		systemctl enable bettercap-forwarding
		systemctl enable arp-antidote

		echo -e "${BOLD}[?]Start arp-cache antidoting the network now?${RESET}"
		until [[ $START_CHOICE =~ ^(y|n)$ ]]; do
			read -rp "[y/n]? " START_CHOICE
		done

		if [[ $START_CHOICE == "y" ]]; then
			# Start antidoting the local area network
			# See https://www.bettercap.org/usage/scripting/
			# and https://github.com/bettercap/scripts
			# for some additional interesting uses.
			echo -e "${BLUE}[i]Starting services...${RESET}"
			systemctl start bettercap-forwarding
			systemctl start arp-antidote
			echo -e "${BLUE}[✓]Done.${RESET}"
		else
			echo -e "${BLUE}[i]OK, bettercap services won't start until next reboot or by running:${RESET}"
			echo -e "${BOLD}[i]sudo systemctl restart bettercap-forwarding${RESET}"
			echo -e "${BOLD}[i]sudo systemctl restart arp-antidote${RESET}"
		fi
	fi
}

function cleanUp() {
	# Cleanup
	if [ -e "$SETUPDIR" ]; then
		rm -rf "$SETUPDIR"
	fi

	#Save script for management
	if ! [ -e /usr/local/bin/setup-antidote.sh ]; then
		echo -e "${BLUE}[i]Adding setup-antidote.sh to /usr/local/bin/ for management.${RESET}"
		find /home/"$UID1000"/ -type f -name "setup-antidote.sh" -print0 | xargs -0 cp -t /usr/local/bin/ && chmod 755 /usr/local/bin/setup-antidote.sh
	fi


	# Final echo to terminal
	echo ""
	echo "=====================[ Web UI Credentials ]========================="
	echo -e "${BLUE}[i](save in your credential manager)${RESET}"
	echo -e "${BOLD}[http]username: $(grep 'api.rest.username' /usr/local/share/bettercap/caplets/http-ui.cap | cut -d ' ' -f 3)${RESET}"
	echo -e "${BOLD}[http]password: $(grep 'api.rest.password' /usr/local/share/bettercap/caplets/http-ui.cap | cut -d ' ' -f 3)${RESET}"
	echo ""
	echo -e "${BOLD}[https]username: $(grep 'api.rest.username' /usr/local/share/bettercap/caplets/https-ui.cap | cut -d ' ' -f 3)${RESET}"
	echo -e "${BOLD}[https]password: $(grep 'api.rest.password' /usr/local/share/bettercap/caplets/https-ui.cap | cut -d ' ' -f 3)${RESET}"
	echo ""
}

function removeAntidote() {
	# Undo and uninstall all components related to arp-cache antidoting and bettercap
	echo -e ""
	echo -e "${BLUE}[i]NOTE: These can easily be reinstalled by re-running this script${RESET}"
	echo -e "${BOLD}Removing service: /etc/systemd/system/arp-antidote.service${RESET}"
	echo -e "${BOLD}Removing service: /etc/systemd/system/bettercap-forwarding.service${RESET}"
	echo -e "${BOLD}Removing file: /etc/iptables/enable-forwarding.sh${RESET}"
	echo -e "${BOLD}Removing file: /etc/iptables/disable-forwarding.sh${RESET}"
	echo -e "${BOLD}Removing file: /etc/sysctl.d/20-bettercap.conf${RESET}"

	systemctl stop arp-antidote
	systemctl disable arp-antidote
	systemctl stop bettercap-forwarding
	systemctl disable bettercap-forwarding

	rm /etc/systemd/system/arp-antidote.service
	rm /etc/systemd/system/bettercap-forwarding.service
	rm /etc/iptables/enable-forwarding.sh
	rm /etc/iptables/disable-forwarding.sh
	rm /etc/sysctl.d/20-bettercap.conf

	echo -e "${BLUE}Reloading system daemons...${RESET}"
	sleep 2
	sysctl --system
	systemctl daemon-reload
	echo -e "${BLUE}[✓]Done.${RESET}"
	
	echo -e "${BLUE}[?]Remove bettercap and caplets?${RESET}"
	until [[ $REMOVE_BETTERCAP =~ ^(y|n)$ ]]; do
		read -rp "[y/n]? " REMOVE_BETTERCAP
	done

	if [[ $REMOVE_BETTERCAP == "y" ]]; then
		echo -e "${BOLD}Removing file: /usr/local/bin/bettercap${RESET}"
		echo -e "${BOLD}Removing dir: /usr/local/share/bettercap${RESET}"
		echo -e "${BLUE}[i]NOTE: Not removing any bettercap.log files, review /var/log/, /root/, or ~/ if any exist.${RESET}"
		rm /usr/local/bin/bettercap
		rm -rf /usr/local/share/bettercap
		echo -e "${BLUE}[✓]Bettercap removed.${RESET}"
	fi


	if [ -e /usr/local/bin/setup-antidote.sh ]; then
		echo -e "${BLUE}[?]Remove /usr/local/bin/setup-antidote.sh?${RESET}"
		until [[ $REMOVE_INSTALLER =~ ^(y|n)$ ]]; do
			read -rp "[y/n]? " REMOVE_INSTALLER
		done

		if [[ $REMOVE_INSTALLER == "y" ]]; then
			rm /usr/local/bin/setup-antidote.sh
		fi
	fi
	echo -e "${BLUE}[✓]Done.${RESET}"
}

function startServices() {
	echo -e "${BLUE}[i]Starting and enabling services...${RESET}"
	# Checks for bettercap-forwarding.service
	if (systemctl is-active --quiet bettercap-forwarding.service); then
		echo "[i]bettercap-forwarding.service already running."
	elif (systemctl is-enabled --quiet bettercap-forwarding.service); then
		echo "[i]restarting bettercap-forwarding.service..."
		systemctl restart bettercap-forwarding
	else
		systemctl enable bettercap-forwarding
		systemctl restart bettercap-forwarding
	fi
	# Checks for arp-antidote.service
	if (systemctl is-active --quiet arp-antidote.service); then
		echo "[i]arp-antidote.service already running."
	elif (systemctl is-enabled --quiet arp-antidote.service); then
		echo "[i]restarting arp-antidote.service..."
		systemctl restart arp-antidote
	else
		systemctl enable arp-antidote
		systemctl restart arp-antidote
	fi
	echo -e "${BLUE}[✓]Done.${RESET}"
}

function stopServices() {
	echo -e "${BLUE}[i]Stopping and disabling services...${RESET}"
	# Checks for arp-antidote.service
	if ! (systemctl is-active --quiet arp-antidote.service); then
		echo "[i]arp-antidote.service already stopped."
		systemctl disable arp-antidote
	else
		systemctl stop arp-antidote
		systemctl disable arp-antidote
	fi
	# Checks for bettercap-forwarding.service
	if ! (systemctl is-active --quiet bettercap-forwarding.service); then
		echo "[i]bettercap-forwarding.service already stopped."
		systemctl disable bettercap-forwarding
	else
		systemctl stop bettercap-forwarding
		systemctl disable bettercap-forwarding
	fi
	echo -e "${BLUE}[✓]Done.${RESET}"
}

# Set of core functions called through setupAntidote
function setupAntidote() {
	makeTemp
	installRITA
	installPackages
	updateCredentials
	installServices
	cleanUp
}

# Command-Line-Arguments
function manageMenu() {
	if [ -e /etc/systemd/system/arp-antidote.service ]; then 
		echo -e ""
		echo -e "${BOLD}Network visibility services already installed.${RESET}"
		echo -e "${BLUE}https://github.com/straysheep-dev/network-visibility${RESET}"
		echo -e ""
		# Check if RITA is installed
		if ! [ -e /usr/local/bin/rita ]; then
			echo -e "${BLUE}[i]RITA not installed, visit ${RESET}${BOLD}https://github.com/activecm/rita/releases/latest${RESET}"
			echo -e "${BLUE}[>]or use: ${RESET}${BOLD}curl -Lf 'https://raw.githubusercontent.com/activecm/rita/v4.4.0/install.sh' > rita-installer.sh${RESET}"
		fi
		echo -e ""
		# Show arp-antidote.service status
		if (systemctl is-active --quiet arp-antidote.service); then
			if (systemctl is-enabled --quiet arp-antidote.service); then
				echo -e "${BLUE}●${RESET} arp-antidote.service is active and enabled (running)"
			else
				echo -e "${BLUE}●${RESET} arp-antidote.service ${BLUE}is active but not enabled${RESET} (running)"
			fi
		else
			if (systemctl is-enabled --quiet arp-antidote.service); then
				echo -e "● arp-antidote.service ${BOLD}not${RESET} active but is enabled (dead)"
			else
				echo -e "● arp-antidote.service ${BOLD}not${RESET} active or enabled (dead)"
			fi
		fi
		# Show bettercap-forwarding.service status
		if (systemctl is-active --quiet bettercap-forwarding.service); then
			if (systemctl is-enabled --quiet bettercap-forwarding.service); then
				echo -e "${BLUE}●${RESET} bettercap-forwarding.service is active and enabled (running)"
			else
				echo -e "${BLUE}●${RESET} bettercap-forwarding.service ${BLUE}is active but not enabled${RESET} (running)"
			fi
		else
			if (systemctl is-enabled --quiet bettercap-forwarding.service); then
				echo -e "● bettercap-forwarding.service ${BOLD}not${RESET} active but is enabled (dead)"
			else
				echo -e "● bettercap-forwarding.service ${BOLD}not${RESET} active or enabled (dead)"
			fi
		fi

		echo -e ""
		echo -e ""
		echo -e "What would you like to do?"
		echo -e ""
		echo -e "   1) Start and enable the services"
		echo -e "   2) Stop and disable the services"		
		echo -e "   3) Randomize the http(s)-ui credentials (after updating caplets)"
		echo -e "   4) Install RITA"
		echo -e "   5) Uninstall the services, optionally also bettercap"
		echo -e "   6) Exit"
		until [[ $MENU_OPTION =~ ^[1-6]$ ]]; do
			read -rp "Select an option [1-6]: " MENU_OPTION
		done

		case $MENU_OPTION in
		1)
			startServices
			;;
		2)
			stopServices
			;;
		3)
			updateCredentials
			cleanUp
			;;
		4)
			makeTemp
			installRITA
			sleep 1
			cleanUp
			;;
		5)
			removeAntidote
			;;
		6)
			exit 0
			;;
		esac

	else

		setupAntidote

	fi	
}
manageMenu
