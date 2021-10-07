#!/bin/bash

# Setup bettercap and the necesary services for intercepting traffic on a RITA server or desktop vm
# Version=0.1 (still needs tested)

BLUE="\033[01;34m" # information
BOLD="\033[01;01m" # highlight
RESET="\033[00m"   # reset

# Root EUID check
if [ "${EUID}" -ne 0 ]; then
	echo "You need to run this script as root"
	exit 1
fi

function setupAntidote() {
	# Normal user
	UID1000="$(grep '1000' /etc/passwd | cut -d ':' -f 1)"
	# Public Network Interface Card
	PUB_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
	# Replace this variable with the latest binary releases when available
	BETTERCAP_VER="bettercap_linux_amd64_v2.31.1"
	# Default path to http(s) conf files that contain credentials
	HTTP_CONF='/usr/local/share/bettercap/caplets/http-ui.cap'
	HTTPS_CONF='/usr/local/share/bettercap/caplets/https-ui.cap'

	# Check if RITA is installed
	if ! (command -v rita); then
		echo -e "${BLUE}[i]RITA not installed, visit ${RESET}${BOLD}https://github.com/activecm/rita/releases/latest${RESET}"
		echo -e "${BLUE}[>]or use: ${RESET}${BOLD}curl -Lf 'https://raw.githubusercontent.com/activecm/rita/v4.4.0/install.sh' > rita-install.sh${RESET}"
	fi

	# Check if bettercap is installed
	if [ -e /usr/local/bin/bettercap ]; then
		echo -e "${BLUE}[✓]Found /usr/local/bin/bettercap...${RESET}"
	else
		# Make a temporary working directory
		if [ -d /tmp/antidote/ ]; then
			rm -rf /tmp/antidote
		fi

		mkdir /tmp/antidote

		SETUPDIR=/tmp/antidote
		export SETUPDIR

		cd "$SETUPDIR" || (exit && echo "Failed changing into setup directory. Quitting.")
		echo -e "${BLUE}[i]Changing working directory to $SETUPDIR${RESET}"


		echo -e "${BLUE}[i]Installing any essential packages required by bettercap from apt...${RESET}"
		# Install essential packages
		apt update
		apt install -y libpcap0.8 libusb-1.0-0 libnetfilter-queue1 unzip

		# Install bettercap pre-compiled binary from GitHub
		# Check for the latest version: https://github.com/bettercap/bettercap/releases/latest
		echo -e "${BLUE}[i]Fetching bettercap binary and checksum from GitHub with curl...${RESET}"
		pkexec --user "$UID1000" curl -Lf 'https://github.com/bettercap/bettercap/releases/download/v2.31.1/'"$BETTERCAP_VER"'.sha256' > "$SETUPDIR"/"$BETTERCAP_VER"'.sha256'
		pkexec --user "$UID1000" curl -Lf 'https://github.com/bettercap/bettercap/releases/download/v2.31.1/'"$BETTERCAP_VER"'.zip' > "$SETUPDIR"/"$BETTERCAP_VER"'.zip'
		# Use curl as normal user, to specified directory using shell redirection `>` changing ownership back to root
		# Else curl outputs file to normal user's home dir

		echo -e "${BLUE}[i]Extracting bettercap binary from archive...${RESET}"
		unzip ./"$BETTERCAP_VER".zip 'bettercap'
		
		sleep 1
		
		echo -e "${BLUE}[i]Checking sha256sum...${RESET}"
		sha256sum -c ./"$BETTERCAP_VER".sha256 || (exit && echo "Quitting.")
		# If 'bettercap: OK' add it to your path
		
		sleep 2

		echo -e "${BLUE}[i]Installing bettercap...${RESET}"
		chmod 755 ./bettercap
		chown root:root ./bettercap
		sudo mv ./bettercap -t /usr/local/bin/

		echo -e "${BLUE}[i]Ensuring bettercap is in current PATH...${RESET}"
		command -v bettercap || (exit && echo "Bettercap not found in PATH. Quitting.")


		# Perform error checks (will need tested as conditional statements here)

		## If you see 'libpcap.so.1 library is not available' you'll need to symbolicly link libpcacp.so to libpcacp.so.1.
		## Additional packages required to resolve error:
		#sudo apt install -y libpcap-dev net-tools
		#find / -type f -name "libpcap.so" 2>/dev/null
		## Note location of libpcap.so if yours is different than the following location:
		#sudo ln -s '/usr/lib/x86_64-linux-gnu/libpcacp.so' '/usr/lib/x86_64-linux-gnu/libpcacp.so.1'
		## If you see the error 'libnetfilter_queue.so.1 is not available":
		#sudo apt install libnetfiler-queue-dev

		# Update caplets and web-ui
		echo -e "${BLUE}[i]Updating bettercap resources...${RESET}"
		bettercap -eval "caplets.update; ui.update; q" || (exit && echo "Error updating bettercap resources. Quitting.")

		sleep 2 
	echo -e "${BLUE}[✓]Done.${RESET}"
	fi

	# gpg --gen-random changed from 24 to 26, 24 outputs a trailing slash `/` that doesn't work well with sed
	# Replace default http credentials if found
	if (grep -Eqx "^set api.rest.(username user|password pass)$" "$HTTP_CONF"); then
			echo -e "${BLUE}[i]Replacing default http web interface credentials (user::pass)...${RESET}"
			sudo sed -i 's/^set api.rest.password pass$/set api.rest.password '"$(gpg --gen-random --armor 0 26)"'/' /usr/local/share/bettercap/caplets/http-ui.cap
			sudo sed -i 's/^set api.rest.username user$/set api.rest.username '"$(gpg --gen-random --armor 0 26)"'/' /usr/local/share/bettercap/caplets/http-ui.cap
	fi
	# Replace default https credentials if found
	if (grep -Eqx "^set api.rest.(username user|password pass)$" "$HTTPS_CONF"); then
			echo -e "${BLUE}[i]Replacing default https web interface credentials (user::pass)...${RESET}"
			sudo sed -i 's/^set api.rest.password pass$/set api.rest.password '"$(gpg --gen-random --armor 0 26)"'/' /usr/local/share/bettercap/caplets/https-ui.cap
			sudo sed -i 's/^set api.rest.username user$/set api.rest.username '"$(gpg --gen-random --armor 0 26)"'/' /usr/local/share/bettercap/caplets/https-ui.cap
	fi

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
ExecStart=/usr/local/bin/bettercap -eval 'net.recon on; arp.spoof on; set arp.spoof.fullduplex true; set events.stream.output /var/log/bettercap.log; http-ui on'
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
ExecStart=/usr/local/bin/bettercap -eval 'net.recon on; arp.spoof on; set arp.spoof.fullduplex true; set events.stream.output /var/log/bettercap.log; api.rest on'
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

	# Cleanup
	rm -rf "$SETUPDIR"

	#Save script for management
	if ! [ -e /usr/local/bin/setup-antidote.sh ]; then
		echo -e "${BLUE}[i]Adding setup-antidote.sh to /usr/local/bin/${RESET}"
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
	echo -e "${BOLD}Happy hunting!${RESET}"
}

function removeAntidote() {
	# Undo and uninstall all components related to arp-cache antidoting and bettercap
	echo -e "${BLUE}[i]Removing the following services and files:${RESET}"
	echo -e "${BLUE}[i]Note: these files can easily be reinstalled by re-running the script${RESET}"
	echo -e "${BOLD}service: /etc/systemd/system/arp-antidote.service${RESET}"
	echo -e "${BOLD}service: /etc/systemd/system/bettercap-forwarding.service${RESET}"
	echo -e "${BOLD}file: /etc/iptables/enable-forwarding.sh${RESET}"
	echo -e "${BOLD}file: /etc/iptables/disable-forwarding.sh${RESET}"
	echo -e "${BOLD}file: /etc/sysctl.d/20-bettercap.conf${RESET}"

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
		echo -e "${BOLD}file: /usr/local/bin/bettercap${RESET}"
		echo -e "${BOLD}dir: /usr/local/share/bettercap${RESET}"
		echo -e "${BLUE}[i]Not removing any bettercap.log files, review /var/log/ or ~/ if any exist.${RESET}"
		rm /usr/local/bin/bettercap
		rm -rf /usr/local/share/bettercap
	fi
	echo -e "${BLUE}[✓]Bettercap removed.${RESET}"
	
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

# Command-Line-Arguments
function manageMenu() {
	if [ -e /etc/systemd/system/arp-antidote.service ]; then 
		echo ""
		echo "Network visibility services already installed."
		echo "https://github.com/straysheep-dev/network-visibility"
		echo ""
		echo "What would you like to do?"
		echo ""
		echo "   1) Randomize the http(s)-ui credentials after updating caplets"
		echo "   2) Stop and remove the arp-cache services, optionally also bettercap"
		echo "   3) Exit"
		until [[ $MENU_OPTION =~ ^[1-3]$ ]]; do
			read -rp "Select an option [1-4]: " MENU_OPTION
		done

		case $MENU_OPTION in
		1)
			setupAntidote
			;;
		2)
			removeAntidote
			;;
		3)
			exit 0
			;;
		esac

	else

		setupAntidote

	fi	
}
manageMenu
