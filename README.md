# network-visibility
Gain full network visibility on flat home or small office networks (quickly, and without a span or tap)

This is a write up of the excellent [No SPAN Port? No Tap? No Problem!](https://www.blackhillsinfosec.com/webcast-no-span-port-no-tap-no-problem/) webcast by [Black Hills Information Security](https://www.blackhillsinfosec.com/).

* [RITA](https://github.com/activecm/rita) + [ZEEK](https://zeek.org/)

* Ideal for flat home or small office networks

* Can capture host <==> host && host <==> gateway

* Works on Raspberry Pi 4, 64bit, 8G RAM (low hardware requirements)

* Can store metadata about the traffic rather than full packet capture (low storage requirements)

A [setup script](https://github.com/straysheep-dev/network-visibility/blob/main/manage-visibility.sh) has been added to help automate the steps below, in an attempt to learn how each component works (both individually and with the others). The goal is to be able to spin up, or spin down, and configure all the services you may need from a single menu on whatever Ubuntu-based device you have available.

## Contents
- [Install Ubuntu 18.04 or 20.04](#install-ubuntu-1804-or-2004-choose-desktop-or-server)
- [Install RITA / MongoDB / ZEEK](#install-rita--mongodb--zeek)
    * [Ubuntu 18.04 x86_64](#ubuntu-1804-x86_64)
    * [Ubuntu 18.04 arm64](#ubuntu-1804-arm64)
    * [Ubuntu 20.04 x86_64 + arm64](#ubuntu-2004-x86_64-and-arm64)
- [Installing Bettercap from Pre-compiled Binaries (GitHub)](#installing-bettercap-from-pre-compiled-binaries-github)
- [Resolving Errors](#resolving-errors)
- [Using the Web-UI](#using-the-web-ui)
- [Arp Poisoning (Antidoting?) the Network](#arp-poisoning-antidoting-the-network)
- [Putting It All Together](#putting-it-all-together)
- [Automated Setup](https://github.com/straysheep-dev/network-visibility/blob/main/setup-antidote.sh)
- [Configure RITA](#configure-rita)

## Install Ubuntu 18.04 or 20.04 (choose desktop or server)

NOTE: with RITA's shell installer on Ubuntu 20.04 mongodb will silently fail to install despite everything else running.

See: <https://github.com/activecm/rita/issues/587>

```bash
# https://releases.ubuntu.com               ## main images
# https://cdimage.ubuntu.com/releases/      ## raspi + alternate flavors
# https://ubuntu.com/download/raspberry-pi
# https://ubuntu.com/tutorials/how-to-install-ubuntu-on-your-raspberry-pi

curl -LfO 'https://releases.ubuntu.com/18.04/SHA256SUMS'
curl -LfO 'https://releases.ubuntu.com/18.04/SHA256SUMS.gpg'

# Server:
curl -LfO 'https://releases.ubuntu.com/18.04/ubuntu-18.04.6-live-server-amd64.iso'

# Desktop:
curl -LfO 'https://releases.ubuntu.com/18.04/ubuntu-18.04.6-desktop-amd64.iso'

# Raspberry Pi:
curl -LfO 'https://cdimage.ubuntu.com/releases/18.04/release/SHA256SUMS'
curl -LfO 'https://cdimage.ubuntu.com/releases/18.04/release/SHA256SUMS.gpg'
curl -LfO 'https://cdimage.ubuntu.com/releases/18.04/release/ubuntu-18.04.5-preinstalled-server-arm64+raspi4.img.xz'

gpg --keyid-format long --keyserver hkps://keyserver.ubuntu.com:443 --recv-keys '843938DF228D22F7B3742BC0D94AA3F0EFE21092'
gpg --verify --keyid-format long SHA256SUMS.gpg SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
OK
```

From here, continue setup using your hypervisor of choice. VMware and VirtualBox are solid starting points.

Remember that upgrading ubuntu 18.04 => 20.04 during install may break monogdb as mentioned above.


## Install RITA / MongoDB / ZEEK

### Ubuntu 18.04 x86_64

```bash
# Check for the latest version: https://github.com/activecm/rita/releases/latest
curl -Lf 'https://raw.githubusercontent.com/activecm/rita/v4.4.0/install.sh' > rita-install.sh
chmod +x rita-install.sh
sudo ./rita-install.sh

# If ZEEK fails to install at line 7xx, check that $(lsb_release -sr) is still '18.04'

# If /etc/rita isn't present but ZEEK and or mongodb installed successfully:
sudo ./install.sh -r --disable-zeek --disable-mongo

# You want that 'Thank you for installing RITA! Happy hunting!' line at the end

# check that both services are running:
sudo /opt/zeek/bin/zeekctl status
systemctl status mongod.service
```

NOTE: if installing RITA on [Security Onion](https://github.com/Security-Onion-Solutions/securityonion) it is smart enough to detect ZEEK already installed

### Ubuntu 18.04 arm64

```bash
# As of 2021-12-01 https://github.com/activecm/docker-zeek is the quickest method on 18.04 arm64 architecture
# There is currently no precompiled binary on https://build.opensuse.org/project/show/security:zeek for 18.04

# Install docker
# https://docs.docker.com/engine/install/ubuntu/
sudo apt-get install -y ca-certificates curl gnupg lsb-release
curl -fsSL 'https://download.docker.com/linux/ubuntu/gpg' > docker-archive-keyring.gpg
gpg --keyid-format long ./docker-archive-keyring.gpg | grep '9DC8 5822 9FC7 DD38 854A  E2D8 8D81 803C 0EBF CD88'

gpg --dearmor < ./docker-archive-keyring.gpg | sudo tee /usr/share/keyrings/docker-archive-keyring.gpg > /dev/null
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io

# Install docker-zeek
# https://github.com/activecm/docker-zeek
curl -fsSL 'https://raw.githubusercontent.com/activecm/docker-zeek/master/zeek' > zeek
sudo chown root:root ./zeek
sudo chmod 755 ./zeek
sudo mv ./zeek /usr/local/bin/zeek

sudo mkdir -p /opt/zeek/etc
# If you have issues with node.cfg, use the same configuration generation script that RITA's shell installer script uses:
curl -fsSL "https://raw.githubusercontent.com/activecm/bro-install/master/gen-node-cfg.sh" > "gen-node-cfg.sh"
curl -fsSL "https://raw.githubusercontent.com/activecm/bro-install/master/node.cfg-template" > "node.cfg-template"
sudo chown root:root ./gen-node-cfg.sh
sudo chown root:root ./node.cfg-template
sudo chmod 755 ./gen-node-cfg.sh
sudo chmod 644 ./node.cfg-template
sudo ./gen-node-cfg.sh

# Export Zeek version
# https://github.com/activecm/docker-zeek#zeek-version
# https://github.com/activecm/docker-zeek#supported-docker-tags
echo "export zeek_release=latest" | sudo tee -a /etc/profile.d/zeek.sh
# or
echo "export zeek_release='3.0'" | sudo tee -a /etc/profile.d/zeek.sh
# then:
source /etc/profile.d/zeek.sh

# Start docker-zeek
/usr/local/bin/zeek start
# Stop docker-zeek
/usr/local/bin/zeek stop
# Enable docker-zeek to automatically restart itself
/usr/local/bin/zeek enable
# Check status
/usr/local/bin/zeek status
# Check version
sudo docker exec -it zeek zeek --version
# To change versions, modify /etc/profile.d/zeek.sh and `source /etc/profile.d/zeek.sh`
# or export a different version tag, then:
/usr/local/bin/zeek restart
# Review versions you have in docker:
sudo docker image list

# Install the zeek-open-connections plugin
# https://github.com/activecm/zeek-open-connections/
# https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html
sudo docker exec -it zeek zkg refresh
sudo docker exec -it zeek zkg install zeek/activecm/zeek-open-connections
/usr/local/bin/zeek restart

# From here either continue below, or jump to the instructions for 20.04 to use RITA via docker instead.

# Install MongoDB (via apt-get from repo.mongodb.org)
# https://docs.mongodb.com/v4.2/installation/

curl -fsSLO https://www.mongodb.org/static/pgp/server-4.2.asc
gpg --with-fingerprint --keyid-format long ./server-4.2.asc | grep 'E162 F504 A20C DF15 827F  718D 4B7C 549A 058F 8B6B'

sudo apt-key add ./server-4.2.asc

echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu bionic/mongodb-org/4.2 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.2.list > /dev/null

sudo apt-get update
sudo apt-get install -y mongodb-org

# Potentially hold package versions back?
# https://docs.mongodb.com/v4.2/tutorial/install-mongodb-on-ubuntu/#install-the-mongodb-packages

systemctl start mongod
# If mongod doesn't start:
systemctl daemon-reload

# Ensure MongoDB is running
if ! (systemctl is-active mongod); then
    systemctl unmask mongod
    systemctl enable mongod
    systemctl restart mongod
fi

# Install RITA from source
# https://go.dev/doc/install
curl -fsSLO 'https://go.dev/dl/go1.17.4.linux-arm64.tar.gz'
sha256sum go1.17.4.linux-arm64.tar.gz | grep 'adab2483f644e2f8a10ae93122f0018cef525ca48d0b8764dae87cb5f4fd4206'
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.17.4.linux-arm64.tar.gz

# Create the following PATH file at /etc/profile.d/go.sh
if [ -d "/usr/local/go" ] ; then
    PATH="$PATH:/usr/local/go/bin"
fi

# Source the updated PATH
source /etc/profile.d/go.sh

# Add go to sudo's PATH by executing `sudo visudo` and adding
# '/usr/local/go/bin:' to the `secure_path=` variable (without single quotes)
sudo visudo

# Confirm go is in $PATH
go version
sudo go version

# Clone RITA from GitHub
git clone https://github.com/activecm/rita.git
cd rita
# `make` will produce a rita binary in the current working directory
make

# to install the binary to /usr/local/bin/rita:
sudo make install
# or to install to a different location:
sudo PREFIX=/ make install

# RITA requires a few directories to be created for it to function correctly.
# https://github.com/activecm/rita/blob/master/docs/Manual%20Installation.md#configuring-the-system
# RITA may create some directories automatically during `sudo make install` as well.
sudo mkdir /etc/rita && sudo chmod 755 /etc/rita
sudo mkdir -p /var/lib/rita/logs && sudo chmod -R 755 /var/lib/rita
sudo cp ./etc/rita.yaml /etc/rita/config.yaml && sudo chmod 644 /etc/rita/config.yaml

# modify the config file as needed and test using the `rita test-config` command
sudo rita test-config
```

### Ubuntu 20.04 x86_64 and arm64

```bash
# Install Zeek
# You can use [docker-zeek](https://github.com/activecm/docker-zeek), or the precompiled binary for 20.04 on x86_64

# https://docs.zeek.org/en/v4.1.1/install.html
sudo apt-get update
sudo apt-get install -y python3-git python3-semantic-version

# https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek
curl -fsSL 'https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key' > ./zeek-release.key
gpg --with-fingerprint --keyid-format long ./zeek-release.key | grep 'AAF3 EB04 4C49 C402 A9E7  B9AE 69D1 B2AA EE3D 166A'

echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /" | sudo tee /etc/apt/sources.list.d/security:zeek.list > /dev/null
gpg --dearmor < ./zeek-release.key | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

sudo apt-get update
sudo apt-get install zeek

# Confirm Zeek config is valid
sudo /opt/zeek/bin/zeekctl check
sudo /opt/zeek/bin/zeekctl deploy

# Allow zkg packages to be installed
sudo sed -i 's/^.*@load packages.*$/@load packages/' /opt/zeek/share/zeek/site/local.zeek

# Install the zeek-open-connections plugin
# https://github.com/activecm/zeek-open-connections/
# https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html
sudo /opt/zeek/bin/zkg refresh
sudo /opt/zeek/bin/zkg install zeek/activecm/zeek-open-connections
sudo /opt/zeek/bin/zeekctl deploy

# Create the following PATH file at /etc/profile.d/zeek-path.sh
if [ -d /opt/zeek/ ] ; then
    PATH="/opt/zeek/bin:$PATH"
fi

# Install docker
# https://docs.docker.com/engine/install/ubuntu/
sudo apt-get install -y ca-certificates curl gnupg lsb-release
curl -fsSL 'https://download.docker.com/linux/ubuntu/gpg' > docker-archive-keyring.gpg
gpg --keyid-format long ./docker-archive-keyring.gpg | grep '9DC8 5822 9FC7 DD38 854A  E2D8 8D81 803C 0EBF CD88'

gpg --dearmor < ./docker-archive-keyring.gpg | sudo tee /usr/share/keyrings/docker-archive-keyring.gpg > /dev/null
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io

# Install docker-compose
# Replace '1.29.2' with your preferred version from the releases: https://github.com/docker/compose/releases
curl -fsSLO "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)"
curl -fsSLO "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m).sha256"
sha256sum -c ./docker-compose-Linux-x86_64.sha256

sudo chown root:root ./docker-compose-Linux-x86_64
sudo chmod 755 ./docker-compose-Linux-x86_64
sudo mv ./docker-compose-Linux-x86_64 /usr/local/bin/docker-compose

# Ensure binary is in PATH and works
docker-compose --version

# Install RITA with MongoDB using docker and docker-compose
# https://github.com/activecm/rita/blob/master/docs/Docker%20Usage.md
sudo docker pull quay.io/activecm/rita

# Create the RITA and docker-compose config files
sudo mkdir -p /etc/rita
sudo curl -fsSL 'https://raw.githubusercontent.com/activecm/rita/master/etc/rita.yaml' > /etc/rita/config.yaml
sudo curl -fsSL 'https://raw.githubusercontent.com/activecm/rita/master/docker-compose.yml' > /etc/rita/docker-compose.yml

# Create the following docker environment configuration file at /etc/rita/rita.env
# Change the VERSION and LOGS variables as needed for your environment
# https://github.com/activecm/rita/blob/master/docs/Docker%20Usage.md#running-rita-with-docker-compose
CONFIG=/etc/rita/rita.yaml
VERSION=v4.4.0
LOGS=/opt/zeek/logs/current

# The docker-specific configuration files 'docker-compose.yml' and 'rita.env' are placed in /etc/rita for this example.
# You will need to cd to /etc/rita/ to run the docker commands.
# https://docs.docker.com/compose/compose-file/compose-file-v3/#service-configuration-reference

# Ensure container runs successfully
cd /etc/rita
sudo docker-compose -f ./docker-compose.yml --env-file ./rita.env run --rm rita --version

# The path for the LOGS variable in /etc/rita/rita.env must be to the exact directory of the log files for the given day (how Zeek rotates logging)
# /opt/zeek/logs/yyyy-mm-dd
# or
# /opt/zeek/logs/current
# and is then called from the CLI as /logs
sudo docker-compose -f ./docker-compose.yml --env-file ./rita.env run --rm rita import /logs db_1

# Show DNS
sudo docker-compose -f ./docker-compose.yml --env-file ./rita.env run --rm rita show-exploded-dns db_1
sudo docker-compose -f ./docker-compose.yml --env-file ./rita.env run --rm rita show-exploded-dns db_1 -H | less -S    # move the less interface around with the arrow-keys if terminal output is messy at first
```


## Installing Bettercap from Pre-Compiled Binaries (Github)

<https://www.bettercap.org/installation/>

Note that for Raspberry Pi installs, the bettercap binary and checksum are for aarch64. Otherwise, the steps are remain the same.

```bash
# Check for the latest version: https://github.com/bettercap/bettercap/releases/latest
sudo apt install -y libpcap0.8 libusb-1.0-0 libnetfilter-queue1 unzip
curl -LfO 'https://github.com/bettercap/bettercap/releases/download/v2.31.1/bettercap_linux_amd64_v2.31.1.sha256'
curl -LfO 'https://github.com/bettercap/bettercap/releases/download/v2.31.1/bettercap_linux_amd64_v2.31.1.zip'
unzip bettercap_linux_amd64_v2.31.1.zip     # you can answer 'no' to replacing bettercap_linux_amd64_v2.31.1.sha256
sha256sum -c bettercap_linux_amd64_v2.31.1.sha256

# if 'bettercap: OK' add it to your path:

chmod 755 bettercap
sudo chown root bettercap
sudo chgrp root bettercap
sudo mv bettercap -t /usr/local/bin/

# run bettercap
bettercap --help
sudo bettercap
```

## Resolving Errors

* If you see 'libpcap.so.1 library is not available' you'll need to symbolicly link libpcacp.so to libpcacp.so.1.

Reference: <https://linuxhint.com/install-bettercap-on-ubuntu-18-04-and-use-the-events-stream/>

```bash
# additional packages required to resolve error:
sudo apt install -y libpcap-dev net-tools

find / -type f -name "libpcap.so" 2>/dev/null

# note location of libpcap.so if yours is different than the following location:
sudo ln -s '/usr/lib/x86_64-linux-gnu/libpcacp.so' '/usr/lib/x86_64-linux-gnu/libpcacp.so.1'
```

* If you see the error 'libnetfilter_queue.so.1 is not available":

```bash
sudo apt install libnetfiler-queue-dev
```

```sudo bettercap``` will run now in interactive mode

Reference: <https://www.bettercap.org/modules/core/ui/>

## Using the Web-UI

This is entirely optional, as you only need a single line on the command line to get arp cache poisoning running.

Reference: <https://www.bettercap.org/usage/webui/>

* Run bettercap's update mechanism to download the latest caplets and webui from github:
```bash
sudo bettercap -eval "caplets.update; ui.update; q"
```

If bettercap is running on Ubuntu Desktop and you'll only be accessing it locally from that machine:

**Edit the default credentials in /usr/local/share/bettercap/caplets/http-ui.cap**
```bash
# replace the default user/pass
sudo sed -i 's/^set api.rest.password pass$/set api.rest.password '$(tr -dc '[:alnum:]' < /dev/urandom | fold -w 32 | head -n 1)'/' /usr/local/share/bettercap/caplets/http-ui.cap
sudo sed -i 's/^set api.rest.username user$/set api.rest.username '$(tr -dc '[:alnum:]' < /dev/urandom | fold -w 32 | head -n 1)'/' /usr/local/share/bettercap/caplets/http-ui.cap
# store these values in your credential manager:
cat /usr/local/share/bettercap/caplets/http-ui.cap
```
If bettercap is running on Ubuntu Server or Desktop and you want to access it from another machine on the same network:

**Edit the default credentials in /usr/local/share/bettercap/caplets/https-ui.cap**
```bash
# replace the default user/pass
sudo sed -i 's/^set api.rest.password pass$/set api.rest.password '$(tr -dc '[:alnum:]' < /dev/urandom | fold -w 32 | head -n 1)'/' /usr/local/share/bettercap/caplets/https-ui.cap
sudo sed -i 's/^set api.rest.username user$/set api.rest.username '$(tr -dc '[:alnum:]' < /dev/urandom | fold -w 32 | head -n 1)'/' /usr/local/share/bettercap/caplets/https-ui.cap
# store these values in your credential manager:
cat /usr/local/share/bettercap/caplets/https-ui.cap
```

For a local desktop instance, access the web-ui by entering `http://127.0.0.1:80` into your browser

To reach a remote instance on the same network, browse to `https://<bettercap-device-ip>`

NOTE: If you planned to port forward via ssh to access the web-ui on a server instance, it does not work exactly as expected. Both the web-ui and rest api need to be accessible by the same client session meaning you'd need to forward two ports (443 and 8083) over the same ssh session.

## Arp Poisoning (Antidoting?) the Network

Ensure forwarding is enabled

Option 2 examples adapted from here: <https://github.com/angristan/wireguard-install>
```bash
# Option 1. if using ufw
# replace eth0 with your interface name
sudo ufw route allow in on eth0 out on eth0
# setup ip forwarding, uncomment the following lines in /etc/ufw/sysctl.conf:
sudo sed -i 's/^#net\/ipv4\/ip_forward=1/net\/ipv4\/ip_forward=1/' /etc/ufw/sysctl.conf
sudo sed -i 's/^#net\/ipv6\/conf\/default\/forwarding=1/net\/ipv6\/conf\/default\/forwarding=1/' /etc/ufw/sysctl.conf
sudo sed -i 's/^#net\/ipv6\/conf\/all\/forwarding=1/net\/ipv6\/conf\/all\/forwarding=1/' /etc/ufw/sysctl.conf
# allow routing
sudo ufw default allow routed
# restart the firewall:
sudo ufw disable
sudo ufw enable
sudo ufw status verbose | grep 'allow (routed)'

# Option 2. if not using ufw, and you want to create persistent systemctl rules:
sudo su
echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/20-bettercap.conf
echo 'net.ipv6.conf.all.forwarding=1' >>/etc/sysctl.d/20-bettercap.conf
sysctl --system

mkdir /etc/iptables

# replace eth0 with your interface name
echo "#!/bin/sh
iptables -I FORWARD -i eth0 -o eth0 -j ACCEPT
ip6tables -I FORWARD -i eth0 -o eth0 -j ACCEPT" > /etc/iptables/enable-forwarding.sh
# replace eth0 with your interface name
echo "#!/bin/sh
iptables -D FORWARD -i eth0 -o eth0 -j ACCEPT
ip6tables -D FORWARD -i eth0 -o eth0 -j ACCEPT" > /etc/iptables/disable-forwarding.sh

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

systemctl daemon-reload
systemctl enable bettercap-forwarding
systemctl start bettercap-forwarding
exit

# to remove the service:
sudo systemctl stop bettercap-forwarding.service
sudo systemctl disable bettercap-forwarding.service
sudo rm /etc/systemd/system/bettercap-forwarding.service
sudo rm /etc/sysctl.d/20-bettercap.conf
sudo rm /etc/iptables/enable-forwarding.sh
sudo rm /etc/iptables/disable-forwading.sh
sudo sysctl --system
sudo systemctl daemon-reload

# Option 3. to temporarily and simply enable forwarding (until next reboot):
sudo nano /proc/sys/net/ipv4/ip_forward
# change 0 to 1
sudo nano /proc/sys/net/ipv6/conf/all/forwarding
# change 0 to 1
sudo iptables -I FORWARD -i eth0 -o eth0 -j ACCEPT  # replace eth0 with your interface name
sudo ip6tables -I FORWARD -i eth0 -o eth0 -j ACCEPT # replace eth0 with your interface name

# confirm
cat /proc/sys/net/ipv4/ip_forward | grep '1'
cat /proc/sys/net/ipv6/conf/all/forwarding | grep '1'
```

Ways to start bettercap:
```bash
# Start bettercap interactive shell
sudo bettercap

# Start bettercap http-ui
sudo bettercap -caplet http-ui

# Start bettercap interactive shell, and enable logging to a file named 'bettercap-events.log'
sudo bettercap -eval "set events.stream.output ~/bettercap-events.log"
```

Update bettercap's caplets and web-ui from the latest on github:
```bash
sudo bettercap -eval "caplets.update; ui.update; q"
```

From here the `>>` commands work **both** over a CLI bettercap interactive session, or in the command bar on the web-ui (noted as >_ at the top of the UI)


* Enable events logging, show all events, then only show the most recent 2 events
```bettercap
>> set events.stream.output ~/bettercap-events.log
>> events.show
>> events.show 2
```

* Show a list of installed caplets.
```bettercap
>> caplets.show
```
* Show a list caplet search paths.
```bettercap
>> caplets.paths
```

The following examples are directly from here: <https://www.bettercap.org/usage/interactive/>

They detail the default $paths / folder structure used, as well as command variation.

```bash
sudo bettercap -caplet example

# In this case the search order will be:

./example.cap
./caplets/example.cap
Any folder in the environment variable $CAPSPATH (values are separated by :, like for $PATH).
/usr/local/share/bettercap/caplets/example.cap (the default path where caplets are installed).

# You can install (or update) the predefined caplets (hosted in this repository) by using the caplet module, either from the command line:
sudo bettercap -eval "caplets.update; q"

# Or simply from the interactive session:
>> caplets.update

# You can then check what???s been installed in /usr/local/share/bettercap/caplets/ with the command:
>> caplets.show
```
Host discovery examples taken from: <https://www.bettercap.org/modules/ethernet/net.recon/>
```bettercap
# discover hosts on local subnet
>> net.recon on

# show list of hosts
>> net.show

# clear list of hosts
>> net.clear

# stop net discovery
>> net.recon off
```

Actively probe for hosts in the local network:
```bettercap
# actively find hosts on local subnet
>> net.probe on

# stop active probe
>> net.probe off
```

Arp spoofing examples taken from: <https://www.bettercap.org/modules/ethernet/spoofers/arp.spoof/>

```bettercap
# capture only outgoing traffic, poison only the clients
>> arp.spoof on

# capture all outbound traffic, poisoning the router as well - fails if router has spoofing protections
>> set arp.spoof.fullduplex true

# capture all internal traffic neighbor <==> neighbor
>> set arp.spoof.internal true

# turn off arp cache poisoning:
>> arp.spoof off
```

## Putting It All Together:
```bash
# start bettercap with http web-ui
sudo bettercap -caplet http-ui
# either via bettercap interactive CLI over ssh or in the web-ui cmd bar:
>> net.recon on
>> net.probe on
>> arp.spoof on
>> arp.spoof.fullduplex true
# you're done! leave these running continuously to capture traffic
```

NOTE: If devices have built in arp spoofing protection, setup a DHCP server on the device running bettercap and RITA

To end a web session logout of the web-ui. The interactive shell will still be running until you `exit`

Simply run `>> exit` to end an interactive shell

If you want to visually confirm packets are being forwarded, review traffic from the device running bettercap with:
```bash
# replace eth0 with your interface name
sudo tcpdump -i eth0 -n -vv not port <ssh-port> and not port 139
# you should see indications of packets being redirected, similar to:
<neighbor-ip> > <bettercap-ip>: ICMP redirect <external-destination-ip> to host <real-gateway-ip>

sudo tcpdump -i enp0s3 -n -vv port 53
# you should see dns replies of domains being visited
```

## Configure RITA

* Rolling imports
```bash
rita import --rolling /path/to/your/zeek_logs name_your_dataset
rita import --rolling /opt/zeek/logs/<yyyy-mm-dd> first_database
```
* Cron job to run RITA every hour
```bash
rita import --rolling /opt/zeek/logs/$(date --date='-1 hour' +\%Y-\%m-\%d)/ dataset_name
```
* RITA usage
```bash
# print out all commands for parsing data
rita --help

# print help for specific commands
rita <command> --help
rita show-beacons --help

# use -H (human-readable) to format data into a table
rita <command> -H <dataset_name> | less -S
rita show-exploded-dns -H dataset_1 | less -S
```

## What Next?

* Configure bettercap commands to spin up as a service on start
* Happy hunting!
