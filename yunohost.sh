#!/bin/sh
set -eu

#
# CONFIGURATION
#

readonly DOMAIN=yunohost.example.com

readonly LAN=ens3
readonly LAN_IP4="10.0.2.15"
readonly LAN_GW4="10.0.2.2"
readonly LAN_PREFIX="24"
readonly LAN_NET4="10.0.2.0/$LAN_PREFIX"

readonly HOST_NAME=host
readonly HOST_FQDN="$HOST_NAME.$DOMAIN"

readonly DMZ=dmz0
readonly DMZ_NAME=dmz
readonly DMZ_FQDN="$DMZ_NAME.$DOMAIN"
readonly DMZ_GW4="192.168.100.1"
readonly DMZ_GW4_PTR="1.100.168.192"
readonly DMZ_IP4="192.168.100.2"
readonly DMZ_ROOTFS="/var/lib/lxc/$DMZ_NAME/rootfs"
readonly DMZ_SSH=1111

readonly DATA_DIR="/data/$DMZ_NAME"
readonly DATA_HOME="$DATA_DIR/home"
readonly DATA_MAIL="$DATA_DIR/mail"
readonly DATA_BACKUP="$DATA_DIR/backup"
readonly DATA_BACKUP_REMOTE="login@rsync.example.com:$HOST_NAME"

readonly YN_USER=test
readonly YN_USER_FIRST='Test-first'
readonly YN_USER_LAST='Test-last'

readonly MAIL_POSTMASTER="postmaster@$DOMAIN"
readonly MAIL_RELAY_USER="$MAIL_POSTMASTER"
readonly MAIL_RELAY_HOST='mail.example.com'
readonly MAIL_IMAP_HOST='mail.example.com'
readonly MAIL_RELAY_PORT='465'

readonly TIMEZONE='Europe/Paris'

# disable interactive prompts for package config/install
export DEBIAN_FRONTEND=noninteractive

# helper to get password
getpass()
{
	local p1 p2
	while true; do
		p1=$(systemd-ask-password "$*               :")
		p2=$(systemd-ask-password "$* (confirmation):")
		if [ "x$p1" = "x$p2" ]; then
			echo "$p1"
			break
		fi
		echo "!!! Password mismatch, try again !!!" >&2
	done
}

# helper to run command in container
dmzexec()
{
	lxc-attach -n "$DMZ_NAME" --clear-env --keep-var DEBIAN_FRONTEND -- /bin/sh -c "$*"
}

# helper to run occ commands in the container
nextcloud()
{
	dmzexec "cd /var/www/nextcloud && sudo -u nextcloud php8.1 --define apc.enable_cli=1 occ $*"
}

# helper to create a new file in DMZ
dmzcat()
{
	local perm="$1"
	local file="$DMZ_ROOTFS/$2"
	cat > "$file"
	chown 100000:100000 "$file"
	chmod "$perm" "$file"
}

# update resolv.conf helper
dmz_resolvconf() {
	rm -f "$DMZ_ROOTFS/etc/resolv.conf"
	dmzcat 644 /etc/resolv.conf << EOF
domain $DOMAIN
search $DOMAIN
nameserver $DMZ_GW4
EOF
}

idempotent_append() {
	local guard='# yunohost provisioning - do not remove'
	local file="$1"
	grep -q -F "$guard" "$1" && file="/dev/null"
	echo "$guard" >> "$file"
	cat >> "$file"
}

#
# FIREWALL
#

firewall()
{
nft -f - << EOF

# flush previous rules, delete chains and reset counters
flush ruleset

table ip filter {
	chain input {
		# default policy is drop
		type filter hook input priority -1; policy drop;
		# enable loopback traffic
		iifname "lo" counter accept
		# enable statefull rules (after that, only need to allow NEW conections)
		ct state related,established counter accept
		# drop packets with no known connections
		ct state invalid counter drop
		# accept local connections to DNS/UDP from DMZ
		iifname "$DMZ" udp dport domain counter accept
		# accept local connections from LAN
		iifname "$LAN" ip saddr $LAN_NET4 counter accept
		# accept local connections to SSH, HTTP and DNS/TCP from DMZ
		iifname "$DMZ" tcp dport { ssh, http, domain } counter accept
		# accept icmp
		ip protocol icmp counter accept
		# ignore dhcp requests on LAN
		iifname "$LAN" ip saddr 0.0.0.0 ip daddr 255.255.255.255 udp sport 68 udp dport 67 counter drop
		# drop and log anything else
		log prefix "[FW INPUT]:" counter drop
	}

	chain forward {
		# default policy is drop
		type filter hook forward priority -1; policy drop;
		# enable statefull rules (after that, only need to allow NEW conections)
		ct state related,established counter accept
		# drop packets with no known connections
		ct state invalid counter drop
		# accept all to DMZ -> WAN (DMZ is not allowed to initiate to LAN)
		iifname "$DMZ" oifname "$LAN" ip daddr != $LAN_NET4 counter accept
		# accept ssh, smtp, http, https, submission, imaps to DMZ
		oifname "$DMZ" tcp dport { ssh, smtp, http, https, submission, imaps } counter accept
		# accept icmp
		ip protocol icmp counter accept
		log prefix "[FW FORWARD ]:" counter drop
	}
}

table ip nat {
	chain prerouting {
		# default policy is accept
		type nat hook prerouting priority -100; policy accept;
		# new connections to smtp, http, https, submission, imaps are redirected to DMZ
		iifname "$LAN" ct state new tcp dport { smtp, http, https, submission, imaps } counter dnat to $DMZ_IP4
		# tcp port 2222 is redirected to DMZ ssh
		iifname "$LAN" ct state new tcp dport $DMZ_SSH counter dnat to $DMZ_IP4:ssh
	}

	chain postrouting {
		# default policy is accept
		type nat hook postrouting priority 100; policy accept;
		# DMZ is source-nated
		ip saddr $DMZ_IP4 oifname "$LAN" counter snat to $LAN_IP4
	}
}
EOF
} # end of firewall

#
# STOP
#  stop dmz container
#

stop()
{
lxc-stop -n "$DMZ_NAME" || true
ip link del dev "$DMZ" || true
# disable routing
sysctl -w net.ipv4.conf.all.forwarding=0
} # end of stop

#
# START
#  enable firewall and start dmz container
#

start()
{

stop

# create guest ifaces, needed for fw rules
ip link add dev "$DMZ" type veth peer guest

firewall

# enable routing
sysctl -w net.ipv4.conf.all.forwarding=1

# container interface setup
ip addr add "$DMZ_GW4/32" dev "$DMZ" peer "$DMZ_IP4/32"
ip link set dev "$DMZ" up

lxc-start -n "$DMZ_NAME"
# wait for lxc to be ready...
lxc-wait -n "$DMZ_NAME" -s RUNNING

## move veth peer to container

# get netns pid
local nspid
nspid=$(lxc-info -n "$DMZ_NAME" -p|awk '/PID:/{print $2}')
[ -z "$nspid" ] && exit 1

# make netns avail. to iproute2...
mkdir -p /var/run/netns
rm -f "/var/run/netns/$nspid"
ln -s "/proc/$nspid/ns/net" "/var/run/netns/$nspid"

# move iface to container under eth0 name and configure it
ip link set guest name eth0 netns "$nspid"
ip -n "$nspid" addr add dev eth0 $DMZ_IP4/32 peer $DMZ_GW4/32
ip -n "$nspid" link set dev eth0 up
ip -n "$nspid" route add default via $DMZ_GW4

# remove netns so iproute2 ignores it again
rm -f "/var/run/netns/$nspid"

} # end of start()

#
# PROVISION
#  setup host - must be run once
#

provision() {

# get passwords
readonly YN_ADMIN_PASS="$(getpass "Yunohost admin password")"
readonly YN_USER_PASS="$(getpass "Yunohost user '$YN_USER' password")"
readonly MAIL_RELAY_PASS="$(getpass "Mail relay user '$MAIL_RELAY_USER' password")"
readonly BORG_PASSPHRASE="$(getpass "Borg backup passphrase")"
export BORG_PASSPHRASE

### Setup host

## sysctl network settings for the host
idempotent_append /etc/sysctl.conf << EOF
# disable ipv6 - I know, I know...
net.ipv6.conf.all.disable_ipv6=1
# harden ipv4 stack
# rpf makes sure dmz cannot spoof its address
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.log_martians=1
# optimized network settings
net.core.default_qdisc=fq_codel
net.ipv4.tcp_ecn=1
net.ipv4.tcp_sack=1
net.ipv4.tcp_dsack=1
# enable TCP fastopen
net.ipv4.tcp_fastopen=1027
EOF
sysctl -p /etc/sysctl.conf

## minimal static network config to get basic internet connectivity

# just in case this stupid tool is there...
apt-get -y purge resolvconf || true

# configure DNS (will be overriden by dnsmasq later)
cat > /etc/resolv.conf << EOF
# Cloudflare
nameserver 1.1.1.1
nameserver 1.0.0.1
# Google
nameserver 8.8.8.8
EOF

echo "$HOST_FQDN" > /etc/hostname

# setup network
ifdown $LAN || true
cat > /etc/network/interfaces << EOF
auto lo
iface lo inet loopback

# LAN
auto $LAN
iface $LAN inet static
	address $LAN_IP4/$LAN_PREFIX
	gateway $LAN_GW4
EOF

# reload network config
hostname -F /etc/hostname
ifup $LAN || true

apt-get -y update
apt-get -y dist-upgrade
apt-get -y install chrony \
				   dnsmasq \
				   lxc \
				   vim \
				   net-tools \
				   msmtp-mta \
				   bsd-mailx \
				   unattended-upgrades \
				   apt-listchanges \
				   borgbackup \
				   logwatch \
				   smartmontools \
				   nftables

## setup Chrony
timedatectl set-timezone "$TIMEZONE"
[ -f /etc/chrony/chrony.conf.pkg ] || mv /etc/chrony/chrony.conf /etc/chrony/chrony.conf.pkg
cat > /etc/chrony/chrony.conf << EOF
pool 2.debian.pool.ntp.org iburst
keyfile /etc/chrony/chrony.keys
driftfile /var/lib/chrony/chrony.drift
ntsdumpdir /var/lib/chrony
logdir /var/log/chrony
maxupdateskew 100.0
rtcsync
makestep 1 3
allow $LAN_NET4
leapsectz right/UTC
EOF

## configure dnsmasq

# disable lxc-net: we do not use it, and it runs dnsmasq, clashing with our own
systemctl stop lxc-net
systemctl mask lxc-net

# create dnsmasq config
[ -f /etc/dnsmasq.conf.pkg ] || mv /etc/dnsmasq.conf /etc/dnsmasq.conf.pkg
cat > /etc/dnsmasq.conf << EOF
bogus-priv
resolv-file=/etc/resolv.dnsmasq
local=/$DOMAIN/
# need at least 1 except or will not answer
except-interface=enp0s4
no-dhcp-interface=$LAN
no-dhcp-interface=$DMZ
expand-hosts
domain=$DOMAIN
mx-host=$DOMAIN,$DOMAIN,10
ptr-record=$DMZ_GW4_PTR.in-addr.arpa,$HOST_FQDN
address=/use-application-dns.net/
EOF

# move DNS conf to be served by dnsmasq
mv /etc/resolv.conf /etc/resolv.dnsmasq

# hosts file: this will be served by dnsmasq
cat > /etc/hosts << EOF
127.0.0.1	localhost localhost.localdomain localhost.$DOMAIN
$LAN_IP4	$HOST_FQDN $HOST_NAME

$DMZ_IP4	$DMZ_FQDN $DMZ_NAME $DOMAIN
EOF

# use dnsmasq for local dns from now on
cat > /etc/resolv.conf << EOF
nameserver 127.0.0.1
EOF

systemctl restart dnsmasq
systemctl restart chrony

## setup msmtp on host
# do not use /etc/aliases as it is touched by packages
echo "default: root@$DOMAIN" > /etc/aliases.msmtp
cat > /etc/msmtprc << EOF
account default
host $DOMAIN
domain $HOST_FQDN
source_ip $LAN_IP4
auto_from on
maildomain $HOST_FQDN
aliases /etc/aliases.msmtp
EOF
# fix apparmor profile
echo "/etc/aliases.msmtp	r," > /etc/apparmor.d/local/usr.bin.msmtp
apparmor_parser -r /etc/apparmor.d/usr.bin.msmtp

## unattended upgrade
# make sure we get mails
echo 'Unattended-Upgrade::Mail "root";' | idempotent_append /etc/apt/apt.conf.d/50unattended-upgrades
# enable it
echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections
dpkg-reconfigure -f noninteractive unattended-upgrades

## setup borg
# use encryption for remote backups though
borg info "$DATA_BACKUP" || borg init --make-parent-dirs --encryption=repokey-blake2 "$DATA_BACKUP"
borg key export "$DATA_BACKUP" /root/borg.key
echo "$BORG_PASSPHRASE" > /root/borg.pass
chmod 400 /root/borg.key /root/borg.pass
## setup daily backups
cat > /etc/cron.daily/backup << EOF
#!/bin/sh
"$(readlink -f "$0")" backup
EOF
chmod 755 /etc/cron.daily/backup

## setup logwatch
cat > /etc/logwatch/conf/logwatch.conf << EOF
Detail = Low
MailFrom = root@$HOST_FQDN
EOF

## setup smartmontools
cat > /etc/smartd.conf << EOF
# test email on startup
/dev/vda -m root -M test
/dev/vdb -m root -M test

# Monitor all attributes, enable automatic online data collection,
# automatic Attribute autosave, and start a short self-test every
# day between 2-3am, and a long self test Saturdays between 3-4am.
# Send alert emails to root
/dev/vda -a -o on -S on -s (S/../.././01|L/../../5/03) -m root
/dev/vdb -a -o on -S on -s (S/../.././01|L/../../5/03) -m root
EOF
cat > /etc/default/smartmontools << EOF
start_smartd=yes
EOF
systemctl restart smartmontools

### Setup DMZ container

## Setup system for unprivileged containers
lxc-checkconfig

# allocate subuids/subgigs for container
usermod --add-subuids 100000-999999 "$USER"
usermod --add-subgids 100000-999999 "$USER"

# setup default config for containers
cat > /etc/lxc/default.conf << EOF
lxc.net.0.type = empty
lxc.apparmor.profile = generated
lxc.apparmor.allow_nesting = 1
lxc.idmap = u 0 100000 899999
lxc.idmap = g 0 100000 899999
EOF

## create container
lxc-info -n "$DMZ_NAME" ||
	lxc-create -n "$DMZ_NAME" -t download -- -d debian -r bullseye -a amd64 --keyserver keyserver.ubuntu.com

# add bind mount for /home and /var/mail
mkdir -p "$DATA_HOME" "$DATA_MAIL"
chmod '=0755' "$DATA_DIR"
chmod '=0755' "$DATA_HOME"
chmod '=3775' "$DATA_MAIL"
chown 100000:100000 "$DATA_HOME"
chown 100000:100008 "$DATA_MAIL"
idempotent_append "$DMZ_ROOTFS/../config" << EOF
# bind mount /home and /var/mail
lxc.mount.entry=$DATA_HOME home     none bind 0 0
lxc.mount.entry=$DATA_MAIL var/mail none bind 0 0
EOF

# setup container network
dmzcat 644 /etc/hostname << EOF
$DMZ_NAME
EOF

dmzcat 644 /etc/hosts << EOF
127.0.0.1	localhost localhost.localdomain localhost.$DOMAIN

$LAN_IP4	$HOST_FQDN $HOST_NAME
$DMZ_IP4	$DMZ_FQDN $DMZ_NAME $DOMAIN
EOF

# update resolv.conf
dmz_resolvconf

## sysctl network settings for the container
idempotent_append "$DMZ_ROOTFS/etc/sysctl.conf" << EOF
# disable ipv6 - I know, I know...
net.ipv6.conf.all.disable_ipv6=1
# harden ipv4 stack
# rpf will drop incoming packets blackholed by fail2ban
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
# do not log blackholed packets (too noisy)
net.ipv4.conf.all.log_martians=0
# optimized network settings
net.ipv4.tcp_ecn=1
net.ipv4.tcp_sack=1
net.ipv4.tcp_dsack=1
# enable TCP fastopen
net.ipv4.tcp_fastopen=1027
EOF

# make sure networkd will not mess up the network
ln -sf /dev/null "$DMZ_ROOTFS/etc/systemd/system/systemd-networkd.service"

# start container
start

# wait for systemd to be ready...
dmzexec "while [ ! -S /run/systemd/private ]; do sleep 1;done"
# wait for the system to be ready...
dmzexec systemctl is-system-running --wait || true

dmzexec timedatectl set-timezone "$TIMEZONE"

## install Yunohost with default user
dmzexec apt-get -y install fetchmail logwatch curl
dmzexec "[ -x /usr/bin/yunohost ] || curl 'https://install.yunohost.org' | bash -s -- -a"
dmzexec "yunohost tools --help 2>&1 >/dev/null || yunohost tools postinstall --domain '$DOMAIN' --user '$YN_USER' --fullname '$YN_USER_FIRST $YN_USER_LAST' --password '$YN_ADMIN_PASS' --ignore-dyndns"
dmzexec apt-get -y autoremove

# disable unused/incompatible services
dmzexec systemctl stop dnsmasq metronome ntp \
	sys-kernel-config.mount sys-kernel-debug.mount systemd-journald-audit.socket \
	systemd-networkd systemd-resolved systemd-networkd-wait-online \
	yunohost-firewall yunohost-api yunomdns
dmzexec systemctl mask dnsmasq metronome ntp \
	sys-kernel-config.mount sys-kernel-debug.mount systemd-journald-audit.socket \
	systemd-networkd systemd-resolved systemd-networkd-wait-online
# unfortunately we cannot mask those, so diable them
dmzexec systemctl disable yunohost-firewall yunohost-api yunomdns

# update resolv.conf again: avoid brain damage by resolvconf
dmz_resolvconf

# disable ssowat overlay
dmzexec yunohost settings set ssowat.panel_overlay.enabled -v no

# harden security
dmzexec yunohost settings set security.experimental.enabled -v yes

# disable xmpp
dmzexec "yunohost domain config set '$DOMAIN' feature.xmpp.xmpp -v no"

# setup yunohost config hooks to tweak conf automatically
mkdir -p "$DMZ_ROOTFS/etc/yunohost/hooks.d/conf_regen"
chown -R 100000:100000 "$DMZ_ROOTFS/etc/yunohost/hooks.d"
# make sure nginx use default resolver
dmzcat 755 /etc/yunohost/hooks.d/conf_regen/99-nginx_fixup << EOF
#!/bin/bash
set -eu
action=\$1
pending_dir=\$4
nginx_conf=\$pending_dir/../nginx/etc/nginx/conf.d/$DOMAIN.conf
[[ \$action == "pre" ]] || exit 0
[[ -w \$nginx_conf ]] || exit 1
sed -e '/resolver/d' \
    -i \$nginx_conf
EOF
# make sure only the main user can login through ssh
dmzcat 755 /etc/yunohost/hooks.d/conf_regen/99-ssh_fixup << EOF
#!/bin/bash
set -eu
action=\$1
pending_dir=\$4
ssh_conf=\$pending_dir/../ssh/etc/ssh/sshd_config
[[ \$action == "pre" ]] || exit 0
[[ -w \$ssh_conf ]] || exit 1
# disable logins and only allow main user
sed -e 's/^AllowGroups .*$/AllowUsers $YN_USER/' \
    -e '/^Match Address /d'             \
    -e '/PermitRootLogin yes/d'         \
    -i \$ssh_conf
EOF

# fixup postfix to relay through gandi mail
dmzexec "yunohost settings set email.smtp.smtp_relay_enabled -v yes"
dmzexec "yunohost settings set email.smtp.smtp_relay_host -v '$MAIL_RELAY_HOST'"
dmzexec "yunohost settings set email.smtp.smtp_relay_user -v '$MAIL_RELAY_USER'"
dmzexec "yunohost settings set email.smtp.smtp_relay_password -v '$MAIL_RELAY_PASS'"
dmzexec "yunohost settings set email.smtp.smtp_relay_port -v '$MAIL_RELAY_PORT'"

# setup fail2ban to use iproute2 instead of iptables
# as rpf is enabled (see sysctl above) incoming packets will be dropped too
# the metric magic is to distinguished between multiple jails
dmzcat 644 /etc/fail2ban/jail.local << EOF
[DEFAULT]
banaction = route
banaction_allports = route
EOF
dmzcat 644 /etc/fail2ban/action.d/route.local << EOF
[Definition]
actionban   = ip route add <blocktype> <ip> metric $(echo -n '<name>'|cksum|cut -f 1 -d ' ')
actionunban = ip route del <blocktype> <ip> metric $(echo -n '<name>'|cksum|cut -f 1 -d ' ')
[Init]
blocktype = blackhole
EOF
dmzexec systemctl restart fail2ban

# for some reason we need to manually install sury keys
# otherwise nextcloud won't install because of failing deps
dmzexec "curl https://packages.sury.org/php/apt.gpg | apt-key add -"

# install nextcloud into domain.tld/cloud with mail and calendar apps
dmzexec "yunohost app install nextcloud -a 'domain=$DOMAIN&path=/cloud&admin=$YN_USER&user_home=yes'"

# fixup nextcloud db to use 4-byte support
# https://docs.nextcloud.com/server/stable/admin_manual/configuration_database/mysql_4byte_support.html
nextcloud "maintenance:mode --on"
dmzexec "mysql nextcloud" << EOF
ALTER DATABASE nextcloud CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
EOF
nextcloud "config:system:set mysql.utf8mb4 --type boolean --value=true"
nextcloud "maintenance:repair"
nextcloud "maintenance:mode --off"

# enable files refresh
nextcloud "config:system:set filesystem_check_changes --value 1"

# install calendar, contacts and mail apps
nextcloud "app:install calendar"
nextcloud "app:install contacts"
nextcloud "app:install mail"

# install and configure previews
nextcloud "app:install previewgenerator"
nextcloud "config:system:set preview_max_x --value 2048"
nextcloud "config:system:set preview_max_y --value 2048"
nextcloud "config:system:set jpeg_quality --value 60"
nextcloud "config:app:set previewgenerator squareSizes --value='32 256'"
nextcloud "config:app:set previewgenerator widthSizes  --value='256 384'"
nextcloud "config:app:set previewgenerator heightSizes --value='256'"
nextcloud "config:app:set preview jpeg_quality --value='60'"
dmzcat 644 /etc/cron.d/99-nextcloud-preview << EOF
*/15  *  *  *  * nextcloud /usr/bin/php8.1 --define apc.enable_cli=1 /var/www/nextcloud/occ preview:pre-generate
EOF

# scan data and generate preview if any
nextcloud "files:scan-app-data"
nextcloud "files:scan-app-data"

# fixup some nextcloud configs...
nextcloud "config:import" << EOF
{
    "system": {
        "mail_smtpmode": "sendmail",
        "mail_sendmailmode": "smtp",
        "mail_from_address": "$MAIL_POSTMASTER",
        "mail_domain": "$DOMAIN",
        "app.mail.verify-tls-peer": false,
        "app.mail.accounts.default": {
            "email": "%EMAIL%",
            "imapHost": "localhost",
            "imapPort": 143,
            "imapSslMode": "none",
            "smtpHost": "localhost",
            "smtpPort": 587,
            "smtpSslMode": "tls"
        }
    }
}
EOF

# default fcgi timeouts are too low for nextcloud
dmzcat 644 "/etc/nginx/conf.d/$DOMAIN.d/99-fix-nextcloud-timeouts.conf" << EOF
proxy_connect_timeout 120s;
proxy_send_timeout 120s;
proxy_read_timeout 120s;
fastcgi_send_timeout 120s;
fastcgi_read_timeout 120s;
EOF
dmzexec systemctl reload nginx

## setup fetchmail

# fetchmail use vmail user and its homedire is set to /var/vmail
# unfortunately that does not exist and confuses fetchmail
mkdir -p "$DMZ_ROOTFS/var/vmail"
chown --reference="$DATA_MAIL/$YN_USER" "$DMZ_ROOTFS/var/vmail"

dmzcat 600 /etc/fetchmailrc << EOF
defaults ssl fetchall nokeep mda "/usr/lib/dovecot/deliver -d %T"
set postmaster "$MAIL_POSTMASTER"
set bouncemail
set no spambounce
set daemon 300

poll $MAIL_IMAP_HOST with proto imap port 993 and timeout 120
	user '$YN_USER@$DOMAIN' with pass "$YN_USER_PASS" is '$YN_USER' here
	user '$MAIL_RELAY_USER' with pass "$MAIL_RELAY_PASS" is '$YN_USER' here
EOF
chown --reference="$DATA_MAIL/$YN_USER" "$DMZ_ROOTFS/etc/fetchmailrc"

dmzcat 644 /etc/default/fetchmail << EOF
export LC_ALL=C
USER=vmail
START_DAEMON=yes
EOF

# FIXME: enable fetchmail if needed
#systemctl restart fetchmail
#systemctl enable fetchmail

# unattended upgrade: make sure we get mails
echo 'Unattended-Upgrade::Mail "root";' | idempotent_append "$DMZ_ROOTFS/etc/apt/apt.conf.d/50unattended-upgrades"
# enable it
echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | dmzexec debconf-set-selections
dmzexec dpkg-reconfigure -f noninteractive unattended-upgrades

# logwatch in dmz
dmzcat 644 /etc/logwatch/conf/logwatch.conf << EOF
Detail = Low
MailFrom = root@$DMZ_FQDN
EOF

# disable annoying warnings
dmzexec yunohost diagnosis run
dmzexec yunohost diagnosis ignore --filter ip test=dnsresolv || true
dmzexec yunohost diagnosis ignore --filter ip test=ipv6 || true
dmzexec yunohost diagnosis ignore --filter dnsrecords category=mail domain=$DOMAIN || true
dmzexec yunohost diagnosis ignore --filter dnsrecords category=xmpp domain=$DOMAIN || true
dmzexec yunohost diagnosis ignore --filter dnsrecords category=extra domain=$DOMAIN || true
dmzexec yunohost diagnosis ignore --filter ports category=xmpp service=metronome || true
dmzexec yunohost diagnosis ignore --filter ports port=5222 || true
dmzexec yunohost diagnosis ignore --filter ports port=5269 || true
dmzexec yunohost diagnosis ignore --filter web test=hairpinning || true
dmzexec yunohost diagnosis ignore --filter mail test=mail_fcrdns || true
dmzexec yunohost diagnosis ignore --filter services service=dnsmasq || true
dmzexec yunohost diagnosis ignore --filter services service=metronome || true
dmzexec yunohost diagnosis ignore --filter services service=yunohost-firewall || true
dmzexec yunohost diagnosis ignore --filter services service=yunohost-api || true
dmzexec yunohost diagnosis ignore --filter services service=yunomdns || true
dmzexec yunohost diagnosis ignore --filter mail test=mail_blacklist || true
dmzexec yunohost diagnosis ignore --filter mail test=mail_queue || true
dmzexec yunohost diagnosis ignore --filter basesystem test=high_number_auth_failure || true
dmzexec yunohost diagnosis ignore --filter yunohost diagnosis ignore --filter regenconf file=/etc/postfix/sasl_passwd.db || true
dmzexec yunohost diagnosis ignore --filter yunohost diagnosis ignore --filter regenconf file=/etc/systemd/system/yunohost-api.service || true
dmzexec yunohost diagnosis ignore --filter yunohost diagnosis ignore --filter regenconf file=/etc/systemd/system/yunohost-firewall.service || true

### Finalization

## upgrade...
upgrade

## start DMZ at boot
cat > /etc/rc.local << EOF
#!/bin/sh
# https://raid.wiki.kernel.org/index.php/Timeout_Mismatch 
echo 180 > /sys/block/vda/device/timeout
echo 180 > /sys/block/vdb/device/timeout
blockdev --setra 1024 /dev/vda
blockdev --setra 1024 /dev/vdb
# Yunohost
"$(readlink -f "$0")" start
exit 0
EOF
chmod 755 /etc/rc.local

# run the 1st backup & logwatch (also act as smoke test)
/etc/cron.daily/backup
/etc/cron.daily/00logwatch

} # end of provision

#
# BACKUP
#

yh_backup() {
	local name="$1"; shift
	dmzexec "yunohost backup delete '$name'" || true
	dmzexec "BACKUP_CORE_ONLY=1 yunohost backup create -n '$name' $*"
}

borg_backup() {
	local repo="$1"; shift
	# borg on host will backup home and mail
	# yunohost backups are put in home and will be backuped by borg
	BORG_PASSPHRASE="$(cat /root/borg.pass)"
	export BORG_PASSPHRASE
	borg create "$@" \
		--verbose \
		--filter AME \
		--list \
		--stats \
		--show-rc \
		--exclude "$DATA_HOME/yunohost.multimedia/share/Music/" \
		--exclude "$DATA_HOME/yunohost.multimedia/share/Video/" \
		--exclude "$DATA_HOME/yunohost.app/nextcloud/data/appdata_*/" \
		--compression zstd \
		"$repo::{hostname}-{now}" \
		$DATA_HOME \
		$DATA_MAIL
	borg prune --list \
		--prefix '{hostname}-' \
		--show-rc \
		--keep-daily 7 \
		--keep-weekly 4 \
		--keep-monthly 6 \
		"$repo"
}

backup() {

# backup system, excluding mails and home
local hooks
hooks="$(dmzexec "yunohost hook list backup" | awk '"-"==$1 && "data_mail" != $2 && "data_home" != $2{printf " %s", $2}')" && yh_backup system "--system $hooks" || true
# backup apps (excluding 'big' data (in home))
yh_backup apps --apps || true

# borg on host will backup home and mail
# yunohost backups are put in home and will be backuped by borg
borg_backup "$DATA_BACKUP" || true
# FIXME: enable remote backup
#borg_backup "$DATA_BACKUP_REMOTE" --remote-path=borg1

} # end of backup

#
# UPGRADE
#

upgrade() {

# update host
apt-get -y update
apt-get -y dist-upgrade
apt-get -y autoremove
apt-get -y clean

# update yunohost
dmzexec yunohost tools update
dmzexec yunohost tools upgrade system
dmzexec yunohost tools upgrade apps

# update nextcloud apps
nextcloud 'app:update --all'

# yunohost system update does not update everything
dmzexec apt-get -y update
dmzexec apt-get -y dist-upgrade
dmzexec apt-get -y autoremove
dmzexec apt-get -y clean

} # end of upgrade

#
# MAIN
#

{
{
case "${1:-none}" in
	"start")
		start
		;;
	"stop")
		stop
		;;
	"restart")
		start
		;;
	"provision")
		provision
		;;
	"backup")
		backup
		;;
	"firewall")
		firewall
		;;
	"upgrade")
		upgrade
		;;
	*)
		echo "Usage: $0 <start|stop|restart|provision|backup|firewall|upgrade>" >&2
		exit 1
esac
# redirect stdout to syslog local0.debug
} | logger -s -t "$0 $*" -p local0.debug 2>&1
# redirect stderr to syslog local0.warning (we need to swap stderr and stdout)
} 3>&2 2>&1 1>&3 | logger -s -t "$0 $*" -p local0.warning -s -p local0.warning

echo "success" | logger -t "$0 $*" -p local0.info
exit 0
