#!/bin/sh

# original script by Todd Stein (toddbstein@gmail.com), Saturday, October 25, 2014 -- https://github.com/tablespoon/fun/blob/master/adblocker.sh
#
# Periodically download lists of known ad and malware servers, and prevents traffic from being sent to them.
# This is a complete rewrite of a script originally written by teffalump (https://gist.github.com/teffalump/7227752).
#
# edited by jhnhlstrm for Netgear R7000 routers running the Asuswrt-Merlin XVortex firmware
# updated 2016-01-20


HOST_LISTS="
        http://adaway.org/hosts.txt
        http://www.malwaredomainlist.com/hostslist/hosts.txt
        http://www.mvps.org/winhelp2002/hosts.txt
        http://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&startdate%5Bday%5D=&startdate%5Bmonth%5D=&star
"


BLOCKLIST=/tmp/mnt/sda1/adblocker/adblocker_hostlist
BLACKLIST=/tmp/mnt/sda1/adblocker/adblocker_blacklist
WHITELIST=/tmp/mnt/sda1/adblocker/adblocker_whitelist
TEMP_FILE=/tmp/mnt/sda1/adblocker/adblocker_temp
LOCKFILE=/tmp/adblocker.lock


# ensure this is the only instance running
if ! ln -s $$ "$LOCKFILE" 2>/dev/null; then
	# if the old instance is still running, exit
	former_pid=$(readlink "$LOCKFILE")
	if [ -e "/proc/$former_pid" ]; then
		exit
	else
		# otherwise, update the symlink
		ln -sf $$ "$LOCKFILE"
	fi
fi


# get script's absolute path and quote spaces for safety
cd "${0%/*}"
SCRIPT_NAME="$PWD/${0##*/}"
SCRIPT_NAME="${SCRIPT_NAME// /' '}"
cd "$OLDPWD"


# await internet connectivity before proceeding (in case rc.local executes this script before connectivity is achieved)
until ping -c1 -w3 google.com || ping -c1 -w3 sunet.se; do
        sleep 5
done &>/dev/null


# grab list of bad domains from the internet
IP_REGEX='([0-9]{1,3}\.){3}[0-9]{1,3}'
wget -qO- $HOST_LISTS | awk "/^$IP_REGEX\W/"'{ print "0.0.0.0",$2 }' | sort -uk2 >>"$TEMP_FILE"


# if the download succeeded, recreate the blocklist
if [ -s "$TEMP_FILE" ]; then
	# use the downloaded domains as a fresh block list
	mv "$TEMP_FILE" "$BLOCKLIST"
fi


# add blacklisted domains if any have been specified, ensuring no duplicates are added
if [ -s "$BLACKLIST" ]; then
	# create a pipe-delimited list of all non-commented words in blacklist and remove them from the block list
	black_listed_regex='\W('"$(grep -o '^[^#]\+' "$BLACKLIST" | xargs | tr ' ' '|')"')$'
	sed -ri "/${black_listed_regex//./\.}/d" "$BLOCKLIST"

	# add blacklisted domains to block list	
	awk '/^[^#]/ { print "0.0.0.0",$1 }' "$BLACKLIST" >>"$BLOCKLIST"
fi


# remove any private net IP addresses (just in case)
# this variable contains a regex which will be used to prevent the blocking of hosts on 192.168.0.0 and 10.0.0.0 networks
PROTECTED_RANGES='\W(192\.168(\.[0-9]{1,3}){2}|10(\.[0-9]{1,3}){3})$'
sed -ri "/$PROTECTED_RANGES/d" "$BLOCKLIST"


# remove any whitelisted domains from the block list
if [ -s "$WHITELIST" ]; then
	# create a pipe-delimited list of all non-commented words in whitelist and remove them from the block list
	white_listed_regex='\W('"$(grep -Eo '^[^#]+' "$WHITELIST" | xargs | tr ' ' '|')"')$'
	sed -ri "/${white_listed_regex//./\.}/d" "$BLOCKLIST"
fi


# add IPv6 blocking
sed -ri 's/([^ ]+)$/\1\n::      \1/' "$BLOCKLIST"


# add block list to dnsmasq config if it's not already there
if ! grep -q "$BLOCKLIST" /jffs/configs/dnsmasq.conf.add; then
	echo "# adblocking" >> /jffs/configs/dnsmasq.conf.add
	echo "address=/0.0.0.0/0.0.0.0" >> /jffs/configs/dnsmasq.conf.add
	echo "ptr-record=0.0.0.0.in-addr.arpa,0.0.0.0" >> /jffs/configs/dnsmasq.conf.add
	echo "addn-hosts=$BLOCKLIST" >> /jffs/configs/dnsmasq.conf.add
fi


# add script to cron utility with id "adblocker" if it's not already there
if ! cru l | grep -Fq "$SCRIPT_NAME" 2>/dev/null; then
	# adds 30 minutes of jitter to prevent undue load on the webservers hosting the lists we pull each week
	# unfortunately, there's no $RANDOM in this shell, so:
	DELAY=$(head /dev/urandom | wc -c | /usr/bin/awk "{ print \$0 % 30 }")
		# Download updated ad and malware server lists every Tuesday at 4:$(printf "%02d" "$DELAY") AM
		cru a adblocker ""$DELAY" 4 * * 2 "$SCRIPT_NAME""
fi


# restart dnsmasq service
service restart_dnsmasq


# clean up
if [ -f "$TEMP_FILE" ]; then
	rm -f "$TEMP_FILE"
fi

rm -f "$LOCKFILE"
