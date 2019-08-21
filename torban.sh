#!/bin/bash
#set -x

#################
# Configuration #
#################
PATTERN="tcp dpt:22"

# Include core system utils in path.
PATH="/sbin:$PATH"

# Abandon ship if not running as root
if [[ $(id -u) -ne 0 ]]; then
	echo "Must run as root!"
	exit 1
fi

# Determine self IP
if [[ -z $1 ]]; then
	# We weren't passed an interface. Do http query.
	myip=$(wget -q http://4.meyep.tech/ -O -)
else
	# Get IP from the provided interface
	myip=$(ip addr show $1 | awk '/inet / { split($2,s,"/"); print s[1] }')
fi

# Figure out which list to update
oddnum=$(iptables -nL --line-numbers | awk '/torodd/ { print $1 }')
evennum=$(iptables -nL --line-numbers | awk '/toreven/ { print $1 }')
if [[ ! -z $oddnum ]]; then
	# The odd list is active, update even.
	target_set=toreven
	ipset flush toreven
	target_line=$oddnum
elif [[ ! -z $evennum ]]; then
	# The even list is active, update odd.
	target_set=torodd
	ipset flush torodd
	target_line=$evennum
else
	# Nothing is set up. Create the sets, set odd for update, make even active for later.
	ipset create torodd hash:ip hashsize 2048
	ipset create toreven hash:ip hashsize 2048
	target_set=torodd
	target_line=$(iptables -nL --line-numbers | awk "/$PATTERN/ { print \$1 }")
	iptables -I INPUT $target_line -m set --match-set toreven src -j DROP
fi

# Get the list, skip the comments, and read line-by-line.
/usr/bin/wget -q https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=$myip -O - | /bin/sed '/^#/d' | while read tip
do
	# Add to the set
	ipset add $target_set $tip
done

# Switch to the updated set
iptables -R INPUT $target_line -m set --match-set $target_set src -j DROP

