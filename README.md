# scripts
The contents of this repository are various unrelated scripts that others may find useful.

## pwcheck.py
Check passwords against the [Have I Been Pwned?](https://haveibeenpwned.com/)
API. Import as a python module to use the `check_hash()` or `check_password()`
functions, or run on the command line with password passed by parameter,
environment variable, or by prompt. Provides result via human-readable text
and return code: 0 = a good password, 1 = password exists on at least one list.

## reboot-checker (.service, .timer)
Want to know when your system reboots? This set of systemd units will send root
an email when the server reboots. Useful for remote systems.

## torban.sh
Want to block people from using the tor network to attack your system from
multiple IPs? This script uses the the API from tor to identify the endpoints
that can reach you and the ipset functionality in the kernel to efficiently
store the list for lookup. If passed a parameter, it will look up the IP from
that interface. Otherwise it will use an http remote IP request. Inserts the
iptables rule before a likely pattern for your SSH allow filter. Customize
$PATTERN at the top of the file for the rule you'd like to precede. May
require installing the ipset tools for your distro.
