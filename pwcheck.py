#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
from hashlib import sha1
import requests
import argparse
import sys, os

parser = argparse.ArgumentParser(description="Check your password against the https://haveibeenpwned.com/ API.")
parser.add_argument('-q', '--quiet', action="store_true", help="No STDOUT. Only output is via return code.")
parser.add_argument("passwd", nargs="?", help="Password to check. If not provided, will also check $PWCHECK or prompt.")

def check_hash(h):
	"""
	Do the heavy lifting. Take the hash, poll the haveibeenpwned API, and check results.
	:param h: The sha1 hash to check
	:return: The number of times the password has been found (0 is good!)
	"""
	if len(h) != 40:
		raise ValueError("A sha1 hash should be 30 characters.")
	h = h.upper()

	chk = h[:5]
	r = requests.get("https://api.pwnedpasswords.com/range/%s" % chk)
	if r.status_code != 200:
		raise EnvironmentError("Unable to retrieve password hashes from server.")
	matches = {m: int(v) for (m, v) in [ln.split(':') for ln in r.content.decode('utf-8').split("\r\n")]}
	#print("Prefix search returned %d potential matches." % len(matches))
	for m in matches.keys():
		if m == h[5:]:
			return matches[m]
	return 0

def check_password(p):
	"""
	Convenience function that calculates the hash for you, then runs check_hash.
	:param p: The password to check
	:return: The check_hash result for the password
	"""
	s = sha1()
	s.update(p.encode('utf-8'))
	return check_hash(s.hexdigest())

def main(args):
	passwd = ''
	if args.passwd:
		passwd = args.passwd
	elif 'PWCHECK' in os.environ:
		passwd = os.environ['PWCHECK']
	else:
		from getpass import getpass
		passwd = getpass()
	r = check_password(passwd)
	if r > 0:
		args.quiet or print("Passwod found on %d lists." % r)
		sys.exit(1)
	else:
		args.quiet or print("Password has not been compromised.")
		sys.exit(0)

if __name__ == '__main__':
	args = parser.parse_args()
	main(args)