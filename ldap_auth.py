#!/usr/bin/env python3
"""Authenticate Home Assistant command-line users against LDAP."""

import argparse
import configparser
import os
import ssl
import sys
from urllib.parse import urlsplit


def parse_local_only(value):
	value = value.strip()
	boolean = value.lower()
	if boolean in ("true", "yes"):
		return True, None
	if boolean in ("false", "no"):
		return False, None
	if not value:
		raise ValueError("local_only must be true, false, yes, no, or a group DN")
	return None, value


def load_config(path):
	config = configparser.ConfigParser(interpolation=None)
	if not config.read(path):
		raise ValueError("Unable to read config file: %s" % path)
	if "ldap" not in config:
		raise ValueError("Config file must contain an [ldap] section")

	settings = config["ldap"]
	required = ("server_uri", "admin_group_dn", "user_group_dn", "user_dn_template")
	missing = [name for name in required if not settings.get(name, "").strip()]
	if missing:
		raise ValueError("Missing config value(s): %s" % ", ".join(missing))

	server_uri = settings["server_uri"].strip()
	uri = urlsplit(server_uri)
	if (
		uri.scheme not in ("ldap", "ldaps")
		or not uri.hostname
		or uri.path not in ("", "/")
		or uri.username
		or uri.password
		or uri.query
		or uri.fragment
	):
		raise ValueError("server_uri must be an ldap:// or ldaps:// URI")

	starttls = settings.getboolean("starttls", fallback=False)
	if starttls and uri.scheme != "ldap":
		raise ValueError("starttls can only be used with an ldap:// server_uri")

	local_only, remote_group_dn = parse_local_only(settings.get("local_only", "false"))
	user_dn_template = settings["user_dn_template"].strip()
	if "{username}" not in user_dn_template:
		raise ValueError("user_dn_template must contain {username}")
	try:
		user_dn_template.format(username="ldap-user")
	except (IndexError, KeyError, ValueError) as error:
		raise ValueError("user_dn_template has an invalid format: %s" % error) from error

	return {
		"server_uri": server_uri,
		"starttls": starttls,
		"ca_certificate": settings.get("ca_certificate", "").strip() or None,
		"admin_group_dn": settings["admin_group_dn"].strip(),
		"user_group_dn": settings["user_group_dn"].strip(),
		"user_dn_template": user_dn_template,
		"local_only": local_only,
		"remote_group_dn": remote_group_dn,
	}


def authenticate(settings, username, password):
	from ldap3 import BASE, NONE, Connection, Server, Tls
	from ldap3.utils.conv import escape_filter_chars
	from ldap3.utils.dn import escape_rdn

	uri = urlsplit(settings["server_uri"])
	tls = Tls(
		validate=ssl.CERT_REQUIRED,
		ca_certs_file=settings["ca_certificate"],
	)
	server = Server(
		uri.hostname,
		port=uri.port,
		use_ssl=(uri.scheme == "ldaps"),
		tls=tls,
		get_info=NONE,
	)
	user_dn = settings["user_dn_template"].format(username=escape_rdn(username))
	connection = Connection(
		server,
		user=user_dn,
		password=password,
		auto_bind=False,
		raise_exceptions=True,
	)
	try:
		if settings["starttls"] and not connection.start_tls():
			return None
		if not connection.bind():
			return None

		connection.search(
			search_base=user_dn,
			search_filter="(objectClass=*)",
			search_scope=BASE,
			attributes=["cn"],
		)
		if not connection.entries:
			return None
		common_name = connection.entries[0].cn.value
		if not common_name:
			return None

		def is_member(group_dn):
			connection.search(
				search_base=group_dn,
				search_filter="(memberUid=%s)" % escape_filter_chars(username),
				search_scope=BASE,
				attributes=[],
			)
			return bool(connection.entries)

		if is_member(settings["admin_group_dn"]):
			group = "system-admin"
		elif is_member(settings["user_group_dn"]):
			group = "system-users"
		else:
			return None

		if settings["remote_group_dn"]:
			local_only = not is_member(settings["remote_group_dn"])
		else:
			local_only = settings["local_only"]
		return {"name": common_name, "group": group, "local_only": local_only}
	finally:
		connection.unbind()


def main(argv=None):
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("--config", required=True, help="Path to the LDAP INI config file")
	args = parser.parse_args(argv)

	username = os.environ.get("username", "").strip()
	password = os.environ.get("password", "")
	if not username or not password:
		return 1

	try:
		from ldap3.core.exceptions import LDAPException
	except ImportError:
		print("LDAP authentication error: install ldap3 from requirements.txt", file=sys.stderr)
		return 1

	try:
		settings = load_config(args.config)
		metadata = authenticate(settings, username, password)
	except (configparser.Error, LDAPException, OSError, ValueError) as error:
		print("LDAP authentication error: %s" % error, file=sys.stderr)
		return 1

	if metadata is None:
		return 1
	print("name = %s" % metadata["name"].replace("\r", " ").replace("\n", " "))
	print("group = %s" % metadata["group"])
	print("local_only = %s" % str(metadata["local_only"]).lower())
	return 0


if __name__ == "__main__":
	sys.exit(main())