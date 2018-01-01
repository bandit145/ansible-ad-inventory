#!/usr/bin/env python3

import argparse
import configparser
import ldap3
import sys
import json
import os
import ssl
parser = argparse.ArgumentParser(description='Dynamic inventory script for Active Directory')
parser.add_argument('-l','--list',help='list inventory',required=True,action='store_true')
parser.add_argument('-d','--debug',help='Enable error message dumping',action='store_true')
args = parser.parse_args()

def main():
	inv_list = {}
	try:
		config = configparser.SafeConfigParser()
		path = os.path.realpath(__file__).split('/')
		config.read_file(open('/'.join(path[0:len(path)-1])+'/active_directory.ini'))
	except IOError:
		print('Cannot find or cannot access active_directory.ini',file=sys.stderr)
		sys.exit(1)
	if config['config']['inventory'] == 'groups':
		ad_inv_by_security_group(config, inv_list)
	elif config['config']['inventory'] == 'ou':
		ad_inv_by_ou(config, inv_list)
	else:
		print('The only valid options for "inventory" are groups/ou',file=sys.stderr)
		sys.exit(1)
	print(json.dumps(inv_list, indent=4))
	sys.exit(0)


def ad_connection(config):
	try:
		if config['config']['port'] == "389":
			server = ldap3.Server(host=config['config']['domain_controller'],use_ssl=False,port=int(config['config']['port']))
			
		elif config['config']['port'] == "636":
			if config['config']['validate_certs'].lower() == 'yes':
				tls = ldap3.Tls(validate=ssl.CERT_REQUIRED)
			elif config['config']['validate_certs'].lower() == 'no':
				tls = ldap3.Tls(validate=ssl.CERT_NONE)
			else:
				print('The only valid options for "validate_certs" are yes/no',file=sys.stderr)
				sys.exit(1)
			server = ldap3.Server(host=config['config']['domain_controller'],use_ssl=True,port=int(config['config']['port']),tls=tls)
		else:
			print('"port" must be one of 389/636',file=sys.stderr)
			sys.exit(0)
		connection = ldap3.Connection(server=server,user=config['config']['user'],
				password=config['config']['password'], authentication=ldap3.NTLM, raise_exceptions=True, auto_referrals=False)
		connection.bind()
		return connection
	except KeyError as error:
		print('You are missing values from active_directory.ini', file=sys.stderr)
		if args.debug:
			print(error, file=sys.stderr)
		sys.exit(1)
	except ldap3.core.exceptions.LDAPOperationResult as error:
		print('Could not bind!',file=sys.stderr)
		if args.debug:
			print(error, file=sys.stderr)
		sys.exit(1)
	except ldap3.core.exceptions.LDAPSocketOpenError as error:
		print('LDAPS bind failed! Probably A certificate verification failure, set "validate_certs=no" or add the CA.crt to your system root store', file=sys.stderr)
		if args.debug:
			print(error, file=sys.stderr)
		sys.exit(1)
	except ValueError as error:
		print('"port" must be an int', file=sys.stderr)
		if args.debug:
			print(error, file=sys.stderr)
		sys.exit(1)	

def add_to_list(group_name, computer, inv_list):
	if group_name not in inv_list and len(computer['attributes']['dnshostname']) > 1:
		inv_list[group_name] = [computer['attributes']['dnshostname']]
	elif group_name not in inv_list:
		inv_list[group_name] = [computer['attributes']['cn'].lower()]
	elif group_name in inv_list and len(computer['attributes']['dnshostname']) > 1:
		if computer['attributes']['dnshostname'] not in inv_list[group_name]:
			inv_list[group_name].append(computer['attributes']['dnshostname'])
	else:
		if computer['attributes']['cn'] not in inv_list[group_name]:
			inv_list[group_name].append(computer['attributes']['cn'].lower())

#Currently does not lookup past one level of group nesting
def ad_inv_by_security_group(config, inv_list):
	connection = ad_connection(config)
	try:
		for ou in config['config']['ous'].split(':'):
			connection.search(search_filter='(objectclass=computer)',search_base=ou,
				attributes=['dnshostname','cn','memberof'])
			for computer in connection.response:
				if 'attributes' in computer:
					if len(computer['attributes']['memberof']) > 0:
						for groups in computer['attributes']['memberof']:
							add_to_list(groups.split(',')[0].split('=')[1],computer, inv_list)
					#Hard coded to include domain controllers (The have primarygroup but that is not in the ldap spec
					# and not supported in ldap3)
					if computer['dn'].split(',')[1].split('=')[1] == 'Domain Controllers':
						add_to_list('Domain Controllers',computer,inv_list)

	except ldap3.core.exceptions.LDAPOperationResult as error:
		print('Something went wrong while searching, are your OUs correct?',file=sys.stderr)
		if args.debug:
			print(error, file=sys.stderr)
		sys.exit(1)	

def ad_inv_by_ou(config, inv_list):
	connection = ad_connection(config)
	try:
		for ou in config['config']['ous'].split(':'):
			connection.search(search_filter='(objectclass=computer)',search_base=ou,
				attributes=['dnshostname','cn'])
			for computer in connection.response:
				if 'attributes' in computer:
					groups = computer['dn'].split(',')
					#get rid of object itself
					del groups[0]
					for ou in groups:
						if 'cn' in ou.lower() or 'ou' in ou.lower():
							add_to_list(ou.split('=')[1],computer, inv_list)
			
	except ldap3.core.exceptions.LDAPOperationResult as error:
		print('Something went wrong while searching, are your OUs correct?',file=sys.stderr)
		if args.debug:
			print(error, file=sys.stderr)
		sys.exit(1)	


if __name__ == '__main__':
	main()