#!/usr/bin/env python3

import argparse
import configparser
import ldap3
import sys
import json
import os
parser = argparse.ArgumentParser(description='Dynamic inventory script for Active Directory')
parser.add_argument('-l','--list',help='list inventory',required=True,action='store_true')
args = parser.parse_args()

def main():
	inv_list = {}
	try:
		config = configparser.ConfigParser()
		path = os.path.realpath(__file__).split('/')
		config.read_file(open('/'.join(path[0:len(path)-1])+'/active_directory.ini'))
	except IOError:
		print('Cannot find or cannot access active_directory.ini',file=sys.stderr)
		sys.exit(1)
	if config['config']['inventory'] == 'groups':
		ad_inv_by_security_group(config, inv_list)
	elif config['config']['inventory'] == 'ou':
		ad_inv_by_security_ou(config, inv_list)
	else:
		print('The only valid options for "inventory" are groups/ou',file=sys.stderr)
		sys.exit(1)

#def group_lookup(computers, inv_list):

def ad_connection(config):
	try:
		server = ldap3.Server(host=config['config']['domain_controller'],port=int(config['config']['port']))
		connection = ldap3.Connection(server=server,user=config['config']['user'],
			password=config['config']['password'], authentication=ldap3.NTLM, raise_exceptions=True, auto_referrals=False)
		connection.bind()
		return connection
	except KeyError:
		print('You are missing values from active_directory.ini', file=sys.stderr)
		sys.exit(1)
	except ldap3.core.exceptions.LDAPOperationResult:
		print('Could not bind!',file=sys.stderr)
		sys.exit(1)
	except ValueError:
		print('"use_ssl" must be True of False and "port" must be an int', file=sys.stderr)
		sys.exit(1)	

#Currently does not lookup past one level
def ad_inv_by_security_group(config, inv_list):
	connection = ad_connection(config)
	try:
		for ou in config['config']['ous'].split(':'):
			connection.search(search_filter='(objectclass=computer)',search_base=ou,
				attributes=['dnshostname','cn','memberof'])
			for computer in connection.response:
				#print(computer)
				if 'attributes' in computer:
					for groups in computer['attributes']['memberof']:
						if len(groups) > 0:
							group_name = groups.split(',')[0].split('=')[1]
							if group_name not in inv_list and len(computer['attributes']['dnshostname']) > 1:
								inv_list[group_name] = [computer['attributes']['dnshostname']]
							elif group_name not in inv_list:
								inv_list[group_name] = [computer['attributes']['cn'].lower()]
							elif group_name in inv_list and len(computer['attributes']['dnshostname']) > 1:
								inv_list[group_name].append(computer['attributes']['dnshostname'])
							else:
								inv_list[group_name].append(computer['attributes']['cn'].lower())
		print(inv_list)

		sys.exit()

	except ldap3.core.exceptions.LDAPOperationResult as error:
		print(error)
		print('Something went wrong while searching, are your OUs correct?',file=sys.stderr)
		sys.exit(1)	
	except KeyError as error:
		print(error)
		print('You are missing values from active_directory.ini', file=sys.stderr)
		sys.exit(1)

def ad_inv_by_ou(config):
	connection = ad_connection(config)

if __name__ == '__main__':
	main()