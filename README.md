# ansible-ad-inventory


### Overview
"active_directory.py" subtree searches through DN's you provide in the .ini file.

It has two modes of sorting your AD computers:

1. By security group (groups):
	In this mode a computer object is added into a group for each Security Group that's listed in it's `memberof` attribute.
	This does not apply or check for nested groups and ignores `Domain Computers`

2. By Organization Unit (ou):
	In this mode a computer object is added into a group for each OU it is under.
	This does follow the nesting of the OU up.
	
	Example:
		server1's DN is `cn=server1,ou=webservers,ou=us_datacenter`, In this scenario (Assuming `ou=us_datacenter` is the starting OU)
		server1 will show up as a member to the "webservers" group and the "us_datacenter" group.
		
	Resulting Ansible inv JSON: {"webservers":["server1"],"us_datacenter":["server1"]}

Note: Use --debug to run in full debug mode and be sure to submit any issues!

### Deployment

1. Install dependencies `pip3 install -r requirements.txt`

2.Download and make "active_directory.py" executable.

3.Add `inventory = /path/to/active_directory.py` under the `[defaults]` header in your "ansible.cfg"

4.Fill out the ini file (Ensure "active_directory.ini" is in the same directroy as "active_directory.py")


Requirements:
	ldap3
