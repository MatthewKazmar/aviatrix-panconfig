#Deploys a baseline Palo Alto config


import os, requests, urllib3, paramiko, sys, time, getpass
from netmiko.paloalto import PaloAltoPanosSSH
from ipaddress import IPv4Network
from io import StringIO

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

controller_ip = os.environ['AVIATRIX_CONTROLLER_IP']
controller_username = os.environ['AVIATRIX_USERNAME']
controller_password = os.environ['AVIATRIX_PASSWORD']

#interpret arguments
if len(sys.argv) == 1:
  print('Usage: python panconfig.py --instance=<instance name in Controller> [--username=username] [--password=password] --addbasicconfig --nointegration')
  sys.exit()

pan_username = 'admin-api'
pan_password = ""
addbasicconfig = False
nointegration = False
instance_id = ""

for x in range(1, len(sys.argv)):
  splitarg = sys.argv[x].lower().split('=')
  if splitarg[0] == '--instance':
    if len(sys.argv) < 2:
      print('Specify an instance name after --instance=.')
      sys.exit()
    else:
      instance_id = splitarg[1]
  if splitarg[0] == '--username':
    if len(sys.argv) < 2:
      print('Specify a username after --username=.')
      sys.exit()
    else:
      pan_username = splitarg[1]
  elif splitarg[0] == '--password':
    if len(sys.argv) < 2:
      print('Specify a password after --password=.')
      sys.exit()
    else:
      pan_password = splitarg[1]
  elif splitarg[0] == '--addbasicconfig':
    addbasicconfig = True
  elif splitarg[0] == '--nointegration':
    nointegration = True

#Exit if no instance Id
if not instance_id:
  print('Usage: python panconfig.py --instance=<instance name in Controller> [--username=username] [--password=password] --addbasicconfig --nointegration')
  print('Please supply an instance id.')
  sys.exit()

#Get a password if its blank.
if not pan_password:
  fwpw = "1"
  fwpw2 = "2"
  while fwpw != fwpw2:
      fwpw = getpass.getpass("Enter a password for the firewall/client user {0}: ".format(pan_username))
      fwpw2 = getpass.getpass("Enter it again: ")
      if fwpw != fwpw2:
        print("  Please enter the same password on both lines.")
  pan_password = fwpw

#Get config
try:
  required_config_cmds = (open('gcp_required_config.txt','r')).readlines()
except:
  print('Can''t find the gcp_required_config.txt file. This is required.')
  sys.exit()
try:
  add_basic_config_cmds = (open('add_basic_config.txt','r')).readlines()
except:
  if addbasicconfig:
    print('Can''t find the add_basic_config.txt file.' )
    addbasicconfig = False
try:
  no_integration_cmds = (open('gcp_no_integration.txt','r')).readlines()
except:
  if nointegration:
    print('Can''t find the gcp_no_integration.txt file.' )
    nointegration = False

#print(add_basic_config_cmds)
#print(no_integration_cmds)

ctrl_url = 'https://{}/v1/api'.format(controller_ip)
download_url = 'https://{}/v1/download'.format(controller_ip)

#Get CID
payload = { 'action': 'login', 'username': controller_username, 'password': controller_password }
response = requests.request("POST", ctrl_url, data=payload, verify = False)
cid = response.json()['CID']

#Get PAN IP, nexthop and PEM name
payload = { 'action': 'get_instance_by_id', 'CID': cid, 'instance_id': instance_id }
response = requests.request("POST", ctrl_url, data=payload, verify = False)
pan_ip = response.json()['results']['management_public_ip']
pan_egress_nexthop = str(IPv4Network(response.json()['results']['egress_subnet'])[1])
pan_lan_nexthop = str(IPv4Network(response.json()['results']['lan_subnet'])[1])
key_file = response.json()['results']['key_file']

#Get PEM/private key
payload = { 'CID': cid, 'filename': key_file}
response = requests.request("POST", download_url, data=payload, verify=False)
private_key = paramiko.RSAKey.from_private_key(StringIO(response.text))

#Log in to firewall
#Try 10 times, wait 30 seconds each time
connect = False
count = 0
maxcount = 10
wait = 30
while connect == False and count < 10: 
  try:
    pan = PaloAltoPanosSSH(ip=pan_ip,username='admin',use_keys=True,pkey=private_key)
  except:
    count +=1
    time.sleep(wait)
    print('Could not connect to {0}. Waiting {1} seconds.'.format(instance_id,wait))
  else:
    connect = True
    print('Connected to {0}.'.format(instance_id))

if connect == False:
  print('Could not connect to {0}.'.format(instance_id))
  sys.exit()

#Get phash
phash = (pan.send_command('request password-hash username {0} password {1}'.format(pan_username,pan_password))).strip()

#Set basic config
pan.send_command('set cli scripting-mode on')
pan.config_mode()
pan.send_command('set mgt-config users {0} permissions role-based superuser yes'.format(pan_username))
pan.send_command('set mgt-config users {0} phash {1}'.format(pan_username, phash))
pan.send_command('set deviceconfig system hostname {0}'.format(instance_id))
pan.send_command('set address nic0_nexthop ip-netmask {0}'.format(pan_egress_nexthop))
pan.send_command('set address nic1_nexthop ip-netmask {0}'.format(pan_lan_nexthop))

pan.send_config_set(config_commands=required_config_cmds,enter_config_mode=False,exit_config_mode=False)
if addbasicconfig:
  pan.send_config_set(config_commands=add_basic_config_cmds,enter_config_mode=False,exit_config_mode=False)
if nointegration:
  pan.send_config_set(config_commands=no_integration_cmds,enter_config_mode=False,exit_config_mode=False)

pan.send_command('move rulebase security rules default_deny bottom')

pan.commit()
pan.exit_config_mode()
pan.disconnect()