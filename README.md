# aviatrix-panconfig
Palo Alto firewalls need configuration after deployment with the Aviatrix Controller. This script will do it.

The script is currently GCP only.
I'll add Azure and AWS eventually.

# Requirements
1. The controller username/password/IP must be in the environment variables
AVIATRIX_CONTROLLER_IP
AVIATRIX_USERNAME
AVIATRIX_PASSWORD

2. The netmiko is installed.

# Usage

python panconfig.py -instance <instance name in Controller> --username [username] --password [password] --addbasicconfig --nointegration

--instance: name in controller, for GCP, its just the VM's name.
--username: optional, defaults to admin-api
--password: will prompt if not supplied, useful for inserting into Terraform
--addbasicconfig: adds permissive rules for testing
--nointegration: adds basic routing rules that would be added by Aviatrix vendor integration. Note that these rules overlap and would cause a commit failure if Vendor Integration is enabled later. This would have to be manually resolved.

## --addbasicconfig details

Adds address objects and groups for RFC1918 addresses
Adds allow all to Internet
Adds allow all with logging between RFC1918 addresses

## --nointegration

Adds routes for GCP health checks for eth1.
Adds routes for RFC1918 addresses back to the gateway.