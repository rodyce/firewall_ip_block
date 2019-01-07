In order to make this script work, a service account is required with Firewall admin privileges in Google Cloud.

The required permissions are the following:

compute.firewalls.create
compute.firewalls.delete
compute.firewalls.get
compute.firewalls.list
compute.firewalls.update

Create a new service account in the "IAM & admin" section. It is one of the first options in the sidebar menu.

Create a new and dedicated service account called "Project Firewall Admin".

Create a new Role called "Firewall Admin" with the previous permissions and assign this role to the service account.