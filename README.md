# Cisco XDR / Workflows remote server registration script

Unofficial python script to get a XDR or Cisco Workflows appliance to register with the base64 string, without needing OVA string support for the cloud init process. Modifying the OVA is not officially supported by Cisco or TAC, and is intended for use in lab environments only.

Enhancements to the deployment model for the remote server will be coming officially in the near future.

## Installation
1. Download the OVA for a remote server from your XDR / Workflows tenant and download your `remotePackage.zip` for your configured remote server.
2. Run `stage_ova.py` to convert the OVA to a qcow disk image, change the password, and push the register_remote.py script to it.
3. SCP the 
4. Run `register_remote.py remotePackage.zip` on the remote appliance.
