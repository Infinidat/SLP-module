############################################################################
# Create a connection to InfiniBox management
############################################################################
function Connect-Infinibox {
	[CmdletBinding()]
	Param(
			[Parameter(Position=1,ValueFromPipeline=$False)] [string]$IboxSystem,
			[Parameter(Position=2,ValueFromPipeline=$False)] [string]$IboxUser,
			[Parameter(Position=3,ValueFromPipeline=$False)] [string]$IboxPassword
	)

	# Validate parameters, ask for password if not provided on command line
	if ( ($IboxSystem -eq "") -or ($IboxUser -eq "") ) {
			Throw "Provide InfiniBox system name and username"
	}
	if ( $IboxPassword -eq "" ) {
			$PW = Read-Host ($IboxUser + ' password: ') -AsSecureString
			$IboxPassword=[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PW))
	}
	if ($IboxPassword -eq "" ) {
			Throw "Provide password for InfiniBox"
	}

	# The web session is created in this function by logging into InfiniBos,
	# and is saved in a global variable so that it can be used in other functions
	$Global:IboxSession=$null

	# Store the parameters so they can be used later
	$Global:IboxUser=$IboxUser
	$Global:IboxSystem=$IboxSystem

	# Login to InfiniBox
	try {
			$LOGINURL=("https://"+$IboxSystem+"/api/rest/users/login")
			$LOGINBODY=('{ "username": "'+$IboxUser+'", "password": "'+$IboxPassword+'", "clientid": "PowerShell"}')
			$IBOXRES=Invoke-WebRequest -SkipCertificateCheck -Uri $LOGINURL -Method POST -Body $LOGINBODY -ContentType "application/json" -SessionVariable "Global:IboxSession"
	}
	catch {
			Throw ("Error logging into InfiniBox " + $IboxSystem + ": " + $_.Exception.Message)
	}

	# Infinibox entities representation in VMware is built from three components:
	#   Infinidat global identifier,
	#   The system serial number, and
	#   Some object management ID (PE, pool)
	# This function calculates the first two parts, and stores them for later user

	# Get the system name
	$Global:IboxName=(Ibox-InvokeApi -api "system/name").result
}

############################################################################
# Internal function: call an InfiniBox API
############################################################################
function Ibox-InvokeApi {
	[CmdletBinding()]
	Param(
			[Parameter(Position=0,ValueFromPipeline=$False)] [Microsoft.PowerShell.Commands.WebRequestMethod]$method,
			[Parameter(Position=1,ValueFromPipeline=$False)] [string]$api,
			[Parameter(Position=2,ValueFromPipeline=$False)] [string]$data,
			[Parameter(Position=3,ValueFromPipeline=$False)] [string]$desc
	)

	# Validate parameters, set defaults
	if ( $api -eq "" ) {
			Throw "no API was submitted"
	}
	if ( $method -eq $null) {
			$method=[Microsoft.PowerShell.Commands.WebRequestMethod]::GET
	}

	# Send API request, using the global web session that was created when we logged in to InfiniBox
	try {
			if ( ($method -eq [Microsoft.PowerShell.Commands.WebRequestMethod]::GET) -or
					 ($method -eq [Microsoft.PowerShell.Commands.WebRequestMethod]::DELETE) ) {
					$RES=Invoke-RestMethod -SkipCertificateCheck -Uri ("https://"+$Global:IboxSystem+"/api/rest/"+$api) -WebSession $Global:IboxSession -Method $method
			} else {
					$RES=Invoke-RestMethod -SkipCertificateCheck -Uri ("https://"+$Global:IboxSystem+"/api/rest/"+$api) -WebSession $Global:IboxSession -Method $method -ContentType "application/json" -Body $data
			}
	}
	catch {
			Throw ("Error while " + $desc + ": " + $_.Exception.Message)
	}

	return $RES
}

############################################################################
# Internal function: convert an SID to user/group name
# Used when querying the shars permissions to show the user/group
#
# There are several possibilities, the SID might belog to:
#   (1) an AD account, (2) a well-known group, 
#   (3) an InfiniBox local SMB user, or (4) an InfiniBox local SMB group
# We let the Windows standard system security deal with the first two
# We query InfiniBox for the last two cases
# Note: if a local SMB account, we prepend it with the IBOX name 
# If nothing managed to translate the SID to name, we just return the SID
############################################################################
function Ibox-TranslateSidToPrincipal {
	Param(
			[Parameter(Position=1,ValueFromPipeline=$False)] [string]$Sid
	)
	# Use the windows security translate the SID to a principal
	try { 
		$PRIN=(New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).value 
	} catch {
		# if Windows failed, we try to see if the SID is an IBOX local SMB group
		$NAME=(Ibox-InvokeApi -method GET -api ("smb_groups?fields=name&sid="+$Sid) -data "" -desc "Get group by SID").result.name 
		if ( ($NAME -ne "") -and ($NAME -ne $null) ) { 
			$PRIN=$Global:IboxName + "\" + $NAME 
		} else {
			# otherwise, we try to see if the SID is an IBOX local SMB group
			$NAME=(Ibox-InvokeApi -method GET -api ("smb_users?fields=name&sid="+$Sid) -data "" -desc "Get user by SID").result.name 
			if ( ($NAME -ne "") -and ($NAME -ne $null) ) { 
				$PRIN=$Global:IboxName + "\" + $NAME 
			} else {
				# Worst case, we just use the SID as-is
				$PRIN=$Sid 
			} 
		}
	}
	return $PRIN
}

############################################################################
# Internal function: convert an user/group name to SID
# Used when admin provides a user/group name as parameter 
############################################################################
function Ibox-TranslatePrincipalToSid {
	Param(
			[Parameter(Position=1,ValueFromPipeline=$False)] [string]$Principal
	)
	# If the principal name starts with the IBOX name, then it's a local SMB group or user
	if ( $Principal.StartsWith($Global:IboxName) ) {
		$PRINNAME=$Principal.Replace($Global:IboxName+"\","")
		$PRINSID=(Ibox-InvokeApi -method GET -api ("smb_groups?fields=sid&name="+$PRINNAME) -data "" -desc "Get group by name").result.sid 
		if ( ($PRINSID -eq $null) -or ($PRINSID -eq "") ) {
			$PRINSID=(Ibox-InvokeApi -method GET -api ("smb_users?fields=sid&name="+$PRINNAME) -data "" -desc "Get user by name").result.sid  
		}
	} else {
		# Use the windows security translate the principal name to SID
		try {
			$PRINSID=(New-Object System.Security.Principal.NTAccount($Principal)).Translate([System.Security.Principal.SecurityIdentifier]).value
		} catch {
			# If nothing works - fail the operation
			throw ("No such user or group: '" + $Principal + "'")
		}
	}
	if ( ($PRINSID -eq $null) -or ($PRINSID -eq "") ) {
		throw ("No such user or group: '" + $Principal + "'")
	}
	return $PRINSID
}

############################################################################
# Internal function: get the share mgmt ID from its name
############################################################################
function Ibox-GetShareId {
	Param(
			[Parameter(Position=1,ValueFromPipeline=$False)] [string]$ShareName
	)
	# Search for the share by name, and retrieve the MGMT id
	$SHAREID=(Ibox-InvokeApi -method GET -api ("shares?fields=id&name="+$ShareName) -data "" -desc "Get Share ID").result.id
	if ( ( $SHAREID -eq $null) -or ($SHAREID -eq "") ) {
		throw ("No such share: '" + $ShareName + "'")
	}
	return $SHAREID
}

############################################################################
# Internal function: get the FS mgmt ID from its name
############################################################################
function Ibox-GetFsId {
	Param(
			[Parameter(Position=1,ValueFromPipeline=$False)] [string]$FsName
	)
	# Search for the filesystem by name, and retrieve the MGMT id
	$FSID=(Ibox-InvokeApi -method GET -api ("filesystems?fields=id&name="+$FsName) -data "" -desc "Get FS ID").result.id
	if ( ( $FSID -eq $null) -or ($FSID -eq "") ) {
		throw ("No such filesystem: '" + $FsName + "'")
	}
	return $FSID
}

############################################################################
# Internal function: make sure the admin has a connection to IBOX
############################################################################
function Ibox-ValidateConnection {
	if ($Global:IboxSession -eq $null) {
		throw "Not connected to InfiniBox, use Connect-Infinibox"
	}
}

############################################################################
# Internal function: make sure the provided permissions are either 
#                    FULLCONTROL, READWRITE, READONLY or NONE
############################################################################
# function Ibox-ValidatePermissions {
	# Param(
	# 		[Parameter(Position=2,Mandatory=$True,ValueFromPipeline=$False)] [string]$Permission
	# )	
	# if ( ($Permission -ne "FULLCONTROL") -and ($Permission -ne "NONE") -and ($Permission -ne "READONLY") -and ($Permission -ne "READWRITE") ) {
	# 	throw ("Permissions must be one of: FULLCONTROL, READWRITE, READONLY or NONE")
	# }
# }	

############################################################################
# Enumerate the share permissions, show one line per SLP entry
############################################################################
function Get-InfiniBoxSharePermissions {
	[CmdletBinding()]
	Param(
			[Parameter(Position=0,ValueFromPipeline=$False)] [string]$Fs,
			[Parameter(Position=1,ValueFromPipeline=$False)] [string]$Share
	)
	Ibox-ValidateConnection
	# RSLT is an array of SLPs 
	$RSLT=@()
	# Begin with a query that retrieves all shares (/api/rest/shares) and 
	# add predicates based on the parameters to this function
	$SHAREQUERY="shares?"
	# If the share name is specified, find its MGMT id and trim the query accordingly
	if (($Share -ne $null) -and ($Share -ne "")) { 
		$SHAREID=Ibox-GetShareId -ShareName $Share
		$SHAREQUERY+=("&id="+$SHAREID)
	}
	# If the FS name is specified, find its MGMT id and trim the query accordingly
	if (($Fs -ne $null) -and ($Fs -ne "")) { 
		$FSID=Ibox-GetFsId -FsName $Fs
		$SHAREQUERY+=("&filesystem_id="+$FSID)
	}
	# retrieve all the (relevant) SMB shares, and loop one by one
	foreach ($CURRSHARE in (Ibox-InvokeApi -method GET -api $SHAREQUERY -data "" -desc "Get shares").result) {
		# Find the FS name, so that we can display it like in the CLI
		$CURRFS=(Ibox-InvokeApi -method GET -api ("filesystems/"+$CURRSHARE.filesystem_id+"?fields=name") -data "" -desc "Get shares").result.name
		# Each share has a list of SLPs, loop through them
		foreach ($PERM in $CURRSHARE.permissions) {
			# translate the SLP SID to principal name
			$PRIN=Ibox-TranslateSidToPrincipal -Sid $PERM.sid 
			# Add new row in the results array
			$RSLT += [PSCustomObject]@{ fs=$CURRFS; share = $CURRSHARE.name; principal = $PRIN; sid = $PERM.sid; permission = $PERM.access }
		}
	}
	return $RSLT
}

############################################################################
# Add a new SLP entry for a share
############################################################################
function New-InfiniBoxSharePermissions {
	[CmdletBinding()]
	Param(
			[Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$False)] [string]$Share,
			[Parameter(Position=1,Mandatory=$True,ValueFromPipeline=$False)] [string]$Principal,
			[Parameter(Position=2,Mandatory=$True,ValueFromPipeline=$False)]
			[ValidateSet("FULLCONTROL","READWRITE","READONLY","NONE",ErrorMessage="Value '{0}' is invalid. Try one of: '{1}'")]
			[string]$Permission
	)
	Ibox-ValidateConnection
	# Ibox-ValidatePermissions -Permission $Permission
	# Get the share MGMT id and the user/group SID
	$SHAREID=Ibox-GetShareId -ShareName $Share
	$PRINSID=Ibox-TranslatePrincipalToSid -Principal $Principal
	# Add a new SLP
	$RSLT=Ibox-InvokeApi -method POST -api ("shares/"+$SHAREID+"/permissions") -data ('{ "sid": "' + $PRINSID + '", "access": "' + $Permission + '" }') -desc "Create SLP"
}

############################################################################
# Update the permissions of an existing SLP entry for a share
############################################################################
function Remove-InfiniBoxSharePermissions {
	[CmdletBinding()]
	Param(
			[Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$False)] [string]$Share,
			[Parameter(Position=1,Mandatory=$True,ValueFromPipeline=$False)] [string]$Principal
	)
	Ibox-ValidateConnection
	# Get the share MGMT id and the user/group SID
	$SHAREID=Ibox-GetShareId -ShareName $Share
	$PRINSID=Ibox-TranslatePrincipalToSid -Principal $Principal
	# Find the MGMT id of the SLP within the share
	$SLPID=(Ibox-InvokeApi -method GET -api ("shares/"+$SHAREID+"/permissions?fields=id&sid="+$PRINSID) -desc "Get SLP ID").result.id
	# If the SLP was not found, then it means there's no SLP for the user/group yet
	if ( ($SLPID -eq "") -or ($SLPID -eq $null) ) {
		throw ("No permissions for '" + $Principal + "' to '" + $Share + "'")
	}
	# Delete the SLP
	$RSLT=Ibox-InvokeApi -method DELETE -api ("shares/"+$SHAREID+"/permissions/"+$SLPID) -desc "Delete SLP"
}

############################################################################
# Remove an existing SLP entry for a share
############################################################################
function Set-InfiniBoxSharePermissions {
	[CmdletBinding()]
	Param(
			[Parameter(Position=0,Mandatory=$True,ValueFromPipeline=$False)] [string]$Share,
			[Parameter(Position=1,Mandatory=$True,ValueFromPipeline=$False)] [string]$Principal,
			[Parameter(Position=2,Mandatory=$True,ValueFromPipeline=$False)]
			[ValidateSet("FULLCONTROL","READWRITE","READONLY","NONE",ErrorMessage="Value '{0}' is invalid. Try one of: '{1}'")]
			[string]$Permission
	)
	Ibox-ValidateConnection
	# Ibox-ValidatePermissions -Permission $Permission
	# Get the share MGMT id and the user/group SID
	$SHAREID=Ibox-GetShareId -ShareName $Share
	$PRINSID=Ibox-TranslatePrincipalToSid -Principal $Principal
	# Find the MGMT id of the SLP within the share
	$SLPID=(Ibox-InvokeApi -method GET -api ("shares/"+$SHAREID+"/permissions?fields=id&sid="+$PRINSID) -desc "Get SLP ID").result.id
	# If the SLP was not found, then it means there's no SLP for the user/group yet
	if ( ($SLPID -eq "") -or ($SLPID -eq $null) ) {
		throw ("No permissions for '" + $Principal + "' to '" + $Share + "'")
	}
	# Modify the SLP
	$RSLT=Ibox-InvokeApi -method PUT -api ("shares/"+$SHAREID+"/permissions/"+$SLPID) -data ('{ "access": "' + $Permission + '" }') -desc "Modify SLP"
}
