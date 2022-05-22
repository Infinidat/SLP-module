# Introduction

The Infinidat.SMB.ShareLevelPermissions PowerShell module allows InfiniBox administrators to manage the share-level permissions for SMB shares on InfiniBox filesystems, in a few simple PowerShell commands.

All of the following commands and examples should be run in PowerShell.

# Requirements

- Install this software on a Windows client which is a member of the Active Directory domain
- Make sure you have PowerShell 7.x (PowerShell 5.0 is not supported)

# Software Install

- Copy the project files to a folder on the Windows client

For example:
```
cd "C:\Program Files\WindowsPowerShell\Modules"
rm -rf infinibox-smb
git clone https://pm:pJnBZqzu3G6qC3MU9UrS@git.infinidat.com/product/infinibox-smb.git
```

# Using the Module to manage SMB share-level permissions

Run PowerShell, and import the Infinidat module. 

```
Import-Module "C:\Program Files\WindowsPowerShell\Modules\infinibox-smb\Infinidat.SMB.ShareLevelPermissions.psd1"
```

Connect to the InfiniBox system.

**Note:** you can add the -IboxPassword parameter to provide the password on the command line.

```
Connect-Infinibox -IboxSystem "ibox2812.lab.gdc.il.infinidat.com" -IboxUser "admin"
```

## List the share-level permissions 

Execute:

```
Get-InfiniBoxSharePermissions [ -Fs <filesystem-name> ]  [ -Share <share-name> ]
```

To show the results in a table, add format-table, for example:

```
Get-InfiniBoxSharePermissions | Format-Table
```

Sample output:

```
PS C:\Users\gnadel> Get-InfiniBoxSharePermissions | Format-Table
fs              share                principal           sid                                            permission
--              -----                ---------           ---                                            ----------
fs1             fs1                  Everyone            S-1-1-0                                        FULLCONTROL
fs1             fs1                  INFINIDAT\gnadel    S-1-5-21-2133157454-631004845-1810441420-8160  READONLY
fs1             fs1                  S-1-1-1             S-1-1-1                                        NONE
fs1             fs1                  ibox3676\1234567890 S-1-5-21-2577287697-2215689574-4278831303-1011 FULLCONTROL
fs1             fs1                  ibox3676\Guest      S-1-5-21-2577287697-2215689574-4278831303-501  READONLY
Babbak-win-fs-1 Babbak-root-share-1  Everyone            S-1-1-0                                        FULLCONTROL
wow2            babbak-share-on-snap Everyone            S-1-1-0                                        FULLCONTROL
```

## Adding, removing and modifying the permissions

Execute one of the following, depending on the case:

```
New-InfiniBoxSharePermissions    -Share <share-name>  -Principal <user-or-group-name>  -Permission {FULLCONTROL|READWRITE|READONLY|NONE}
Set-InfiniBoxSharePermissions    -Share <share-name>  -Principal <user-or-group-name>  -Permission {FULLCONTROL|READWRITE|READONLY|NONE}
Remove-InfiniBoxSharePermissions -Share <share-name>  -Principal <user-or-group-name> 
```

To specify a local user or group from InfiniBox, simply prefix ther name with the InfiniBox system name, such as `myibox1\Administrator`.

To specify a user or group from an Active Directory domain, simply use their name or prefix with the domain name, such as `MyDomain\MyAccount`.

**Note:** to use a user or group from an Active Directory domain, the PowerShell client must be a member of the domain.

