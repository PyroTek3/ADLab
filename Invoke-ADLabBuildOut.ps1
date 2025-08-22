<#
.SYNOPSIS
Builds out an Active Directory lab environment with OUs and accounts.

.DESCRIPTION
This script creates Organizational Units (OUs), user accounts, and admin accounts to simulate a production AD environment.

.PARAMETER DomainName
Domain Name of your AD

.EXAMPLE
PS>.\Invoke-ADLabBuildOut.ps1

This is the prefer method of running this script
.EXAMPLE
PS>.\Invoke-ADLabBuildOut.ps1 -DomainName ad.vulndomain.corp 

.EXAMPLE
PS>Set-ExecutionPolicy Bypass -Scope Process -Force 
PS>.\Invoke-ADLabBuildOut.ps1

.NOTES
AUTHOR: Sean Metcalf
AUTHOR EMAIL: sean.metcalf@trustedsec.com
COPYRIGHT: 2025 
WEBSITE: https://ADSecurity.org

This script requires the following:
 * PowerShell 5.0 (minimum)
 * Windows 10/2016
 * Active Directory PowerShell Module
 * Group Policy PowerShell Module
If the above requirements are not met, results will be inconsistent.
This script is provided as-is, without support.
#>

# Script Version 1.25.08.20.16
#

Param
 (
    $Domain,
    [switch]$CreateTopLevelOUs,
    [switch]$CreateBranchOfficeOUs,
    [switch]$RenameDomainAdministrator,
    [switch]$CreateADLabUsers,
    [switch]$CreateADLabGroups,
    [switch]$CreateADLabServiceAccounts,
    [switch]$CreateADLabAdminAccounts,
    [switch]$CreateADLabGMSAs,
    [switch]$CreateADLabWindowsWorkstations,
    [switch]$CreateADLabWindowsServers,
    [switch]$CreateADLabComputers,
    [switch]$CreateADLabFGPPs,
    [switch]$SetSPNDefaultAdminAccount,
    [switch]$InvokeRandomizeAdmins,
    [switch]$InvokeRandomizeServiceAccountAdmins,
    [switch]$AddPasswordToADAttribute,
    [switch]$AddKerberosDelegation

 )


Function Create-TopLevelOUs
 {
    Param
     (
        [Parameter(Mandatory=$true)]$Domain
     )

    [array]$TopLevelOUs = @('AD Administration','Enterprise Services','Domain Users','Workstations')

    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
    $DomainInfo = Get-ADDomain -Server $DomainDC

    ForEach ($TopLevelOUsItem in $TopLevelOUs)
     {
        Write-Host "Creating the top-level OU: $TopLevelOUsItem"
        New-ADOrganizationalUnit $TopLevelOUsItem -Server $DomainDC
        Start-sleep 5
        IF ($TopLevelOUsItem -like "*Admin*")
         {
            Write-Host "Creating OUs under the $TopLevelOUsItem top-level OU"
            New-ADOrganizationalUnit 'Accounts' -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False -Server $DomainDC
            New-ADOrganizationalUnit 'Computers' -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False -Server $DomainDC
            New-ADOrganizationalUnit 'Groups' -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False -Server $DomainDC
            New-ADOrganizationalUnit 'Service Accounts' -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False -Server $DomainDC
         }
        IF ($TopLevelOUsItem -eq "Enterprise Services")
         {
            Write-Host "Creating OUs under the $TopLevelOUsItem top-level OU"
            New-ADOrganizationalUnit 'Entra ID' -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False -Server $DomainDC
            New-ADOrganizationalUnit 'Exchange'-Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False -Server $DomainDC
            New-ADOrganizationalUnit 'Groups' -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False  -Server $DomainDC
            New-ADOrganizationalUnit 'SCCM' -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False -Server $DomainDC
            New-ADOrganizationalUnit 'Servers' -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False -Server $DomainDC
            New-ADOrganizationalUnit 'Service Accounts' -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False -Server $DomainDC
            New-ADOrganizationalUnit 'VMware' -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False -Server $DomainDC
            New-ADOrganizationalUnit 'Web Servers' -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False -Server $DomainDC
         }
     }   
 }

Function Create-BranchOfficeOUs
 {
    Param
     (
        [Parameter(Mandatory=$true)]$Domain,
        [switch]$CreateTopLevelOUContainer,
        [string]$TopLevelOUContainerName
     )

    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
    $DomainInfo = Get-ADDomain -Server $DomainDC

    $OUPath = $DomainInfo.DistinguishedName 

    IF (!$TopLevelOUContainerName)
     { $TopLevelOUContainerName = 'Branch Offices' }

    IF ($CreateTopLevelOUContainer -eq $True)
     { 
        New-ADOrganizationalUnit $TopLevelOUContainerName -Server $DomainDC
        $OUPath = "OU=$TopLevelOUContainerName,$($DomainInfo.DistinguishedName)" 
        Start-sleep 5
     }

    $TopLevelOUStructureArray = @('User Accounts','Groups','Service Accounts','Workstations','Servers')

    $AFTopLevelOUArray = @('Lagos','Cairo','Kinshasa','Nairobi','Cape Town','Johannesburg','Addis Ababa','Abuja','Dar es Salaam','Alexandria','Casablanca','Durban','Accra','Luanda','Giza')
    $ANTTopLevelOUArray = @("Amundsen-Scott","Lenie","McMurdo","Palmer Station","Shirreff")
    $APTopLevelOUArray = @('Singapore','Tokyo','Seoul','Hong Kong','Beijing','Bangkok','Sydney','Shanghai','Melbourne','Kuala Lumpur','Osaka','Delhi','Mumbai','Bangalore','Auckland','Taipei','Guangzhou','Shenzhen','Brisbane','Perth')
    $EUTopLevelOUArray = @('Vienna','Barcelona','Paris','Budapest','Lisbon','Amsterdam','London','Rome','Stockholm','Athens','Berlin','Prague','Copenhagen','Florence','Madrid','Edinburgh','Istanbul','Milan','Munich','Seville','Venice','Brussels','Saint Petersburg','Dubrovnik')
    $NATopLevelOUArray = @("Mexico City","New York","Los Angeles","Toronto","Chicago","Houston","Montreal","Havana","Tijuana","Phoenix","Ecatepec de Morelos","León","Philadelphia","Puebla","Juárez","Zapopan","San Antonio","Calgary","Guadalajara","San Diego","Dallas","Guatemala City","Port-au-Prince","Monterrey","Tegucigalpa","Edmonton","Panama City","Nezahualcóyotl","Ottawa","Managua","Santo Domingo","Austin","Jacksonville","San Jose","Fort Worth","Washington DC")
    $SATopLevelOUArray = @('São Paulo','Buenos Aires','Rio de Janeiro','Bogotá','Lima','Santiago','Belo Horizonte','Salvador','Brasília','Caracas',"Medellín","Guayaquil","Fortaleza","Manaus","Cali","Curitiba","Quito","Maracaibo","Santa Cruz de la Sierra","Recife",'Córdoba')

    Switch($DomainInfo.Name)
     {
        'af'  { $TopLevelOUArray = $AFTopLevelOUArray }
        'ant' { $TopLevelOUArray = $ANTTopLevelOUArray }
        'ap'  { $TopLevelOUArray = $APTopLevelOUArray }
        'eu'  { $TopLevelOUArray = $EUTopLevelOUArray }
        'na'  { $TopLevelOUArray = $NATopLevelOUArray }
        'sa'  { $TopLevelOUArray = $SATopLevelOUArray }
     }

    Write-Host "Creating $($TopLevelOUArray.Count) Top-Level OUs"

    $TopLevelOUArray = $TopLevelOUArray | Sort-Object
    ForEach ($TopLevelOUArrayItem in $TopLevelOUArray)
     { 
        Write-Host "Creating the OU $TopLevelOUArrayItem in $domain"
        New-ADOrganizationalUnit $TopLevelOUArrayItem -Path $OUPath -ProtectedFromAccidentalDeletion $False -Server $DomainDC
        Start-Sleep 3
        ForEach ($TopLevelOUStructureArrayItem in $TopLevelOUStructureArray)
         { New-ADOrganizationalUnit $TopLevelOUStructureArrayItem -Path "OU=$TopLevelOUArrayItem,$OUPath" -ProtectedFromAccidentalDeletion $False -Server $DomainDC }
     }
     Write-Host "Top-level OU creation complete"    
 }

Function Rename-DomainAdministrator
 {`
    Param
     (
        [Parameter(Mandatory=$true)]$Domain,
        [Parameter(Mandatory=$true)][string]$NewName
     )

    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
    Write-Host "Renaming Administrator to $NewName"
    TRY
     {
        Rename-ADObject -Identity (Get-ADUser "Administrator" -Server $DomainDC) -NewName $NewName -Server $DomainDC
         Set-ADUser -Identity (Get-ADUser 'Administrator' -Server $DomainDC) -SamAccountName $NewName -Server $DomainDC
        Write-Host "Administrator account renamed to $NewName complete"   
     }
    CATCH
     { Write-Warning "An error occured while attempting to rename the account 'Administrator' to $NewName" }
 }

Function Create-ADLabUsers
 {
    Param
     (
        [Parameter(Mandatory=$true)]$Domain,
        [Parameter(Mandatory=$true)]$NumberOfADUserAccounts,
        [Parameter(Mandatory=$true)]$FirstNameFile,
        [Parameter(Mandatory=$true)]$LastNameFile,
        [Parameter(Mandatory=$true)]$UserOU,
        [ValidateSet('FirstL','LastF','FirstNameLastName','LastNameFirstName','Random')][String]$NameFormatLayout, 
        [string]$Password,
        [switch]$EnableAccounts
        
     )

     $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name

     $FirstNameArray = Import-CSV $FirstNameFile
     $LastNameArray = Import-CSV $LastNameFile

     $DomainInfo = Get-ADDomain -Server $DomainDC

     IF (!$UserOU)
      { $UserOUPath = "OU=Domain Users,$($DomainInfo.DistinguishedName)" } 
     ELSE
      { $UserOUPath = "$UserOU,$($DomainInfo.DistinguishedName)" }

    $PasswordArray = @('Password99!','Password1234','P@55w0rd','1234Password','Password123!')
    IF ($Password)
      { [switch]$PasswordString = $True }
     ELSE
      { [switch]$PasswordString = $False }

     [int]$UserAccountLoopCount = 0

    Do
     {  
        $UserAccountLoopCount++
        
        $FirstRandom = Get-Random -Minimum 0 -Maximum 999
        $LastRandom = Get-Random -Minimum 0 -Maximum 99

        $UserFirstName = ($FirstNameArray[$FirstRandom]).Name
        $UserLastName = ($LastNameArray[$LastRandom]).Name
        
        $UserFirstInitialName = $UserFirstName[0]
        $UserLastInitialName = $UserLastName[0]

        $RandomNum1 = Get-Random -minimum 1 -maximum 9
        $RandomNum2 = Get-Random -minimum 1 -maximum 9
        $RandomNum3 = Get-Random -minimum 1 -maximum 9
        $RandomNum4 = Get-Random -minimum 1 -maximum 9
        $RandomNum5 = Get-Random -minimum 1 -maximum 9
        $RandomNum6 = Get-Random -minimum 1 -maximum 9

        SWITCH ($NameFormatLayout)
         {
            'FirstL' { $TestUserAccount = $UserFirstName + $UserLastInitialName }
            'LastF' { $TestUserAccount = $UserLastName + $UserFirstInitialName }
            'FirstNameLastName' { $TestUserAccount = $UserFirstName + '.' + $UserLastName }
            'LastNameFirstName' { $TestUserAccount = $UserLastName + '.' + $UserFirstName }
            'Random' { $TestUserAccount = "u" + $RandomNum1 + $RandomNum2 + $RandomNum3 + $RandomNum4 + $RandomNum5 + $RandomNum6 }
            Default { $TestUserAccount = $TestUserAccount = $UserFirstName + '.' + $UserLastName }
         }
              
        $TestUserAccountUPN = $TestUserAccount + "@" + $DomainInfo.DNSRoot

        Write-Host "Creating lab user $TestUserAccount (#$UserAccountLoopCount out of $NumberOfADUserAccounts)"
        
		$RandomNumber = Get-Random -minimum 1 -maximum 50
		IF ($RandomNumber -le 50) {$HomeDir = "\\ABC-RS01\Home\$TestUserAccount"}
		IF ($RandomNumber -le 45) {$HomeDir = "\\DEF-RS01\Home\$TestUserAccount"}
		IF ($RandomNumber -le 40) {$HomeDir = "\\GHI-RS01\Home\$TestUserAccount"}
		IF ($RandomNumber -le 35) {$HomeDir = "\\JKL-RS01\Home\$TestUserAccount"}
		IF ($RandomNumber -le 30) {$HomeDir = "\\MNO-RS01\Home\$TestUserAccount"}
		IF ($RandomNumber -le 25) {$HomeDir = "\\domain.com\Home\$TestUserAccount"}
		IF ($RandomNumber -le 20) {$HomeDir = "\\domain.com\Home\$TestUserAccount"}
		IF ($RandomNumber -le 10) {$HomeDir = "\\NEBLDGFILER01.domain.com\Home\$TestUserAccount"}
		IF ($RandomNumber -le 5) {$HomeDir = "\\BLDG01FILER.domain.com\Home\$TestUserAccount"}
			  
        $RandomNumber = Get-Random -minimum 1 -maximum 50
		IF ($RandomNumber -le 50) {$ProfilePath = "\\ABC-RS01\Profile\$TestUserAccount"}
		IF ($RandomNumber -le 45) {$ProfilePath = "\\DEF-RS01\Profile\$TestUserAccount"}
		IF ($RandomNumber -le 40) {$ProfilePath = "\\GHI-RS01\Profile\$TestUserAccount"}
		IF ($RandomNumber -le 35) {$ProfilePath = "\\JKL-RS01\Profile\$TestUserAccount"}
		IF ($RandomNumber -le 30) {$ProfilePath = "\\MNO-RS01\Profile\$TestUserAccount"}
		IF ($RandomNumber -le 25) {$ProfilePath = "\\domain.com\Profile\$TestUserAccount"}
		IF ($RandomNumber -le 20) {$ProfilePath = "\\domain.com\Profile\$TestUserAccount"}
		IF ($RandomNumber -le 10) {$ProfilePath = "\\NEBLDGFILER01.domain.com\Profile\$TestUserAccount"}
		IF ($RandomNumber -le 5) {$ProfilePath = "\\BLDG01FILER.domain.com\Profile\$TestUserAccount"}
              
		$RandomNumber = Get-Random -minimum 1 -maximum 50
		IF ($RandomNumber -le 50) {$Company = "Umbrella Corporation"}
		IF ($RandomNumber -le 45) {$Company = "InGen"}
		IF ($RandomNumber -le 40) {$Company = "Oceanic Air"}
		IF ($RandomNumber -le 35) {$Company = "Burns Industries"}
		IF ($RandomNumber -le 30) {$Company = "Buy n Large"}
		IF ($RandomNumber -le 25) {$Company = "Cyberdyne Systems"}
		IF ($RandomNumber -le 20) {$Company = "SPECTRE"}
		IF ($RandomNumber -le 15) {$Company = "Stark Industries"}
        IF ($RandomNumber -le 10) {$Company = "Wayne Enterprises"}

		$RandomNumber = Get-Random -minimum 1 -maximum 50
		IF ($RandomNumber -le 50) {$Organization = "CSA"}
		IF ($RandomNumber -le 45) {$Organization = "CSB"}
		IF ($RandomNumber -le 40) {$Organization = "CSC"}
		IF ($RandomNumber -le 35) {$Organization = "ITSA"}
		IF ($RandomNumber -le 30) {$Organization = "ITSB"}
		IF ($RandomNumber -le 25) {$Organization = "ITSC"}
		IF ($RandomNumber -le 20) {$Organization = "GSA"}
		IF ($RandomNumber -le 15) {$Organization = "ESA"}
			  
        $RandomNumber = Get-Random -minimum 1 -maximum 50
		IF ($RandomNumber -le 50) {$Title = "Consultant"}
		IF ($RandomNumber -le 45) {$Title = "Engineer"}
		IF ($RandomNumber -le 40) {$Title = "Project Manager"}
		IF ($RandomNumber -le 35) {$Title = "Program Manager"}
		IF ($RandomNumber -le 30) {$Title = "Event Coordinator"}
		IF ($RandomNumber -le 25) {$Title = "Administrator"}
		IF ($RandomNumber -le 20) {$Title = "Intern"}
		IF ($RandomNumber -le 15) {$Title = "Graphic Designer"}
			  
        $RandomNumber = Get-Random -minimum 1 -maximum 50
		IF ($RandomNumber -le 50) {$Department = "Consulting Services A"}
		IF ($RandomNumber -le 45) {$Department = "Consulting Services B"}
		IF ($RandomNumber -le 40) {$Department = "Consulting Services C"}
		IF ($RandomNumber -le 35) {$Department = "IT Services A"}
		IF ($RandomNumber -le 30) {$Department = "IT Services B"}
		IF ($RandomNumber -le 25) {$Department = "IT Services C"}
		IF ($RandomNumber -le 20) {$Department = "Graphic Services A"}
		IF ($RandomNumber -le 15) {$Department = "Event Services A"}
			  
		$RandomNumber = Get-Random -minimum 1 -maximum 50
		IF ($RandomNumber -le 50) {$Division = "ConsServA"}
		IF ($RandomNumber -le 45) {$Division = "ConsServB"}
		IF ($RandomNumber -le 40) {$Division = "ConsServC"}
		IF ($RandomNumber -le 35) {$Division = "ITServA"}
		IF ($RandomNumber -le 30) {$Division = "ITServB"}
		IF ($RandomNumber -le 25) {$Division = "ITServC"}
		IF ($RandomNumber -le 20) {$Division = "GraphicServA"}
		IF ($RandomNumber -le 15) {$Division = "EventServA"}
			  
        $RandomNumber = Get-Random -minimum 1 -maximum 50
		IF ($RandomNumber -le 50) {$HomeDrive = "H"}
		IF ($RandomNumber -le 45) {$HomeDrive = "I"}
		IF ($RandomNumber -le 40) {$HomeDrive = "J"}
		IF ($RandomNumber -le 35) {$HomeDrive = "H"}
		IF ($RandomNumber -le 30) {$HomeDrive = "K"}
		IF ($RandomNumber -le 25) {$HomeDrive = "H"}
		IF ($RandomNumber -le 20) {$HomeDrive = "L"}
		IF ($RandomNumber -le 15) {$HomeDrive = "H"}
              
		$RandomNumber = Get-Random -minimum 1 -maximum 50
		IF ($RandomNumber -le 50) {$Office = "DC-B2-ABC"}
		IF ($RandomNumber -le 45) {$Office = "DC-C1-ABC"}
		IF ($RandomNumber -le 40) {$Office = "DC-A3-ABC"}
		IF ($RandomNumber -le 35) {$Office = "NYC-D4-ABC"}
		IF ($RandomNumber -le 30) {$Office = "SF-F5-ABC"}
		IF ($RandomNumber -le 25) {$Office = "LA-A2-ABC"}
		IF ($RandomNumber -le 20) {$Office = "CHI-B2-ABC"}
		IF ($RandomNumber -le 15) {$Office = "MIA-A1-ABC"}
		
        IF ($PasswordString -eq $False )
         { $Password = $PasswordArray | Get-Random -Count 1 } 

        $ReversibleEncryptionSetting = get-random -min 1 -max 6
        If ($ReversibleEncryptionSetting -eq 1)
         { $ReversibleEncrpytionSet = $True }
        ELSE
         { $ReversibleEncrpytionSet = $False }

        $PasswordNotRequiredSetting = get-random -min 1 -max 6
        If ($PasswordNotRequiredSetting -eq 2)
         { $PasswordNotRequiredSet = $True }
        ELSE
         { $PasswordNotRequiredSet = $False }

        $PasswordNeverExpiresSetting = get-random -min 1 -max 6
        If ($PasswordNeverExpiresSetting -eq 5)
         { $PasswordNeverExpiresSet = $True }
        ELSE
         { $PasswordNeverExpiresSet = $False }

        $KerberosEncyptionDESSetting = get-random -min 1 -max 6
        If ($KerberosEncyptionDESSetting -eq 3)
         { $KerberosEncyptionSet = $True }
        ELSE
         { $KerberosEncyptionSet = $False }

        $DoesNotRequirePreAuthSetting = get-random -min 1 -max 6
        If ($DoesNotRequirePreAuthSetting -eq 4)
         { $DoesNotRequirePreAuthSet = $True }
        ELSE
         { $DoesNotRequirePreAuthSet = $False }

        $CannotChangePasswordSetting = get-random -min 1 -max 6
        If ($CannotChangePasswordSetting -eq 1)
         { $CannotChangePasswordSet = $True }
        ELSE
         { $CannotChangePasswordSet = $False }

        $SmartcardLogonRequiredSetting = get-random -min 1 -max 6
        If ($SmartcardLogonRequiredSetting -eq 2)
         { $SmartcardLogonRequiredSet = $True }
        ELSE
         { $SmartcardLogonRequiredSet = $False }

        $CannotChangePasswordSetting = get-random -min 1 -max 6
        If ($CannotChangePasswordSetting -eq 3)
         { $CannotChangePasswordSet = $True }
        ELSE
         { $CannotChangePasswordSet = $False }

        $SmartcardLogonRequiredSetting = get-random -min 1 -max 6
        If ($SmartcardLogonRequiredSetting -eq 4)
         { $SmartcardLogonRequiredSet = $True }
        ELSE
         { $SmartcardLogonRequiredSet = $False }
        
        IF ($EnableAccounts -eq $True)
         {	     	   
			New-ADUser –name "$TestUserAccount" -SamAccountName "$TestUserAccount" -Path "$UserOUPath" -DisplayName "$TestUserAccount" `
			    -Description "Test User" -AccountPassword (ConvertTo-SecureString -AsPlainText $Password -Force)  `
			    -HomeDirectory "$HomeDir" -ProfilePath "$ProfilePath" -Company $Company -Organization $Organization -EmailAddress $TestUserUPN `
				-Department $Department -Division $Division -Office $Office -GivenName $UserFirstName -Surname $UserLastName -CannotChangePassword $CannotChangePasswordSet `
                -UserPrincipalName $TestUserUPN -Title $Title -HomeDrive $HomeDrive -AllowReversiblePasswordEncryption $ReversibleEncrpytionSet -PasswordNotRequired  $PasswordNotRequiredSet `
                -PasswordNeverExpires $PasswordNeverExpiresSet -SmartcardLogonRequired $SmartcardLogonRequiredSet `
                 -Enabled $True -Server $DomainDC
            Set-ADAccountControl -Identity $TestUserAccount -DoesNotRequirePreAuth $DoesNotRequirePreAuthSet -Server $DomainDC
            IF ($KerberosEncyptionSet -eq $True)
             { Set-ADAccountControl -Identity $TestUserAccount -UseDESKeyOnly $True -Server $DomainDC  }
         }
        ELSE
         {	       
			New-ADUser –name "$TestUserAccount" -SamAccountName "$TestUserAccount" -Path "$UserOUPath" -DisplayName "$TestUserAccount" `
			    -Description "Test User" -AccountPassword (ConvertTo-SecureString -AsPlainText $Password -Force)  `
			    -HomeDirectory "$HomeDir" -ProfilePath "$ProfilePath" -Company $Company -Organization $Organization -EmailAddress $TestUserUPN `
				-Department $Department -Division $Division -Office $Office -GivenName $UserFirstName -Surname $UserLastName -CannotChangePassword $CannotChangePasswordSet `
                -UserPrincipalName $TestUserUPN -Title $Title -HomeDrive $HomeDrive -AllowReversiblePasswordEncryption $ReversibleEncrpytionSet -PasswordNotRequired  $PasswordNotRequiredSet `
                -PasswordNeverExpires $PasswordNeverExpiresSet -SmartcardLogonRequired $SmartcardLogonRequiredSet `
                 -Enabled $False -Server $DomainDC
            Set-ADAccountControl -Identity $TestUserAccount -DoesNotRequirePreAuth $DoesNotRequirePreAuthSet -Server $DomainDC
          }
     }
    While 
     ( $UserAccountLoopCount -lt $NumberOfADUserAccounts )

    Write-Host "Lab account creation complete"
 }

Function Create-ADLabGroups
 {
    Param
     (
        [Parameter(Mandatory=$true)]$Domain,
        [Parameter(Mandatory=$true)][string]$GroupOU,
        $Groups
     )
    
    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
    $DomainInfo = Get-ADDomain -Server $DomainDC

    $GroupOUPath = $GroupOU + ',' + $DomainInfo.DistinguishedName

    IF ($Groups)
     { $ADGroupArray = $Groups} 
    ELSE
     { $ADGroupArray = @('Workstation Admins','Server Admins') }

    ForEach ($ADGroupArrayItem in $ADGroupArray)
     { New-ADGroup -Name $ADGroupArrayItem -GroupCategory "Security" -GroupScope "Global" -Path $GroupOUPath -Server $DomainDC }

    Write-Host "Lab group creation complete"
  }

Function Create-ADLabServiceAccounts
 {
    Param
    (
        [Parameter(Mandatory=$true)]$Domain,
        [Parameter(Mandatory=$true)]$OUPath,
        [Parameter(Mandatory=$true)]$NumberOfAccounts,
        $ServiceAccountPrefix,
        $Password
    )
    
    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name

    $DomainInfo = Get-ADDomain -Server $DomainDC
    IF (!$OUPath)
     { $OUPath = 'OU=Service Accounts,OU=Enterprise Services'}
    $UserOUPath = "$OUPath,$($DomainInfo.DistinguishedName)"

     $LabServiceAccountArray = @('Acronis','AGPM','Azure','BESServer','BigFix','Brightmail','CAXOER','CheckPoint','CiscoUnity','Citrix','CitrixPVS','Cloudera','Cognos','CommVault','CyberArkReconcile','Dynamics','Exchange','ExchArchive','FIM','Flume',`
    'Hadoop','Imanami','Impala','InfoSphere','Insight','JBoss','Kafka','LDAP','Mongo','MagFS','NetIQ','OpenAccess','Oracle','PaloAlto','Patch','Qualys','Quest','SAPBO','SCCM','ServiceNow','SCOM','SharePoint','MSSQL','Varonis','VMWare','VPN','Web')

    [int]$MSOLAccountCount = Get-Random -min 1 -max 5
    DO
     {
        $MSOLLoopCount++
        $ADGUID = $((new-guid).Guid).SubString(0,13)
        $EntraConnectServiceAccount = 'MSOL_' + $($ADGUID -replace('-',''))
        [array]$LabServiceAccountArray += $EntraConnectServiceAccount
     }
     WHILE ($MSOLLoopCount -lt $MSOLAccountCount)

    $PasswordArray = @('Qwerty!','Zxcvbnm!','Qwertyuiop!','1234asdf!','qwer1234!','ThisIsASecurePassword!')
    IF ($Password)
      { [switch]$PasswordString = $True }
     ELSE
      { [switch]$PasswordString = $False }

    [int]$SerivceAccountLoopCount = 0

    Write-Output "Creating $NumberOfAccounts service accounts..."
    DO
     { 
        $SerivceAccountLoopCount++
        $LabServiceAccountArrayItem = $ServiceAccountPrefix + $($LabServiceAccountArray | Get-Random -count 1)
        $LabServiceAccountArrayUPN = $LabServiceAccountArrayItem + '@' + $DomainInfo.DNSRoot
        IF ($PasswordString -eq $False)
         { $Password = $PasswordArray | Get-Random -Count 1 } 

        Write-Host "Creating service account for $LabServiceAccountArrayItem"
        New-ADUser -Name $LabServiceAccountArrayItem -AccountPassword (ConvertTo-SecureString -AsPlainText $Password -Force) -UserPrincipalName $LabServiceAccountArrayUPN -Path $UserOUPath -Enabled $True -Server $DomainDC 

        $LabServiceAccountArrayItemName = $DomainInfo.NetBIOSName + '\' + $LabServiceAccountArrayItem 
        Start-sleep 5

        $ServerNumber = Get-Random -min 101 -max 999

        $AcronisSPN = "cmd.exe /C setspn -U -S AcronisAgent/TRDACRSRV$ServerNumber $LabServiceAccountArrayItemName"
        $AGPMSPN = "cmd.exe /C setspn -U -S AgpmServer/TRDAGPMSRV$ServerNumber $LabServiceAccountArrayItemName"
        $BIGFIXSPN = "cmd.exe /C setspn -U -S iem/TRBFSRV$ServerNumber $LabServiceAccountArrayItemName"
        $CAXOSPN = "cmd.exe /C setspn -U -S CAXOsoftEngine/TRDXOSRV$ServerNumber $LabServiceAccountArrayItemName"
        $CiscoSPN = "cmd.exe /C setspn -U -S CUSESSIONKEYSVR/TRDCiscoSRV$ServerNumber $LabServiceAccountArrayItemName"
        $CITRIXSPN = "cmd.exe /C setspn -U -S Norskale/TRDCTXSRV$ServerNumber $LabServiceAccountArrayItemName"
        $CitrixPVSSPN = "cmd.exe /C setspn -U -S PVSSoap/TRDPVSSRV$ServerNumber $LabServiceAccountArrayItemName"
        $CHECKPOINTSPN = "cmd.exe /C setspn -U -S ckp_pdp/TRDCHKSRV$ServerNumber $LabServiceAccountArrayItemName"
        $CLOUDERASPN = "cmd.exe /C setspn -U -S sentry/TRDCLDSRV$ServerNumber $LabServiceAccountArrayItemName"
        $COGNOSSPN = "cmd.exe /C setspn -U -S Cognos/TRDCOGSRV$ServerNumber $LabServiceAccountArrayItemName"
        $DYNAMICSSPN = "cmd.exe /C setspn -U -S Cognos/TRDDYNSRV$ServerNumber $LabServiceAccountArrayItemName"
        $EXCHSPN = "cmd.exe /C setspn -U -S exchangeMDB/TRDEXCHSRV$ServerNumber $LabServiceAccountArrayItemName"
        $FIMSPN = "cmd.exe /C setspn -U -S FIMService/TRDFIMSRV$ServerNumber $LabServiceAccountArrayItemName"
        $FLUMESPN = "cmd.exe /C setspn -U -S flume/TRDFLMSRV$ServerNumber $LabServiceAccountArrayItemName"
        $HADOOPSPN = "cmd.exe /C setspn -U -S hdfs/TRDHADOSRV$ServerNumber $LabServiceAccountArrayItemName"
        $IMPALASPN = "cmd.exe /C setspn -U -S impala/TRDIMPOSRV$ServerNumber $LabServiceAccountArrayItemName"
        $InfoSphereSPN = "cmd.exe /C setspn -U -S secshd/TRDIMPOSRV$ServerNumber $LabServiceAccountArrayItemName"
        $JBOSSSPN = "cmd.exe /C setspn -U -S jboss/TRDJBSSRV$ServerNumber $LabServiceAccountArrayItemName"
        $KAFKASPN = "cmd.exe /C setspn -U -S kafka/TRDKFKSRV$ServerNumber $LabServiceAccountArrayItemName"
        $MagFSSPN = "cmd.exe /C setspn -U -S MagFS/TRDMAGDB$ServerNumber $LabServiceAccountArrayItemName"
        $MongoSPN = "cmd.exe /C setspn -U -S mongod/TRDMNGDB$ServerNumber $LabServiceAccountArrayItemName"
        $MSSQLSPN = "cmd.exe /C setspn -U -S MSSQL/TRDSQLDB$ServerNumber $LabServiceAccountArrayItemName"
        $OpenAccessSPN = "cmd.exe /C setspn -U -S OA60/TRDOASRV$ServerNumber $LabServiceAccountArrayItemName"
        $OracleSPN = "cmd.exe /C setspn -U -S oracle/TRDORASRV$ServerNumber $LabServiceAccountArrayItemName"
        $QuestSPN = "cmd.exe /C setspn -U -S NPPolicyEvaluator/TRDQSTSRV$ServerNumber $LabServiceAccountArrayItemName"
        $SAPSPN = "cmd.exe /C setspn -U -S BOCMS/TRDSAPSRV$ServerNumber $LabServiceAccountArrayItemName"
        $SCOMSPN = "cmd.exe /C setspn -U -S MSOMHSvc/TRDSCOMSRV$ServerNumber $LabServiceAccountArrayItemName"
        $VMwareSPN = "cmd.exe /C setspn -U -S STS/TRDVMW$ServerNumber $LabServiceAccountArrayItemName"
        $WWWSPN = "cmd.exe /C setspn -U -S HTTP/TRDWEB$ServerNumber $LabServiceAccountArrayItemName"

        IF ($LabServiceAccountArrayItem -eq 'Acronis')
         { invoke-expression $AcronisSPN  }
        IF ($LabServiceAccountArrayItem -eq 'AGPM')
         { invoke-expression $AGPMSPN  }
        IF ($LabServiceAccountArrayItem -eq 'BigFix')
         { invoke-expression $AGPMSPN  }
        IF ($LabServiceAccountArrayItem -eq 'CAXOER')
         { invoke-expression $CAXOSPN  }
        IF ($LabServiceAccountArrayItem -eq 'CheckPoint')
         { invoke-expression $CHECKPOINTSPN  }
        IF ($LabServiceAccountArrayItem -eq 'Citrix')
         { invoke-expression $CITRIXSPN  }
        IF ($LabServiceAccountArrayItem -eq 'CitrixPVS')
         { invoke-expression $CitrixPVSSPN  }
        IF ($LabServiceAccountArrayItem -eq 'Cloudera')
         { invoke-expression $CLOUDERASPN  }
        IF ($LabServiceAccountArrayItem -eq 'Cognos')
         { invoke-expression $COGNOSSPN  }
        IF ($LabServiceAccountArrayItem -eq 'Dynamics')
         { invoke-expression $DYNAMICSSPN  }
        IF ($LabServiceAccountArrayItem -eq 'Exchange')
         { invoke-expression $EXCHSPN  }
        IF ($LabServiceAccountArrayItem -eq 'FIM')
         { invoke-expression $FIMSPN  }
        IF ($LabServiceAccountArrayItem -eq 'Flume')
         { invoke-expression $FLUMESPN  }
        IF ($LabServiceAccountArrayItem -eq 'Hadoop')
         { invoke-expression $HADOOPSPN  }
        IF ($LabServiceAccountArrayItem -eq 'Impala')
         { invoke-expression $IMPALASPN  }
        IF ($LabServiceAccountArrayItem -eq 'InfoSphere')
         { invoke-expression $InfoSphereSPN  }
        IF ($LabServiceAccountArrayItem -eq 'JBoss')
         { invoke-expression $JBOSSSPN  }
        IF ($LabServiceAccountArrayItem -eq 'Kafka')
         { invoke-expression $KAFKASPN  }
        IF ($LabServiceAccountArrayItem -eq 'MagFS')
         { invoke-expression $MagFSSPN  }
        IF ($LabServiceAccountArrayItem -eq 'Mongo')
         { invoke-expression $MongoSPN  }
        IF ($LabServiceAccountArrayItem -eq 'SQL')
         { invoke-expression $MSSQLSPN }
        IF ($LabServiceAccountArrayItem -eq 'OpenAccess')
         { invoke-expression $OpenAccessSPN }
        IF ($LabServiceAccountArrayItem -eq 'Oracle')
         { invoke-expression $OracleSPN }
        IF ($LabServiceAccountArrayItem -eq 'Quest')
         { invoke-expression $QuestSPN }
        IF ($LabServiceAccountArrayItem -eq 'SAPBO')
         { invoke-expression $SAPSPN }
         IF ($LabServiceAccountArrayItem -eq 'SCOM')
         { invoke-expression $SCOMSPN }
        IF ($LabServiceAccountArrayItem -eq 'VMWare')
         { invoke-expression $VMwareSPN }
        IF ($LabServiceAccountArrayItem -eq 'Web')
         { invoke-expression $WWWSPN }
     }
     WHILE
       ( $SerivceAccountLoopCount -lt $NumberOfAccounts ) 
     Write-Host "Lab service account creation complete"
 }

Function Create-ADLabAdminAccounts
 {
    Param
     (
        [Parameter(Mandatory=$true)]$Domain,        
        [Parameter(Mandatory=$true)][int]$NumberOfAdminAccounts, # Note that actual # of accounts created may be less than this number due to admin name collisions
        [Parameter(Mandatory=$true)][string]$FirstNameFile,
        [Parameter(Mandatory=$true)][string]$LastNameFile,
        [Parameter(Mandatory=$true)][string]$AccountOU,
        [ValidateSet('FirstL','LastF','FirstNameLastName','LastNameFirstName','Random')][String]$NameFormatLayout, 
        $Password,
        [string]$AdminNamePrefix,
        [string]$AdminNameSuffix
    )
    
    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
    $DomainInfo = Get-ADDomain -Server $DomainDC
    $AdminAccountOU = "$AccountOU,$($DomainInfo.DistinguishedName)"

    $FirstNameArray = Import-CSV $FirstNameFile
    $LastNameArray = Import-CSV $LastNameFile

    $PasswordArray = @('1q2w3e4r5t6y!','q1w2e3r4t5y6!','1234asdf!','qwer1234!')
    IF ($Password)
      { [switch]$PasswordString = $True }
     ELSE
      { [switch]$PasswordString = $False }

    [int]$AdminAccountLoopCount = 0

    Do
     {  
        $AdminAccountLoopCount++
        Write-Host "Creating Admin account $AdminAccountLoopCount of $NumberOfAdminAccounts"

        $FirstRandomNumber = Get-Random -Minimum 0 -Maximum 999
        $LastRandomNumber = Get-Random -Minimum 0 -Maximum 99
        $FirstName = ($FirstNameArray[$FirstRandomNumber]).Name
        $LastName = ($LastNameArray[$LastRandomNumber]).Name

        $FirstNameInitial = $FirstName.Substring(0, 1)
        $LastNameInitial = $LastName.Substring(0, 1)

        $RandomNum1 = Get-Random -minimum 1 -maximum 10
        $RandomNum2 = Get-Random -minimum 1 -maximum 10
        $RandomNum3 = Get-Random -minimum 1 -maximum 10
        $RandomNum4 = Get-Random -minimum 1 -maximum 10
        $RandomNum5 = Get-Random -minimum 1 -maximum 10
        $RandomNum6 = Get-Random -minimum 1 -maximum 10

        $AdminAccountName = $AdminNamePrefix + $FirstName + $LastNameInitial 
                  			  
        IF ($AdminNamePrefix)
         { 
            SWITCH ($NameFormatLayout)
             {
                'FirstL' { $AdminAccountName = $AdminNamePrefix + $FirstName + $LastNameInitial }
                'LastF' { $AdminAccountName = $AdminNamePrefix + $FirstNameInitial + $LastName }
                'FirstNameLastName' { $AdminAccountName = $AdminNamePrefix + $FirstName + $LastName }
                'LastNameFirstName' { $AdminAccountName = $AdminNamePrefix + $LastName + $FirstName }
                'Random' { $AdminAccountName = $AdminNamePrefix + $RandomNum1+$RandomNum2+$RandomNum3+$RandomNum4+$RandomNum5+$RandomNum6 }
                default { $AdminAccountName = $AdminNamePrefix + $FirstName + $LastNameInitial }
             }
         }
        IF ($AdminNameSuffix)
         { 
            SWITCH ($NameFormatLayout)
             {
                'FirstL' { $AdminAccountName = $FirstName + $LastNameInitial + $AdminNameSuffix }
                'LastF' { $AdminAccountName = $FirstNameInitial + $LastName + $AdminNameSuffix }
                'FirstNameLastName' { $AdminAccountName = $AdminNamePrefix + $FirstName + $LastName + $AdminNameSuffix }
                'LastNameFirstName' { $AdminAccountName = $AdminNamePrefix + $LastName + $FirstName + $AdminNameSuffix }
                'Random' { $AdminAccountName = $RandomNum1+$RandomNum2+$RandomNum3+$RandomNum4+$RandomNum5+$RandomNum6 + $AdminNameSuffix }
                default { $AdminAccountName = $FirstName + $LastNameInitial + $AdminNameSuffix }
             }
         }
        
        $AdminAccountUPN = $AdminAccountName + "@" + $DomainInfo.DNSRoot

        IF ($PasswordString -eq $False)
         { $Password = $PasswordArray | Get-Random -Count 1 }  

        $ReversibleEncryptionSetting = get-random -min 1 -max 6
        If ($ReversibleEncryptionSetting -eq 1)
         { $ReversibleEncrpytionSet = $True }
        ELSE
         { $ReversibleEncrpytionSet = $False }

        $PasswordNotRequiredSetting = get-random -min 1 -max 6
        If ($PasswordNotRequiredSetting -eq 2)
         { $PasswordNotRequiredSet = $True }
        ELSE
         { $PasswordNotRequiredSet = $False }

        $PasswordNeverExpiresSetting = get-random -min 1 -max 6
        If ($PasswordNeverExpiresSetting -eq 5)
         { $PasswordNeverExpiresSet = $True }
        ELSE
         { $PasswordNeverExpiresSet = $False }

        $KerberosEncyptionDESSetting = get-random -min 1 -max 6
        If ($KerberosEncyptionDESSetting -eq 3)
         { $KerberosEncyptionSet = $True }
        ELSE
         { $KerberosEncyptionSet = $False }

        $DoesNotRequirePreAuthSetting = get-random -min 1 -max 6
        If ($DoesNotRequirePreAuthSetting -eq 4)
         { $DoesNotRequirePreAuthSet = $True }
        ELSE
         { $DoesNotRequirePreAuthSet = $False }

        $CannotChangePasswordSetting = get-random -min 1 -max 6
        If ($CannotChangePasswordSetting -eq 1)
         { $CannotChangePasswordSet = $True }
        ELSE
         { $CannotChangePasswordSet = $False }

        $SmartcardLogonRequiredSetting = get-random -min 1 -max 6
        If ($SmartcardLogonRequiredSetting -eq 2)
         { $SmartcardLogonRequiredSet = $True }
        ELSE
         { $SmartcardLogonRequiredSet = $False }

        $CannotChangePasswordSetting = get-random -min 1 -max 6
        If ($CannotChangePasswordSetting -eq 3)
         { $CannotChangePasswordSet = $True }
        ELSE
         { $CannotChangePasswordSet = $False }

        $SmartcardLogonRequiredSetting = get-random -min 1 -max 6
        If ($SmartcardLogonRequiredSetting -eq 4)
         { $SmartcardLogonRequiredSet = $True }
        ELSE
         { $SmartcardLogonRequiredSet = $False }

        $AdminAccounEmailSetting = get-random -min 1 -max 6
        If ($AdminAccounEmailSetting -eq 4)
         { $AdminAccounEmail = $AdminAccountUPN }
        ELSE
         { $AdminAccounEmail = $NULL }
        
        New-ADUser -Name $AdminAccountName -AccountPassword (ConvertTo-SecureString -AsPlainText $Password -Force) -Path $AdminAccountOU `
         -Description "Test admin User" -GivenName $FirstName -Surname $LastName -UserPrincipalName $AdminAccountUPN  `
         -CannotChangePassword $CannotChangePasswordSet -AllowReversiblePasswordEncryption $ReversibleEncrpytionSet -PasswordNotRequired  $PasswordNotRequiredSet `
         -PasswordNeverExpires $PasswordNeverExpiresSet -SmartcardLogonRequired $SmartcardLogonRequiredSet -EmailAddress $AdminAccounEmail `
         -Enabled $True -Server $DomainDC
        Set-ADAccountControl -Identity $AdminAccountName -DoesNotRequirePreAuth $DoesNotRequirePreAuthSet -Server $DomainDC
     }
    While 
     ( $AdminAccountLoopCount -lt $NumberOfAdminAccounts )

    Write-Host "Lab admin account creation complete"
 }

Function Create-ADLabGMSAs
 {
    Param
     (
        [Parameter(Mandatory=$true)][string]$Domain,
        [Parameter(Mandatory=$true)][int]$NumberofGMSAs,
        [Parameter(Mandatory=$true)][string]$GroupOU,
        [string]$GMSAPrefix,
        [switch]$InstallKDSRootKey,
        [switch]$SkipKDSRootKeyCheck
     )
    
    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
    $DomainInfo = Get-ADDomain -Server $DomainDC

    $GroupOUPath = $GroupOU + ',' + $DomainInfo.DistinguishedName
    IF ($SkipKDSRootKeyCheck -eq $True)
     { Write-Host "Skipping KDS Root Key Installation check across domains." }
    ELSE
     {
        Write-Host "Checking for KDS Root Key Installation across domains..."
        $KDSRootKeyArray = Get-KdsRootKey
        $KDSRootKeyDomainArray = @()
        ForEach ($KDSRootKeyArrayItem in $KDSRootKeyArray)
         { 
            $DC1 = $KDSRootKeyArrayItem.DomainController -Replace('CN=',"") 
            $DC2 = $DC1 -Replace (',OU=Domain Controllers',"")
            $DomainDC = $DC2 -Replace (',DC=',".")
            $KDSDomainArray = Get-ADDomain -Server $DomainDC
            $KDSDomainArray | Add-Member -MemberType NoteProperty -Name KDSCreationTime -Value $KDSRootKeyArrayItem.CreationTime -Force
            [array]$KDSRootKeyDomainArray += $KDSDomainArray
         }

        $KDSDomainCheck = $KDSRootKeyDomainArray | Where {$_.DNSRoot -eq $Domain}
        IF ( (!$KDSDomainCheck) -AND ($InstallKDSRootKey -eq $True) )
         { 
            write-host "Configuring KDS root key for $Domain"
            Invoke-Command -ComputerName $DomainDC -ScriptBlock { Add-KdsRootKey -EffectiveImmediately } 
            Start-Sleep -Seconds 120
         }
        ELSE
         { Write-Host "KDS Root Key already installed for $Domain" }
     }
      $LabServiceAccountArray = @('Acronis','AGPM','Azure','BESServer','BigFix','Brightmail','CAXOER','CheckPoint','CiscoUnity','Citrix','CitrixPVS','Cloudera','Cognos','CommVault','CyberArkReconcile','Dynamics','Exchange','ExchArchive','FIM','Flume',`
    'Hadoop','Imanami','Impala','InfoSphere','Insight','JBoss','Kafka','LDAP','Mongo','MagFS','NetIQ','OpenAccess','Oracle','PaloAlto','Patch','Qualys','Quest','SAPBO','SCCM','ServiceNow','SCOM','SharePoint','MSSQL','Varonis','VMWare','VPN','Web')
   
    $GMSADoWhileLoop = 0
    DO
    {
        $GMSADoWhileLoop++
        Write-Host "Creating GMSA account $GMSADoWhileLoop of $NumberofGMSAs"
        
        $GMSANumber = Get-Random -Minimum 1 -Maximum 10 

        $GMSAAccount = $($LabServiceAccountArray | Get-Random -count 1)
        $GMSAAccountName = $GMSAPrefix + $GMSAAccount 
        $GmsaDescription = "Account for $GMSAAccount "
        $GmsaDNSHostName = 'SRV' + $GMSAAccount + '0' + $GMSANumber + '.' + $Domain
        $GmsaGroupName = $GMSAAccountName + '0' + $GMSANumber

        New-ADGroup -Name $GmsaGroupName -DisplayName $GmsaGroupName -GroupScope Global -Path $GroupOUPath -Server $DomainDC

        New-ADServiceAccount -Name $GMSAAccountName -Description $GmsaDescription -DNSHostName $GmsaDNSHostName -ManagedPasswordIntervalInDays 30 -PrincipalsAllowedToRetrieveManagedPassword $GmsaGroupName -Enabled $True -PassThru -Server $DomainDC
     }
     WHILE
      ($GMSADoWhileLoop -lt $NumberofGMSAs)

    Write-Host "Created $NumberofGMSAs GMSAs in $Domain"

  }

Function Create-ADLabWindowsWorkstations
 {
    Param
     (
        [Parameter(Mandatory=$true)]$Domain,
        [Parameter(Mandatory=$true)][int]$NumberOfWorkstations,
        [Parameter(Mandatory=$true)][string]$ComputerOU
     )

    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
    $DomainInfo = Get-ADDomain -Server $DomainDC
    
    $WorkstationOperatingSystemArray = @('Windows XP Professional','Windows 7 Enterprise','Windows 7 Professional','Windows 7 Ultimate',  `
    'Windows 8 Enterprise','Windows 8.1 Enterprise', `
    'Windows 10 Enterprise','Windows 10 Professional', ,'Windows 10 Enterprise 2016 LTSB','Windows 10 Enterprise LTSC', `
    'Windows 10 Enterprise','Windows 10 Pro', ,'Windows 10 Enterprise 2016 LTSB','Windows 10 Enterprise LTSC', `
    'Windows 11 Business','Windows 11 Professional','Windows 11 Enterprise','Windows 11 Enterprise LTSC', `
    'Windows 11 Professional','Windows 11 Enterprise','Windows 11 Enterprise LTSC')

    $ComputerOUPath = $ComputerOU + ',' + $DomainInfo.DistinguishedName

    $DoWhileWorkstationLoop = 0
    DO
     {
        $DoWhileWorkstationLoop++
        Write-Host "Creating Windows Workstation computer account $DoWhileWorkstationLoop of $NumberOfWorkstations"
        
        $ComputerOperatingSystem = $($WorkstationOperatingSystemArray | Get-Random -count 1)
        $ComputerNumber = Get-Random -Minimum 100 -Maximum 999
        $ComputerAlpha = -join ((65..90) | Get-Random -Count 3 | % {[char]$_})
        $ComputerName = 'WRK' + ($DomainInfo.Name).ToUpper() + $ComputerAlpha + $ComputerNumber

        New-ADComputer -Name $ComputerName -OperatingSystem $ComputerOperatingSystem -Path $ComputerOUPath -Enabled $True -Server $DomainDC

     }
     WHILE
      ( $DoWhileWorkstationLoop -lt $NumberOfWorkstations )
 }
 
Function Create-ADLabWindowsServers
 {
    Param
     (
        [Parameter(Mandatory=$true)]$Domain,
        [Parameter(Mandatory=$true)][int]$NumberOfservers,
        [Parameter(Mandatory=$true)][string]$ComputerOU
     )

    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
    $DomainInfo = Get-ADDomain -Server $DomainDC
    
    $WindowsServerOperatingSystemArray = @('Windows Server 2003', `
    'Windows Server 2008 Enterprise',
    'Windows Server 2008 R2 Standard','Windows Server 2008 R2 Enterprise', 'Windows Server 2008 R2 Datacenter'
    'Windows Server 2012 Standard','Windows Server 2012 Enterprise', `
    'Windows Server 2012 R2 Standard','Windows Server 2012 R2 Enterprise', ` 
    'Windows Server 2016 Standard','Windows Server 2019 Standard','Windows Server 2019 Datacenter', 
    'Windows Server 2022 Standard','Windows Server 2022 Enterprise','Windows Server 2025 Standard','Windows Server 2025 Enterprise')

    $ComputerOUPath = $ComputerOU + ',' + $DomainInfo.DistinguishedName

    $DoWhileServerLoop = 0
    DO
     {
        $DoWhileServerLoop++
        Write-Host "Creating Windows Server computer account $DoWhileServerLoop of $NumberOfservers"
        
        $ComputerOperatingSystem = $($WindowsServerOperatingSystemArray | Get-Random -count 1)
        $ComputerNumber = Get-Random -Minimum 100 -Maximum 999
        $ComputerAlpha = -join ((65..90) | Get-Random -Count 3 | % {[char]$_})
        $ComputerName = 'SRV' + ($DomainInfo.Name).ToUpper() + $ComputerAlpha + $ComputerNumber

        New-ADComputer -Name $ComputerName -OperatingSystem $ComputerOperatingSystem -Path $ComputerOUPath -Enabled $True -Server $DomainDC

     }
     WHILE
      ( $DoWhileServerLoop -lt $NumberOfservers )
 }

Function Create-ADLabComputers
 {
    Param
     (
        [Parameter(Mandatory=$true)]$Domain,
        [Parameter(Mandatory=$true)][int]$NumberOfComputers,
        [Parameter(Mandatory=$true)][string]$ComputerOU
     )

    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
    $DomainInfo = Get-ADDomain -Server $DomainDC
    
    $NonWindowsOperatingSystemArray = @(
    'Acropolis File Server OS','AIX','CentOS','CentOS Linux release 7.5.1804 (Core)','Centrify','Cisco Identity Services Engine',
    'Cohesity','Darwin','Debian','Data Domain OS','EMC Celerra File Server','EMC File Server',"Enterprise Linux Enterprise Linux Server release 5.11 (Carthage)",
    "Enterprise Linux Enterprise Linux Server release 5.5 (Carthage)","Enterprise Linux Enterprise Linux Server release 5.7 (Carthage)",
    'GuardianOS','HP-UX','Hyper-V','Kazeon Information Server Software','LikeWise Identity','LikeWise Open','Linux',
    'Mac OS X','NetApp Release 8.3.1','NetApp Release 8.3.2P2','NetApp Release 8.3.2P4','NetApp Release 9.1P2',
    'NetApp Release 9.1P8','NetApp Release 9.2','NetApp Release 9.3P3','NetApp Release 9.3P4','NetApp Release 9.3P8',
    'NetApp Release 9.4','NetApp Release 9.5P1','NetApp Release 9.5P2','NetApp Release 9.5P3','NetApp Release 9.5P4',
    'NetApp Release 9.5P6','NetApp Release 9.5P10','NetApp Release 9.7P3','NetApp Release 9.7P5','Nutanix Files',
    'OneFS','OnTap','ONTAP 8.1','Oracle Linux',"Oracle Linux Server release 6.1","Oracle Linux Server release 6.10",
    "Oracle Linux Server release 6.5","Oracle Linux Server release 6.7","Oracle Linux Server release 6.8",
    "Oracle Linux Server release 6.9","Oracle Linux Server release 7.4","Oracle Linux Server release 7.5",
    "Oracle Linux Server release 7.6","Oracle Linux Server release 7.7",'PBIS','redhatlinuxgnu',
    'Red Hat Enterprise Linux',"Red Hat Enterprise Linux Server release 5.11 (Tikanga)",
    "Red Hat Enterprise Linux Server release 5.7 (Tikanga)","Red Hat Enterprise Linux Server release 6.10 (Santiago)",
    "Red Hat Enterprise Linux Server release 6.4 (Santiago)","Red Hat Enterprise Linux Server release 6.6 (Santiago)",
    "Red Hat Enterprise Linux Server release 6.7 (Santiago)","Red Hat Enterprise Linux Server release 6.8 (Santiago)",
    "Red Hat Enterprise Linux Server release 6.9 (Santiago)","Red Hat Enterprise Linux Server release 7.1 (Maipo)",
    "Red Hat Enterprise Linux Server release 7.3 (Maipo)","Red Hat Enterprise Linux Server release 7.4 (Maipo)",
    "Red Hat Enterprise Linux Server release 7.5 (Maipo)","Red Hat Enterprise Linux Server release 7.6 (Maipo)",
    "Red Hat Enterprise Linux Server release 7.7 (Maipo)","Red Hat Enterprise Linux Server release 7.8 (Maipo)",
    'Samba','SLES','SunOS','Solaris','SUSE Linux',"SUSE Linux Enterprise Server 11 (x86_64)",
    "SUSE Linux Enterprise Server 12 SP4",'OneFS','Ubuntu 16.04.3 LTS','unknown')

    $ComputerOUPath = $ComputerOU + ',' + $DomainInfo.DistinguishedName

    $DoWhileServerLoop = 0
    DO
     {
        $DoWhileServerLoop++
        Write-Host "Creating Non-Windows computer account $DoWhileServerLoop of $NumberOfservers"
        
        $ComputerOperatingSystem = $($NonWindowsOperatingSystemArray | Get-Random -count 1)
        $ComputerNumber = Get-Random -Minimum 100 -Maximum 999
        $ComputerAlpha = -join ((65..90) | Get-Random -Count 3 | % {[char]$_})
        $ComputerName = 'SRV' + ($DomainInfo.Name).ToUpper() + $ComputerAlpha + $ComputerNumber

        New-ADComputer -Name $ComputerName -OperatingSystem $ComputerOperatingSystem -Path $ComputerOUPath -Enabled $True -Server $DomainDC

     }
     WHILE
      ( $DoWhileServerLoop -lt $NumberOfservers )
 }

Function Create-ADLabFGPPs
 {
    Param
     (
        [Parameter(Mandatory=$true)]$Domain,
        [Parameter(Mandatory=$true)]$NumberOfFGPPs,
        [Parameter(Mandatory=$true)]$AdminGroupOU
     )
    
    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
    $DomainInfo = Get-ADDomain -Server $DomainDC

    $AdminGroupsPathDN = $AdminGroupOU + ',' + $DomainInfo.DistinguishedName

    [int]$FGPPDOWhileLoop = 0
    Do
     {
        $FGPPDOWhileLoop++
        Write-Host "Create Fine-Grained Password Policies in $ForestDomainItem ($FGPPDOWhileLoop of $NumberOfFGPPs)..." -ForegroundColor Cyan

        $RandomNumber = Get-Random -Minimum 11 -Maximum 49
        $FGPPGroupName = "$(($DomainInfo.Name).ToUpper())-FGPP-$RandomNumber-Group"
        $FGPPName = "$(($DomainInfo.Name).ToUpper())-FGPP-$RandomNumber"
        
        New-ADGroup -Name $FGPPGroupName -SamAccountName $FGPPName -GroupCategory Security -GroupScope Universal -DisplayName $FGPPGroupName -Path $AdminGroupsPathDN -Server $DomainDC  
        Start-Sleep -Seconds 5

        New-ADFineGrainedPasswordPolicy -Name $FGPPName -DisplayName $FGPPName -Precedence 100 -ComplexityEnabled $true -ReversibleEncryptionEnabled $false -PasswordHistoryCount 10 -MinPasswordLength 12 -MinPasswordAge 3.00:00:00 -MaxPasswordAge 30.00:00:00 -LockoutThreshold 3 -LockoutObservationWindow 0.00:25:00 -LockoutDuration 0.00:30:00 -Server $DomainDC 
       #  Add-ADFineGrainedPasswordPolicySubject $FGPPName -Subjects $FGPPGroupName -Server $DomainDC 
      }
    WHILE
     ( $FGPPDOWhileLoop -lt $NumberOfFGPPs ) 
 }

Function Set-SPNDefaultAdminAccount
 {
    Param
     (
        [Parameter(Mandatory=$true)]$Domain,
        [Parameter(Mandatory=$true)]$ServerOU
     )

    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
    $DomainInfo = Get-ADDomain -Server $DomainDC

    Write-Host "Add SPN to default Administrator Account in $Domain ..." -ForegroundColor Cyan
    $SPNNames = @('Alpha','Beta','Gamma','Delta','Epsilon','Zeta','Eta','Theta','Iota','Kappa','Lambda','Omicron','Sigma','Omega')
    $SPNMachineName = $SPNNames | Get-Random -Count 1
    $ServerName = $SPNMachineName + (Get-Random -Minimum 1 -Maximum 99)
    $ServerOUPath = $ServerOU + ',' + $DomainInfo.DistinguishedName
    New-ADComputer -Name $ServerName -SamAccountName $ServerName -Path $ServerOUPath -Server $DomainDC 
    $SPN = 'MSSQLSvc/' + $ServerName + ':1433'
    [string]$DefaultDomainAdminSID = $DomainInfo.DomainSID.Value + '-500'
    $DefaultDomainAdministrator = Get-ADObject -Identity $((Get-ADUser $DefaultDomainAdminSID -Server $DomainDC).DistinguishedName) -Server $DomainDC
    TRY
        { Set-ADObject -Identity $($DefaultDomainAdministrator.DistinguishedName) -add @{serviceprincipalname=$SPN} -Server $DomainDC } 
    CATCH
        { Write-Warning "Unable to set the SPN $SPN on the default Administrator account $DefaultDomainAdministratorDN using the DC $DomainDC" }  
 }

Function Invoke-RandomizeAdmins
 {
    Param
     (
        [Parameter(Mandatory=$true)]$Domain,
        [Parameter(Mandatory=$true)]$AdminOU,
        [Parameter(Mandatory=$true)]$ADAdminGroups
     )

    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
    $DomainInfo = Get-ADDomain -Server $DomainDC

    $AdminOUPath = $AdminOU + ',' + $DomainInfo.DistinguishedName

    [array]$AdminUserArray = Get-ADUser -Filter * -SearchBase $AdminOUPath -Server $DomainDC

    Write-Host "Discovered $($AdminUserArray.Count) Admin Accounts in $AdminOUPath"

    ForEach ($ADAdminGroupItem in $ADAdminGroups)
     {
        $DoWhileLoopTotalCount = Get-Random -Min 1 -Max $($AdminUserArray.Count)
        [int]$DoWhileLoopCount = 0
        
        Write-Host "Adding $DoWhileLoopTotalCount Admin Accounts to the privileged group $ADAdminGroupItem"

        DO
         {
            $DoWhileLoopCount++
            $AdminAccountDN = ($AdminUserArray | Get-Random -Count 1).DistinguishedName
            Add-ADGroupMember -Identity $ADAdminGroupItem -Members $AdminAccountDN -Server $DomainDC

         }
        WHILE ($DoWhileLoopCount -le $DoWhileLoopTotalCount)
     }
 }

Function Invoke-RandomizeServiceAccountAdmins
 {
    Param
     (
        [Parameter(Mandatory=$true)]$Domain,
        [Parameter(Mandatory=$true)]$ServiceAccountOU,
        [Parameter(Mandatory=$true)]$MaxServiceAccountsInAGroup,
        [Parameter(Mandatory=$true)]$ADAdminGroups 
      )

    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
    $DomainInfo = Get-ADDomain -Server $DomainDC

    $ServiceAccountOUPath = $ServiceAccountOU + ',' + $DomainInfo.DistinguishedName

    [array]$ServiceAccountArray = Get-ADUser -Filter * -SearchBase $ServiceAccountOUPath -Server $DomainDC

    Write-Host "Discovered $($ServiceAccountArray.Count) Service Accounts in $ServiceAccountOUPath"

    ForEach ($ADAdminGroupItem in $ADAdminGroups)
     {
        $DoWhileLoopTotalCount = Get-Random -Min 1 -Max $MaxServiceAccountsInAGroup
        [int]$DoWhileLoopCount = 0
        
        Write-Host "Adding $DoWhileLoopTotalCount Service Accounts to the privileged group $ADAdminGroupItem"

        DO
         {
            $DoWhileLoopCount++
            $ServiceAccountAccountDN = ($ServiceAccountArray | Get-Random -Count 1).DistinguishedName
            Add-ADGroupMember -Identity $ADAdminGroupItem -Members $ServiceAccountAccountDN -Server $DomainDC

         }
        WHILE ($DoWhileLoopCount -le $DoWhileLoopTotalCount)
     }
 }

Function Add-PasswordToADAttribute
 {
    Param
     (
        [Parameter(Mandatory=$true)]$Domain,
        [Parameter(Mandatory=$true)][ValidateSet("Description","Info/Notes")]$Attribute,
        [Parameter(Mandatory=$true)]$AccountOU,
        $Password
     )  
    
    IF (!$Password)
     { $Password = 'Password99!' } 

    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
    $DomainInfo = Get-ADDomain -Server $DomainDC

    $OUDN = $AccountOU + ',' + $DomainInfo.DistinguishedName

    $ADUserAccountArray = Get-ADUser -filter * -SearchBase $OUDN
    $ADUserAccount = $ADUserAccountArray | Get-Random -Count 1

    SWITCH ($Attribute)
     {
       'Description' { Set-ADUser -Identity $ADUserAccount.SamAccountName -Description $Password -Server $DomainDC }
       'Info/Notes' { Set-ADUser -Identity $ADUserAccount.SamAccountName -Replace @{info=$Password} -Server $DomainDC }
     }
 }

Function Add-KerberosDelegation
 {
    Param
     (
        [Parameter(Mandatory=$true)]$Domain,
        [Parameter(Mandatory=$true)]$ServiceAccountOU,
        [Parameter(Mandatory=$true)]$ServerAccountOU,
        [Parameter(Mandatory=$true)]$NumberOfKerberosDelegation,
        $ServiceAccountPrefix,
        $ReplicationDelayNumber,
        $Password
      )

    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
    $DomainInfo = Get-ADDomain -Server $DomainDC 

    $ServiceAccountOUPath = $ServiceAccountOU + ',' + $DomainInfo.DistinguishedName
    $ServerAccountOUPath = $ServerAccountOU + ',' + $DomainInfo.DistinguishedName

    $ApplicationNamePrefixArray = @('Alpha','Beta','Gamma','Delta','Epsilon','Zeta','Eta','Theta','Iota','Kappa','Lambda','Omicron','Sigma','Omega')
    $InstancePortOptionArray = @('80','110','389','443','636','1433','3389')

    IF (!$ReplicationDelayNumber)
     { $ReplicationDelayNumber = '15' }

    IF (!$Password)
     { $Password = 'Password1234!' }

    $RandomBoolean = @($True, $False)

    [int]$DoWhileKerbDelegationLoopNum = 1
    DO
      {
        $ApplicationNamePrefix = $ApplicationNamePrefixArray | Get-Random -Count 1
    
        $ServerName = $ApplicationNamePrefix + 'DB' + (Get-Random -Minimum 1 -Maximum 50)
        New-ADComputer -Name $ServerName -SamAccountName $ServerName -Path $ServerAccountOUPath -Server $DomainDC
        $InstanceOrPort = $InstancePortOptionArray | Get-Random -Count 1 
        IF ($InstanceOrPort -eq "Application")
         { $InstanceOrPort = $ApplicationNamePrefix } 
        $SPN = 'MSSQLSvc/' + $ServerName + ':' + $InstanceOrPort
        [array]$SPNArray += $SPN
    
        IF ($ServiceAccountPrefix)
         { $UserID = $ServiceAccountPrefix + $ApplicationNamePrefix + (Get-Random -Minimum 1 -Maximum 50) }
        ELSE
         { $UserID = $ApplicationNamePrefix + (Get-Random -Minimum 1 -Maximum 50) }

        New-ADUser $UserID -Path $ServiceAccountOUPath -AccountPassword (ConvertTo-SecureString -AsPlainText $Password -Force) -Enabled $True -Server $DomainDC

        Start-Sleep -Seconds $ReplicationDelayNumber
        $ServiceAccountDN = (Get-ADUser $UserID -Server $DomainDC).DistinguishedName
        Set-ADObject -Identity $ServiceAccountDN -add @{serviceprincipalname=$SPN} -Server $DomainDC 
    
        $TrustedForDelegationBoolean = $RandomBoolean | Get-Random -Count 1

        IF ($DoWhileKerbDelegationLoopNum % 2 -eq 0 ) 
        { $TrustedForDelegationBoolean -eq $True } # Enables Unconstrained Delegation 

        IF ($DoWhileKerbDelegationLoopNum % 2 -eq 1 ) {  } 

        IF ($TrustedForDelegationBoolean -eq $True)
         { $TrustedToAuthForDelegationBoolean = $False }
        ELSE
         { $TrustedToAuthForDelegationBoolean = $True  } # Enables Constrained Delegation Protocol Transition
        Set-ADAccountControl -Identity $ServiceAccountDN -TrustedForDelegation $TrustedForDelegationBoolean -TrustedToAuthForDelegation $TrustedToAuthForDelegationBoolean -Server $DomainDC
    
        IF ($SPNArray.Count -lt 10)
          { $DelegateToSPN = $SPNArray  | Get-Random -Count 1 } 
        IF ($SPNArray.Count -ge 10)
          { [array]$DelegateToSPN = $SPNArray  | Get-Random -Count 5 } 
        Set-ADObject $ServiceAccountDN -add @{'msDS-AllowedToDelegateTo'="$DelegateToSPN"} -Server $DomainDC

        $DoWhileKerbDelegationLoopNum++
      } 
    While ( $DoWhileKerbDelegationLoopNum -le $NumberOfKerberosDelegation ) 
 }


################################################


IF ($CreateTopLevelOUs -eq $True)
  {
    Create-TopLevelOUs -Domain $Domain
  }

IF ($CreateBranchOfficeOUs -eq $True)
  {
    Create-BranchOfficeOUs -Domain $Domain -CreateTopLevelOUContainer
  }

IF ($RenameDomainAdministrator -eq $True)
  {
    Rename-DomainAdministrator -Domain $Domain -NewName 'TRDAdministrator'
  }

IF ($CreateADLabUsers -eq $True)
  {
    Create-ADLabUsers -Domain $Domain -NumberOfADUserAccounts '20' -FirstNameFile 'C:\Scripts\FirstNames.csv' -LastNameFile 'C:\Scripts\LastNames.csv' -UserOU "OU=Domain Users" -EnableAccounts
  }

IF ($CreateADLabGroups -eq $True)
  {
    Create-ADLabGroups -Domain $Domain -GroupOU 'OU=Groups,OU=Enterprise Services'
  }

IF ($CreateADLabServiceAccounts -eq $True)
  {
    Create-ADLabServiceAccounts -Domain $Domain -NumberOfAccounts 10 -OUPath 'OU=Service Accounts,OU=Enterprise Services'
  }

IF ($CreateADLabAdminAccounts -eq $True)
  {
    Create-ADLabAdminAccounts -Domain $Domain -AdminNamePrefix 'Admin' -NumberOfAdminAccounts '10' -FirstNameFile 'C:\Scripts\FirstNames.csv' -LastNameFile 'C:\Scripts\LastNames.csv' -AccountOU 'OU=Accounts,OU=AD Administration'
  }

IF ($CreateADLabGMSAs -eq $True) 
  {
    Create-ADLabGMSAs -Domain $Domain -NumberofGMSAs '10' -GMSAPrefix 'gmsa-' -GroupOU 'OU=Groups,OU=Enterprise Services' -InstallKDSRootKey
  }

IF ($CreateADLabWorkstations -eq $True)
  {
    Create-ADLabWindowsWorkstations -Domain $Domain -NumberOfWorkstations '20' -ComputerOU 'OU=Workstations'
  }

IF ($CreateADLabServers -eq $True)
  {
    Create-ADLabWindowsServers -Domain $Domain -NumberOfservers '20' -ComputerOU 'OU=Servers,OU=Enterprise Services'
  }

IF ($CreateADLabComputers -eq $True)
  {
    Create-ADLabComputers -Domain $Domain -NumberOfComputers '20' -ComputerOU 'OU=Servers,OU=Enterprise Services'
  }

IF ($CreateADLabFGPPs -eq $True) 
  {
    Create-ADLabFGPPs -Domain $Domain -NumberOfFGPPs 10 -AdminGroupOU 'OU=Groups,OU=Enterprise Services'
  }

IF ($SetSPNDefaultAdminAccount -eq $True) 
  {
    Set-SPNDefaultAdminAccount -Domain $Domain -ServerOU 'OU=Servers,OU=Enterprise Services'
  }

IF ($InvokeRandomizeAdmins -eq $True) 
  {
    Invoke-RandomizeAdmins -Domain $Domain -AdminOU 'OU=Accounts,OU=AD Administration' -ADAdminGroups @('Administrators','Account Operators','Backup Operators','Cert Publishers','DNSAdmins','Domain Admins','Enterprise Key Admins','Print Operators','Server Operators''Schema Admins')
  }

IF ($InvokeRandomizeServiceAccountAdmins -eq $True) 
  {
    Invoke-RandomizeServiceAccountAdmins -Domain $Domain -MaxServiceAccountsInAGroup 10 -ServiceAccountOU 'OU=Service Accounts,OU=Enterprise Services' -ADAdminGroups @('Administrators','Account Operators','Backup Operators','Cert Publishers','DNSAdmins','Domain Admins','Enterprise Key Admins','Print Operators','Server Operators''Schema Admins')
  }

IF ($AddPasswordToADAttribute -eq $True) 
  {
    Add-PasswordToADAttribute -Domain $Domain -Attribute "Info/Notes" -AccountOU 'OU=Service Accounts,OU=Enterprise Services' 
  }

IF ($AddKerberosDelegation -eq $True) 
  {
    Add-KerberosDelegation -Domain $Domain -NumberOfKerberosDelegation 5 -ServiceAccountPrefix 'svc-' -ServiceAccountOU 'OU=Service Accounts,OU=Enterprise Services' -ServerAccountOU 'OU=Servers,OU=Enterprise Services' 
  }

