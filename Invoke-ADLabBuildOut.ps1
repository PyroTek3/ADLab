Param
 (
    $Domain = 'na.trd.com',
    [switch]$CreateTopLevelOUs,
    [switch]$CreateBranchOfficeOUs,
    [switch]$RenameDomainAdministrator,
    [switch]$CreateADLabUsers,
    [switch]$CreateADLabGroups,
    [switch]$CreateADLabServiceAccounts,
    [switch]$CreateADLabAdminAccounts
 )


Function Create-TopLevelOUs
 {
    Param
     (
        [Parameter(Mandatory=$true)]$Domain
     )

    [array]$TopLevelOUs = @('AD Administration','Enterprise Services','Domain Users')

    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
    $DomainInfo = Get-ADDomain -Server $DomainDC

    ForEach ($TopLevelOUsItem in $TopLevelOUs)
     {
        New-ADOrganizationalUnit $TopLevelOUsItem -Server $DomainDC
        Start-sleep 5
        IF ($TopLevelOUsItem -like "*Admin*")
         {
            New-ADOrganizationalUnit 'Accounts' -Server $DomainDC -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False
            New-ADOrganizationalUnit 'Computers' -Server $DomainDC -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False
            New-ADOrganizationalUnit 'Groups' -Server $DomainDC -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False
            New-ADOrganizationalUnit 'Service Accounts' -Server $DomainDC -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False
         }
        IF ($TopLevelOUsItem -eq "Enterprise Services")
         {
            New-ADOrganizationalUnit 'Exchange' -Server $DomainDC -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False
            New-ADOrganizationalUnit 'SCCM' -Server $DomainDC -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False
            New-ADOrganizationalUnit 'VMware' -Server $DomainDC -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False
            New-ADOrganizationalUnit 'Web Servers' -Server $DomainDC -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False
            New-ADOrganizationalUnit 'Servers' -Server $DomainDC -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False
            New-ADOrganizationalUnit 'Service Accounts' -Server $DomainDC -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False
            New-ADOrganizationalUnit 'Groups' -Server $DomainDC -Path "OU=$TopLevelOUsItem,$($DomainInfo.DistinguishedName)" -ProtectedFromAccidentalDeletion $False 
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
    $SATopLevelOUArray = @('São Paulo','Buenos Aires','Rio de Janeiro','Bogotá','Lima','Santiago','Belo Horizonte','Salvador','Brasília','Caracas',"Medellín","Guayaquil","Fortaleza","Salvador","Belo Horizonte","Manaus","Cali","Curitiba","Quito","Maracaibo","Santa Cruz de la Sierra","Recife",'Córdoba')

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

    ForEach ($TopLevelOUArrayItem in $TopLevelOUArray)
     { 
        Write-Host "Creating the OU $TopLevelOUArrayItem in $domain"
        New-ADOrganizationalUnit $TopLevelOUArrayItem -Path $OUPath -Server $DomainDC -ProtectedFromAccidentalDeletion $False 
        Start-Sleep 3
        ForEach ($TopLevelOUStructureArrayItem in $TopLevelOUStructureArray)
         { New-ADOrganizationalUnit $TopLevelOUStructureArrayItem -Path "OU=$TopLevelOUArrayItem,$OUPath" -Server $DomainDC -ProtectedFromAccidentalDeletion $False }
     }
     Write-Host "Top-level OU creation complete"    
 }

Function Rename-DomainAdministrator
 {
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
        [Parameter(Mandatory=$true)][string]$Password,
        [Parameter(Mandatory=$true)]$FirstNameFile,
        [Parameter(Mandatory=$true)]$LastNameFile,
        [Parameter(Mandatory=$true)]$UserOU,
        [switch]$EnableAccounts,
        [switch]$RandomUserName
     )

     $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name

     $FirstNameArray = Import-CSV $FirstNameFile
     $LastNameArray = Import-CSV $LastNameFile

     $DomainInfo = Get-ADDomain -Server $DomainDC
     IF (!$UserOU)
      { $UserOUPath = "OU=Domain Users,$($DomainInfo.DistinguishedName)" } 
     ELSE
      { $UserOUPath = "OU=$UserOU,$($DomainInfo.DistinguishedName)" }

     [int]$UserAccountLoopCount = 0

    Do
     {  
        $UserAccountLoopCount++
        
        $FirstRandom = Get-Random -Minimum 0 -Maximum 999
        $LastRandom = Get-Random -Minimum 0 -Maximum 99

        $UserFirstName = ($FirstNameArray[$FirstRandom]).Name
        $UserLastName = ($LastNameArray[$LastRandom]).Name
        $DefaultUserID = "$UserFirstName.$UserLastName"
              
        IF ($RandomUserName -eq $True)
        {  ## OPEN IF Duser is True
            $RandomNum1 = Get-Random -minimum 1 -maximum 9
            $RandomNum2 = Get-Random -minimum 1 -maximum 9
            $RandomNum3 = Get-Random -minimum 1 -maximum 9
            $RandomNum4 = Get-Random -minimum 1 -maximum 9
            $RandomNum5 = Get-Random -minimum 1 -maximum 9
            $RandomNum6 = Get-Random -minimum 1 -maximum 9
                  			  
    		$TestUserAccount = "u"+$RandomNum1+$RandomNum2+$RandomNum3+$RandomNum4+$RandomNum5+$RandomNum6
            $TestUserUPN = $TestUserAccount + "@" + $DomainDNS
        }  ## CLOSE IF Duser is True
        ELSE
        {  ## OPEN ELSE Duser is False 
            $TestUserAccount = $DefaultUserID 
            $TestUserUPN = $DefaultUserID + "@" + $DomainDNS
        }  ## CLOSE ELSE Duser is False 

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
		
        IF ($EnableAccounts -eq $True)
         {	     
		   
			    New-ADUser –name "$TestUserAccount" -SamAccountName "$TestUserAccount" -Path "$UserOUPath" -DisplayName "$TestUserAccount" `
			        -Description "$Site TestUser$Count" -Enabled $True -AccountPassword (ConvertTo-SecureString -AsPlainText $Password -Force)  -CannotChangePassword $True `
			        -PasswordNeverExpires $False -HomeDirectory "$HomeDir" -ProfilePath "$ProfilePath" -Company $Company -Organization $Organization `
				    -Department $Department -Division $Division -Office $Office -GivenName $UserFirstName -Surname $UserLastName `
                    -UserPrincipalName $TestUserUPN -Title $Title -HomeDrive $HomeDrive -Server $DomainDC
		    

         }
        ELSE
         {	     
		    
			    New-ADUser –name "$TestUserAccount" -SamAccountName "$TestUserAccount" -Path "$UserOUPath" -DisplayName "$TestUserAccount" `
			        -Description "$Site TestUser$Count" -Enabled $False -AccountPassword (ConvertTo-SecureString -AsPlainText $Password -Force)  -CannotChangePassword $True `
			        -PasswordNeverExpires $False -HomeDirectory "$HomeDir" -ProfilePath "$ProfilePath" -Company $Company -Organization $Organization `
				    -Department $Department -Division $Division -Office $Office -GivenName $UserFirstName -Surname $UserLastName `
                    -UserPrincipalName $TestUserUPN -Title $Title -HomeDrive $HomeDrive  -Server $DomainDC
		     
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
        [Parameter(Mandatory=$true)]$Domain
     )
    
    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name

    $ADGroupArray = @('Workstation Admins','Server Admins')

    ForEach ($ADGroupArrayItem in $ADGroupArray)
     { New-ADGroup -Name $ADGroupArrayItem -GroupCategory "Security" -GroupScope "Global" -Server $DomainDC }

    Write-Host "Lab group creation complete"
  }

Function Create-ADLabServiceAccounts
 {
    Param
    (
        [Parameter(Mandatory=$true)]$Domain,
        [Parameter(Mandatory=$true)]$OUPath,
        [Parameter(Mandatory=$true)]$Password
    )
    
    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name

    $DomainInfo = Get-ADDomain -Server $DomainDC
    IF (!$OUPath)
     { $OUPath = 'OU=Service Accounts,OU=Enterprise Services'}
    $UserOUPath = "$OUPath,$($DomainInfo.DistinguishedName)"

    $LabServiceAccountArray = @('svcAGPM','svcAzure','svcBESServer','svcCiscoUnity','svcCommVault','svcCyberArkReconcile','svcExchange','svcExchArchive','svcImanami','svcLDAP','svcPatch','svcQualys','svcQuest','svcSCCM','svcServiceNow','svcSCOM','svcSQL','svcVaronis','svcVMWare','svcVPN','svcWeb')
    
    [int]$SerivceAccountLoopCount = 0

    ForEach ($LabServiceAccountArrayItem in $LabServiceAccountArray)
     { 
        $SerivceAccountLoopCount++
        $LabServiceAccountArrayUPN = $LabServiceAccountArrayItem + '@' + $DomainInfo.DNSRoot

        Write-Host "Creating service account #$SerivceAccountLoopCount of $($LabServiceAccountArray.Count)"
        New-ADUser -Name $LabServiceAccountArrayItem -AccountPassword (ConvertTo-SecureString -AsPlainText $Password -Force) -UserPrincipalName $LabServiceAccountArrayUPN -Path $UserOUPath -Enabled $True -Server $DomainDC 

        $LabServiceAccountArrayItemName = $DomainInfo.NetBIOSName + '\' + $LabServiceAccountArrayItem 
        Start-sleep 5

        $ServerNumber = Get-Random -min 100 -max 999

        $AGPMSPN = "cmd.exe /C setspn -U -S AgpmServer/TRDAGPMSRV$ServerNumber $LabServiceAccountArrayItemName"
        $EXCHSPN = "cmd.exe /C setspn -U -S exchangeMDB/TRDEXCHSRV$ServerNumber $LabServiceAccountArrayItemName"
        $MSSQLSPN = "cmd.exe /C setspn -U -S MSSQL/TRDSQLDB$ServerNumber $LabServiceAccountArrayItemName"
        $CiscoSPN = "cmd.exe /C setspn -U -S CUSESSIONKEYSVR/TRDCiscoSRV$ServerNumber $LabServiceAccountArrayItemName"
        $QuestSPN = "cmd.exe /C setspn -U -S NPPolicyEvaluator/TRDQSTSRV$ServerNumber $LabServiceAccountArrayItemName"
        $SCOMSPN = "cmd.exe /C setspn -U -S MSOMHSvc/TRDSCOMSRV$ServerNumber $LabServiceAccountArrayItemName"
        $VMwareSPN = "cmd.exe /C setspn -U -S STS/TRDVMW$ServerNumber $LabServiceAccountArrayItemName"
        $WWWSPN = "cmd.exe /C setspn -U -S HTTP/TRDWEB$ServerNumber $LabServiceAccountArrayItemName"

        IF ($LabServiceAccountArrayItem -eq 'svcAGPM')
         { invoke-expression $AGPMSPN  }
        IF ($LabServiceAccountArrayItem -eq 'svcExchange')
         { invoke-expression $EXCHSPN  }
        IF ($LabServiceAccountArrayItem -eq 'svcSQL')
         { invoke-expression $MSSQLSPN }
        IF ($LabServiceAccountArrayItem -eq 'svcCiscoUnity')
         { invoke-expression $CiscoSPN }
        IF ($LabServiceAccountArrayItem -eq 'svcQuest')
         { invoke-expression $QuestSPN }
        IF ($LabServiceAccountArrayItem -eq 'svcSCOM')
         { invoke-expression $SCOMSPN }
        IF ($LabServiceAccountArrayItem -eq 'svcVMWare')
         { invoke-expression $VMwareSPN }
        IF ($LabServiceAccountArrayItem -eq 'svcWeb')
         { invoke-expression $WWWSPN }
     }

     Write-Host "Lab service account creation complete"
 }

Function Create-ADLabAdminAccounts
 {
    Param
     (
        [Parameter(Mandatory=$true)]$Domain,        
        [Parameter(Mandatory=$true)][int]$NumberOfAdminAccounts, # Note that actual # of accounts created may be less than this number due to admin name collisions
        [Parameter(Mandatory=$true)][string]$FirstNameFile,
        [Parameter(Mandatory=$true)][string]$Password,
        [Parameter(Mandatory=$true)][string]$AccountOU,
        [string]$AdminNamePrefix,
        [string]$AdminNameSuffix
    )
    
    $DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
    $DomainInfo = Get-ADDomain -Server $DomainDC
    $AdminAccountOU = "$AccountOU,$($DomainInfo.DistinguishedName)"

    $FirstNameArray = Import-CSV $FirstNameFile

    [int]$AdminAccountLoopCount = 0

    Do
     {  
        $AdminAccountLoopCount++
        $RandomNumber = Get-Random -Minimum 0 -Maximum 999
        $FirstName = ($FirstNameArray[$RandomNumber]).Name
        IF ($AdminNamePrefix)
         { $AdminAccountName = $AdminNamePrefix + $FirstName }
        IF ($AdminNameSuffix)
         { $AdminAccountName = $FirstName + $AdminNameSuffix }
        New-ADUser -Name $AdminAccountName -AccountPassword (ConvertTo-SecureString -AsPlainText $Password -Force) -Server $DomainDC -Path $AdminAccountOU -Enabled $True 
     }
    While 
     ( $AdminAccountLoopCount -lt $NumberOfAdminAccounts )

    Write-Host "Lab admin account creation complete"
 }



#################


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
    Create-ADLabUsers -Domain $Domain -NumberOfADUserAccounts '10' -Password "Password99!" -FirstNameFile 'C:\Scripts\FirstNames.csv' -LastNameFile 'C:\Scripts\LastNames.csv' -UserOU "Domain Users" -EnableAccounts
  }

IF ($CreateADLabGroups -eq $True)
  {
    Create-ADLabGroups -Domain $Domain
  }

IF ($CreateADLabServiceAccounts -eq $True)
  {
    Create-ADLabServiceAccounts -Domain $Domain -OUPath 'OU=Service Accounts,OU=Enterprise Services' -Password "ThisIsASecurePassword!"
  }

IF ($CreateADLabAdminAccounts -eq $True)
  {
    Create-ADLabAdminAccounts -Domain $Domain -AdminNamePrefix 'Admin' -AdminNameSuffix -NumberOfAdminAccounts '10' -FirstNameFile 'C:\Scripts\FirstNames.csv' -LastNameFile 'C:\Scripts\LastNames.csv' -Password  "ThisIsASecurePassword!" -AccountOU 'OU=Accounts,OU=AD Administration'
  }
