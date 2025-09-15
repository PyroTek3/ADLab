# ADLab
Location of some Active Directory lab scripts I have created and find useful

The main script is Invoke-ADLabBuildOut.ps1 which can add elements to a newly created Active Directory forest.
Invoke-ADLabBuildOut Options:

* CreateTopLevelOUs - when this option is selected, it will build out an Admin OU structure and an Enterprise Services OU structure in the selected domain.
* CreateBranchOfficeOUs - when this option is selected and there are regional domains with specific names, it will build out OU structures with the names of cities in that region. There is a default mode where it will automatically build out OUs based on city names.
* RenameDomainAdministrator - rename the default domain administrator account to the provided new name.
* CreateADLabUsers - creates user names based on randomized first names with randomized last names based on the provided format.. Need to have the firstnames.csv and lastnames.csv in a local path for this to work.
* CreateADLabGroups - creates a couple of common group names.
* CreateADLabServiceAccounts - creates commonly used service accounts, some of which will have service principal names associated with them.
* CreateADLabAdminAccounts - creates a set of admin account names based on the provided format. Need to have the firstnames.csv and lastnames.csv in a local path for this to work.
* CreateADLabGMSAs - creates a set of Group Managed Service Accounts. If there's not a KDS root key alsready confiugred, use the parameter InstallKDSRootKey.
* CreateADLabWindowsWorkstations - creates computer accounts with common Windows workstation operating systems.
* CreateADLabWindowsServers - creates computer accounts with common Windows server operating systems.
* CreateADLabComputers - creates computer accounts with common non-Windows operating systems.
* CreateADLabFGPPs - creates Fine-Grained Password Policies with associated groups.
* SetSPNDefaultAdminAccount - sets a service principal name on the default domain administrator account.
* InvokeRandomizeAdmins - gets the current admin accounts and will randomize adding them to privileged groups in AD.
* InvokeRandomizeServiceAccountAdmins - gets the current service accounts and will randomize adding them to privileged groups in AD.
* AddPasswordToADAttribute - gets the user accounts in the domain and randomly adds password information to the info/notes and/or description field.
* AddKerberosDelegation - creates random service account names and randomly configures Kerberos Delegation on them
* AddComputerAccountstoAdmins - gets the server computer accounts and randomly adds to privileged group names
* SetOUsWithBlockedGPOInheritance - randomly configures block Group Policy inheritance on OUs.
