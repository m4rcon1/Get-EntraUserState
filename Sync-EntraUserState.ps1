# 
# 
# Sync-EntraUserState
# 
# Version: 1.0
# 
# Author: Marco Wohler
# 
# Desc: Retrives all deactivated users out from Entra ID Audit Log and matches them up against local AD users. If a user is deactivated in Entra ID
# but still active in local AD, the script deactivates that user in the local AD.
# 
# Intall Microsoft Graph PowerShell Module first:
#     https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0
# 
# Generate Config:
# To obtain a config file you have to create a new text file which contains al relevant data (TenantId, ClientId and encrypted ClientSecret).
# Like:
# 
# TenantId = bcba188d-7962-4c4f-aff8-bc0fab9c1ee1
# ClientId = 1409d0a1-478b-4aa6-b3c4-3b6b220e1557
# ClientSecret = 01000000d08c9ddf0115d1118c7a00c0...
# 
# To generate an encrypted ClientSecret, you can use PowerShell on the very system and with the same user account that will run the script:
# $secureClientSecret = Read-Host -Prompt "Please enter the Client Secret, generated in the corresponding Enterprise App" -AsSecureString
# $encryptedClientSecretString = ConvertFrom-SecureString $secureClientSecret
# $encryptedClientSecretString
# 
# 
# More info about this script and its setup: TBD
# 
#
#######

##### Vars:
[String]$configFilePath = "C:\ProgramData\SyncEntraUserState\config.txt"    # Config file with TenantId, ClientId and encrypted ClientSecret
[Int]$offsetMinutes = 10                                                    # Minutes to subtract from current time to set the start of the query period
[String]$searchBaseDn = "OU=global,DC=kmuitspice,DC=COM"                    # Distinguished Name of the AD OU, which is the base to search accounts in local AD
[String]$logPath = "C:\temp\SyncEntraUserState.log"                         # Log file path and name of the log file


#### Set TLS1.2 for Web Connections
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


##### Read Config and set up log
try{
    if(Test-Path $configFilePath){
        $config = Get-Content -Path $configFilePath -TotalCount 3
        $config | ForEach-Object {
            $var = $_.Split('=')
            Set-Variable -Name $var[0].Trim() -Value $var[1].Trim()
        }
    } else {
        Write-Error -Message "Cannot find config file at $configFilePath" -Category ObjectNotFound
    }
} catch {
    Write-Error -Message "Something went wrong during reading config: $_"
    Exit
}

try {
    $logDirectory = Split-Path $logPath
    if(-not (Test-Path $logDirectory)){
        New-Item -ItemType Directory -Path $logDirectory
    }
}
catch {
    Write-Error -Message "Can not find log path '$logDirectory' nor create the path."
}


##### Connect to Graph API
try{
    $cred = New-Object System.Management.Automation.PSCredential ($ClientId,(ConvertTo-SecureString $ClientSecret))
    Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $cred -NoWelcome
} catch {
    Write-Error -Message "Something went wrong during connecting to Microsoft Graph: $_"
    Exit
}


##### Get deactivated Entra ID users from audit log & Users from AD
try{
    $timeSpan = (Get-Date).ToUniversalTime().AddMinutes(-$offsetMinutes).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $syncOffset = (Get-Date).AddMinutes(-$offsetMinutes)
    $logEntries= Get-MgAuditLogDirectoryAudit -Filter "ActivityDisplayName eq 'Update user' and Result eq 'success' and ActivityDateTime ge $timeSpan"
    $deactivatedEntraIdUsers = @()
    foreach($logEntry in $logEntries){
        if($logEntry.TargetResources.ModifiedProperties.DisplayName -contains 'AccountEnabled' -and $logEntry.TargetResources.ModifiedProperties.newvalue -contains '[false]' -and $logEntry.TargetResources.ModifiedProperties.oldvalue -contains '[true]'){
            $deactivatedEntraIdUsers += $logEntry.TargetResources.UserPrincipalName
        }
    }
    $localADUsers = Get-ADUser -Filter "Enabled -eq 'True'" -SearchBase $searchBaseDn -Properties whenChanged | Where-Object { $_.whenChanged -lt $syncOffset } | select -Property Name,UserPrincipalName   # The syncOffset must be the same length as the TimeSpan used to read the Entra log, because when a user is manually activated, they should not be deactivated again.
} catch {
    Disconnect-MgGraph
    Write-Error -Message "Something went wrong during fetching users from Graph API or local AD: $_"
    Exit
}


##### Matchup Entra ID users and AD users & deactivate AD users wich are deactivated in Entra ID
try{
    $userPairs = $localADUsers.UserPrincipalName | Where-Object { $deactivatedEntraIdUsers -contains $_ }

    foreach($user in $userPairs){
        $dateTimeOfDDeactivation = Get-Date -Format "yyyyMMdd-HH:mm K"
        Get-ADUser -Filter "UserPrincipalName -eq '$user'" | Set-ADUser -Enabled $false
        "$dateTimeOfDDeactivation`tUser $user deactivated." | Tee-Object -FilePath $logPath -Append
    }
} catch {
    Write-Error "Something went wrong during matching up Entra ID and AD users & deactivating AD users: $_"
}


##### Clean up
Disconnect-MgGraph
