<#
.SYNOPSIS
ScaleWVDSessionHosts.ps1
.NOTES
Written by Ulisses Righi
ulisses@righisoft.com.br
Version 1.1 3/16/2020
#>

#region Paths
$CurrentPath = Split-Path $script:MyInvocation.MyCommand.Path
$JsonPath = "$CurrentPath\Config.Json"
$WVDTenantLog = "$CurrentPath\ScaleWVDSessionHosts.log"
$Global:KeyPath = $CurrentPath

#endregion

#region ScriptConfig
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Imports stored credential handling script
. $CurrentPath\Functions-PSStoredCredentials.ps1

#endregion

# Sets variables on the Script scope. Used when loading variables from JSON
function Set-ScriptVariable ($Name, $Value) {
    Invoke-Expression ("`$Script:" + $Name + " = `"" + $Value + "`"")
}

  function Import-Json ($JsonPath) {
    if (Test-Path $JsonPath) {
        try {
            $Configuration = Get-Content $JsonPath | Out-String | ConvertFrom-Json
        }
        catch {
            Write-Log "Invalid JSON Syntax on file $JsonPath." -Category Error
            exit 1
        }
    }
    else {
        Write-Log "$JsonPath does not exist." -Category Error
        exit 1
    }
    # Loads JSON settings into variables on the Script scope

    $Configuration.WVDScale.Azure | Where-Object { $null -ne $_.Name } | `
        ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }
    $Configuration.WVDScale.WVDScaleSettings | Where-Object { $null -ne $_.Name } | `
        ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }
    $Configuration.WVDScale.Deployment | Where-Object { $null -ne $_.Name } | `
        ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }
    $Configuration.WVDScale.ConnectionMonitor | Where-Object { $null -ne $_.Name } | `
        ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }
    
    $Script:OffPeakDays = $Script:OffPeakDays.Split(",")
}

#region LoggingFunctions
function Write-Log ([string]$Message, 
    [ValidateSet("Information", "Warning", "Error")]
    [string]$Category) {
    $DateTime = Get-Date -f "dd-MM-yyyy HH:mm:ss"
    $LogMessage = "$DateTime [$Category] $Message"
    $LogMessage | Out-File -FilePath $WVDTenantLog -Append
    Write-Host $LogMessage
}

#endregion

#region ScriptFunctions

# Checks whether script is running on peak hours or not.
# Returns $true if in peak hours.

function Assert-PeakHours {
    $CurrentDateTime = Get-Date

    if (($CurrentDateTime.TimeOfDay -ge $BeginPeakTime -and `
        $CurrentDateTime.TimeOfDay -le $EndPeakTime) -and `
        $OffPeakDays -notcontains $CurrentDateTime.DayOfWeek) {
        return $true
    }
    return $false

}
# Ensures that online session hosts are made available if not in maintenance mode
# and vice-versa.
function Assert-SessionHostStatus ($SessionHosts) {
    foreach ($SessionHost in $SessionHosts) {
        $AzResource = Get-AzResource -Name $SessionHost.SessionHostName.Split(".")[0]
        $Tags = $AzResource.Tags

        # Checks if a session host should stop waiting for new connections after the 
        # time limit has elapsed.
        if ($Tags.UserConnectionRequested -eq "true" -and $null -ne $Tags.UserConnectionRequestDate) {
            $ConnectionRequestDateTime = Get-Date $Tags.UserConnectionRequestDate
            if ($ConnectionRequestDateTime.AddMinutes($ConnectionRequestTimeLimit) -lt (Get-Date))
            {
                Write-Log -Message "Connection request time limit for $($SessionHost.SessionHostName) has elapsed." -Category Warning
                $Tags.UserConnectionRequested = "false"
                $Tags.UserConnectionRequestDate = ""
                $AzResource | Set-AzResource -Tag $Tags -Force
            }
            else {
                Write-Log "$($SessionHost.SessionHostName) is is waiting mode." -Category Information
            }
        }

        if ($Tags.$MaintenanceTagName -eq "true" -or
            $SessionHost.Status -eq "NoHeartbeat") {
                Write-Log -Message `
                "Host $($SessionHost.SessionHostName) is offline or in maintenance mode. Setting it to not allow new sessions." -Category Warning
                Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostPoolName `
                -SessionHostName $SessionHost.SessionHostName -AllowNewSession $false | Out-Null
        }
        else {
            Write-Log -Message `
                "Host $($SessionHost.SessionHostName) is available. Setting it to allow new sessions." -Category Information
            Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostPoolName `
            -SessionHostName $SessionHost.SessionHostName -AllowNewSession $true | Out-Null
        }
    }
}

# Gets the total number of cores running, which is used
# for calculating the number of sessions per host.
function Measure-AvailableCores ($SessionHosts) {
    $TotalRunningCores = 0
    $TotalAvailableCores = 0
    $AvailableSessionHosts = $SessionHosts | Where-Object `
        { $_.Status -eq "Available" }
    foreach ($SessionHost in $AvailableSessionHosts) {
        # Finds the Azure VMs and counts the number of cores
        $TotalRunningCores += (Get-SessionHostVMSizeInfo $SessionHost).NumberOfCores
        if ($SessionHost.AllowNewSession -and
            (Get-SessionHostVMTags $SessionHost).$MaintenanceTagName -ne "true") {
            $TotalAvailableCores += (Get-SessionHostVMSizeInfo $SessionHost).NumberOfCores
        }
    }
    Write-Log -Message "Found $TotalRunningCores running cores." -Category Information
    Write-Log -Message "Found $TotalAvailableCores available cores." -Category Information
    return $TotalAvailableCores
}

# Gets the VM size information from Azure
function Get-SessionHostVMSizeInfo ($SessionHost) {
    $VMName = $SessionHost.SessionHostName.Split(".")[0]
    $VMInfo = Get-AzVM -Status | Where-Object { $_.Name -eq $VMName }
    $RoleSize = Get-AzVMSize -Location $VMInfo.Location | `
        Where-Object { $_.Name -eq $VMInfo.HardwareProfile.VmSize }
    return $RoleSize
}

# Gets the VM tags from Azure
function Get-SessionHostVMTags ($SessionHost) {
    $VMName = $SessionHost.SessionHostName.Split(".")[0]
    $VMInfo = Get-AzResource -Name $VMName
    return $VMInfo.Tags
}

function Start-SessionHost ($SessionHost) {
    $VMName = $SessionHost.SessionHostName.Split(".")[0]
    Write-Log -Message "Starting session host $VMName." -Category Information
    try {
        # Asserts that the VM is running before making the session host available
        $IsVMRunning = $false
        while (!$IsVMRunning)
        {
            $VMInfo = Get-AzVM -Status | Where-Object { $_.Name -eq $VMName }
            if ($VmInfo.PowerState -eq "VM running" -and $VmInfo.ProvisioningState -eq "Succeeded"){
                $IsVMRunning = $true
            }
            elseif ($VMInfo.PowerState -eq "Failed")
            {
                throw "Azure VM is in a failed state."
            }
            else {
                Get-AzVM | Where-Object { $_.Name -eq $VMName } | Start-AzVM
                Start-Sleep -Seconds 10
            }
        }
    }
    catch {
        Write-Log -Message "Error while starting session host.`r`n $($_.Exception.Message)" -Category Error
    }
    try {
        Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostPoolName `
            -SessionHostName $SessionHost.SessionHostName -AllowNewSession $true | Out-Null
    }
    catch {
        Write-Log -Message "Error while setting the session host state.`r`n $($_.Exception.Message)" -Category Error
    }
}

function Stop-SessionHost ($UserSessions, $SessionHost) {
    try {
        Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostPoolName `
            -SessionHostName $SessionHost.SessionHostName -AllowNewSession $false | Out-Null
    }
    catch {
        Write-Log -Message "Error while setting the session host state.`r`n $($_.Exception.Message)" -Category Error
    }
    
    $LocalSessions = $UserSessions | Where-Object { $_.SessionHostName -eq $SessionHost.SessionHostName }

    # Checks if there are running sessions and logs users off.
    # If no local sessions are found, shuts down server.
    # The Start-OffPeakProcedure function is responsible for calling the server
    # with the least amount of sessions, repeated on the while loop.
    # This means that if an user session takes some time to be logged off, or is
    # stuck, that function will try again until the server is shut down.
    # This prevents user sessions from being stuck on the RDS Broker.
    if ($null -ne $LocalSessions) {
        $LocalSessions | Send-RdsUserSessionMessage -MessageTitle $LogOffMessageTitle `
            -MessageBody $LogOffMessageBody | Out-Null
        foreach ($LocalSession in $LocalSessions) {
            Write-Log -Message "Logging $($LocalSession.UserPrincipalName) off and sleeping for $LimitSecondsToForceLogOffUser seconds." -Category Information
        }
        
        # Waits before forcing a session logoff
        Start-Sleep -Seconds $LimitSecondsToForceLogOffUser
        $LocalSessions | Invoke-RdsUserSessionLogoff -NoUserPrompt | Out-Null
    }
    else {
        try {
            # Stops the Azure VM
            $VMName = $SessionHost.SessionHostName.Split(".")[0]
            Write-Log -Message "Trying to shut $VMName down." -Category Information
            Get-AzVM  | Where-Object { $_.Name -eq $VMName } | Stop-AzVM -Force | Out-Null
        }
        catch {
            Write-Log -Message "Error while shutting $VMName down. $($_.Exception.Message)" -Category Error
        }
    }
}

# Off-peak procedure: if the number of active session hosts is above the minimum
# number of hosts, shuts down session hosts with the least amount of sessions,
# warning users before logging them off.
function Start-OffPeakProcedure ($HostPoolInfo) {
    # Sets host pool to depth first mode
    Set-RdsHostPool -TenantName $HostPoolInfo.TenantName -Name $HostPoolInfo.HostPoolName `
        -DepthFirstLoadBalancer:$true -MaxSessionLimit 99999 | Out-Null
    
    # Checks available session hosts, including those that do not allow new sessions,
    # except session hosts in maintenance mode and session hosts waiting for a user
    # connection (from the MonitorUserconnections.ps1 script)

    $AvailableSessionHosts = Get-RdsSessionHost -TenantName $HostPoolInfo.TenantName `
        -HostPoolName $HostPoolInfo.HostPoolName | Where-Object { $_.Status -eq "Available" -and 
        ((Get-SessionHostVMTags $_).$MaintenanceTagName -ne "true") -and
        ((Get-SessionHostVMTags $_).UserConnectionRequested -ne "true")}

    Write-Log -Message "Number of available hosts: $($AvailableSessionHosts.Count)." -Category Information
    while ($AvailableSessionHosts.Count -gt $MinimumNumberOfRDSH){
        # Lists sessions
        $UserSessions = $HostPoolInfo | Get-RdsUserSession

        # Builds object with server information to order by number of active sessions
        $ServerSessionTable = @()
        foreach ($SessionHost in $AvailableSessionHosts) {
            $ActiveUserSessions = ($UserSessions | Where-Object { `
                $_.SessionHostName -eq $SessionHost.SessionHostName -and $_.SessionState -eq "Active" }).Count
            $DisconnectedUserSessions = ($UserSessions | Where-Object { `
                $_.SessionHostName -eq $SessionHost.SessionHostName -and $_.SessionState -eq "Disconnected" }).Count
            $ServerSessionTable += [PSCustomObject]@{
                SessionHostName = $SessionHost.SessionHostName
                ActiveUserSessions = $ActiveUserSessions
                DisconnectedUserSessions = $DisconnectedUserSessions
            }
        }
        
        # If the minimum number of servers is 0, skips shutting
        # down last session host if there are any sessions
        if ($AvailableSessionHosts.Count -eq 1 `
            -and $MinimumNumberOfRDSH -eq "0" `
            -and $UserSessions.Count -gt 0) {
                Write-Log -Message "Skipping last host as there are still connected sessions." -Category Warning
            break
        }

        # Finds the best candidate (least amount of active, then least amount of 
        # disconnected users) and starts the log off and shut down process
        $BestCandidate = $ServerSessionTable | Sort-Object DisconnectedUserSessions | `
            Sort-Object ActiveUserSessions | Select-Object -First 1

        # Preemptively sets servers that are going to be shut down to not accept new sessions
        $Candidates = $ServerSessionTable | Sort-Object DisconnectedUserSessions | `
            Sort-Object ActiveUserSessions | Select-Object -First ($AvailableSessionHosts.Count - $MinimumNumberOfRDSH)
    
        foreach ($Candidate in $Candidates)
        {
            Set-RdsSessionHost -TenantName $HostPoolInfo.TenantName -HostPoolName $HostPoolInfo.HostPoolName `
                -Name $Candidate.SessionHostName -AllowNewSession $false
        }

        Stop-SessionHost $UserSessions $BestCandidate

        # Waits for 30 seconds before reading session host status again,
        # to allow the service to update the heartbeat
        Start-Sleep -Seconds 30

        # Updates number of running hosts
        $AvailableSessionHosts = Get-RdsSessionHost -TenantName $HostPoolInfo.TenantName `
            -HostPoolName $HostPoolInfo.HostPoolName | Where-Object { $_.Status -eq "Available" -and 
            ((Get-SessionHostVMTags $_).$MaintenanceTagName -ne "true") -and
            ((Get-SessionHostVMTags $_).UserConnectionRequested -ne "true")}
    }
    
    $Message = "No more hosts to shut down. Hosts available: $($AvailableSessionHosts.Count). " + `
    "Minimum number of hosts: $MinimumNumberOfRDSH."
    Write-Log -Message $Message -Category Information

    $NumberOfSessions = ($AvailableSessionHosts.Sessions | Measure-Object -Sum).Sum
    $SessionLimit = (Measure-AvailableCores $AvailableSessionHosts) * $SessionThresholdPerCPU

    if ($NumberOfSessions -gt $SessionLimit)
    {
        $Message = "The number of sessions on the remaining hosts is higher " + `
        "than the threshold for peak hours. Consider increasing the number of minimum " + `
        "hosts during off-peak hours."
        Write-Log -Message $Message -Category Warning
    }
}

# Compares the number of user sessions to the number of cores, and
# starts session hosts as needed. Sets the host pool to BreadthFirst
# to better distribute resources. If no session hosts are running,
# starts a session host.
function Start-PeakProcedure ($HostPoolInfo) {

    $SessionHosts = Get-RdsSessionHost -TenantName $HostPoolInfo.TenantName `
        -HostPoolName $HostPoolInfo.HostpoolName | `
        Where-Object { (Get-SessionHostVMTags $_).$MaintenanceTagName -ne "true" }
    # Checks current number of sessions and compares it to the threshold
    $NumberOfSessions = ($SessionHosts.Sessions | Measure-Object -Sum).Sum
    $AvailableCores = Measure-AvailableCores $SessionHosts
    $SessionLimit = $AvailableCores * $SessionThresholdPerCPU

    # Sets host pool to breadth first mode
    Set-RdsHostPool -TenantName $HostPoolInfo.TenantName -Name $HostPoolInfo.HostPoolName `
        -BreadthFirstLoadBalancer -MaxSessionLimit $MaximumNumberOfSessions | Out-Null

    Write-Log -Message "Found $NumberOfSessions open sessions." -Category Information

    while (($NumberOfSessions -gt $SessionLimit) -or ($AvailableCores -eq 0))
    {
        # Finds offline session hosts and starts them
        $SessionHost = $SessionHosts | Where-Object { $_.Status -eq "NoHeartbeat" -and 
            (Get-SessionHostVMTags $_).$MaintenanceTagName -ne "true" } | Select-Object -First 1
        if ($null -ne $SessionHost) {
            Start-SessionHost $SessionHost
        }
        else {
            Write-Log "Session threshold is above limit, but there are no hosts to start." Warning
            break
        }

        $SessionHosts = Get-RdsSessionHost -TenantName $HostPoolInfo.TenantName `
            -HostPoolName $HostPoolInfo.HostpoolName | `
            Where-Object { (Get-SessionHostVMTags $_).$MaintenanceTagName -ne "true" }
        $AvailableCores = Measure-AvailableCores $SessionHosts
        $SessionLimit = $AvailableCores * $SessionThresholdPerCPU
    }
 }

 #endregion

 #region Main
function Main {

    Write-Log -Message "Starting WVD session host scaling script." -Category Information

    Import-Json $JsonPath

    # AADApplicationId is loaded from JSON
    $AppCreds = Get-StoredCredential -UserName $AADApplicationId
    $RDSCreds = Get-StoredCredential -UserName $Username

    try { 
        # Connects to Azure
        # AzureSubscriptionId is loaded from JSON
        $AzureAuthentication = Connect-AzAccount -SubscriptionId $CurrentAzureSubscriptionId -Credential $AppCreds
        Write-Log -Message "Connected to Azure subscription $($AzureAuthentication.Context.Subscription.Id)." -Category Information

        # Connects to RDS
        if ($isServicePrincipal -eq "True"){
            Add-RdsAccount -DeploymentUrl $RDBroker -TenantId $AADTenantId -Credential $RDSCreds -ServicePrincipal | Out-Null
            Write-Log -Message "Connected to RDS Account $AADTenantId using service principal." -Category Information
        }
        else {
            Add-RdsAccount -DeploymentUrl $RDBroker -Credential $Credential | Out-Null
            Write-Log -Message "Connected to RDS Account $AADTenantId." -Category Information
        }
    }
    catch {
        Write-Log -Message "Authentication failed. `r`n $($_.Exception.Message)" -Category Error
        exit 1
    }

    try {
        Set-RdsContext -TenantGroupName $TenantGroupName | Out-Null
    }
    catch {
        Write-Log -Message "Error setting the RDS context. `r`n $($_.Exception.Message)" -Category Error
        exit 1
    }

    $HostpoolInfo = Get-RdsHostPool -TenantName $TenantName -Name $HostpoolName
    if ($null -eq $HostpoolInfo) {
        Write-Log -Message "Host pool '$HostpoolName' does not exist on '$TenantName'." -Category Information
        exit 1
    }

    $AllSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName
    if ($null -eq $AllSessionHosts) {
        Write-Log -Message "No session hosts found on '$HostpoolName'." -Category Information
        exit 1
    }
    
    Assert-SessionHostStatus $AllSessionHosts

    if (Assert-PeakHours) {
        Write-Log -Message "Host pool is in peak hours. Starting peak procedure." -Category Information
        Start-PeakProcedure $HostPoolInfo
        Write-Log -Message "Completed peak procedure." -Category Information
    }
    else {
        Write-Log -Message "Host pool is in off-peak hours. Starting off-peak procedure." -Category Information
        Start-OffPeakProcedure $HostPoolInfo
        Write-Log -Message "Completed off-peak procedure." -Category Information
    }
}

$WVDModule = Get-InstalledModule -Name "Microsoft.RDInfra.RDPowershell" -ErrorAction SilentlyContinue
if (!$WVDModule) {
  Write-Log "WVD module not found. Please install the module by running Install-Module Microsoft.RDInfra.RDPowershell -AllowClobber'" -Category Error
}
$AzModule = Get-InstalledModule -Name "Az" -ErrorAction SilentlyContinue
if (!$AzModule) {
  Write-Log "Azure module not found. Please install the module by running Install-Module Az -AllowClobber'" -Category Error
}

if ($AzModule -and $WVDModule) {
    Import-Module "Microsoft.RDInfra.RDPowershell"
    Import-Module "Az"
    Main
}


#endregion