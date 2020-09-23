<#
.SYNOPSIS
ScaleWVDSessionHosts_SpringUpdate.ps1
.NOTES
Written by Ulisses Righi
ulisses@righisoft.com.br
Version 1.5 8/31/2020
#>

#region Paths
$CurrentPath = Split-Path $script:MyInvocation.MyCommand.Path
$JsonPath = "$CurrentPath\Config_SpringUpdate.Json"
$WVDTenantLogPath = "$CurrentPath\ScaleWVDSessionHosts.log"
$StatsPath = "$CurrentPath\WVDStats.csv"
$Global:KeyPath = $CurrentPath

#endregion

#region ScriptConfig
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Imports the stored credential handling script made by Paul Cunningham
# Downloads latest version if it doesn't exist locally
if (!(Test-Path $CurrentPath\Functions-PSStoredCredentials.ps1)) {
    Invoke-WebRequest "https://raw.githubusercontent.com/cunninghamp/PowerShell-Stored-Credentials/master/Functions-PSStoredCredentials.ps1" `
        -OutFile "$CurrentPath\Functions-PSStoredCredentials.ps1"
}
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
    $LogMessage | Out-File -FilePath $WVDTenantLogPath -Append
    Write-Host $LogMessage
}


function Reset-Log ($Path = $WVDTenantLogPath, $MaxSize = 1MB, $LogsToKeep = 10) {
    $FolderPath = Split-Path $Path
    $CurrentLog = Get-ChildItem -Path $Path
    if ($CurrentLog.Length -gt $MaxSize) {
        $CompressedPath = $Path.TrimEnd(".log") + (Get-Date -Format yyyy-MM-dd) + ".log.zip"
        Compress-Archive -Path $Path -DestinationPath $CompressedPath
        Remove-Item $Path -Force | Out-Null
    }
    $OldLogs = Get-ChildItem -Path $FolderPath -Filter "$($CurrentLog.BaseName)*.log.zip" | Sort-Object CreationTime

    while ($OldLogs.Count -gt $LogsToKeep) {
        Remove-Item $OldLogs[0]
        $OldLogs = Get-ChildItem -Path $FolderPath -Filter "$($CurrentLog.BaseName)*.log.zip" | Sort-Object CreationTime
    }
}
function Write-Stats ([string]$ServerName,
    [string]$Status,
    [string]$AllowNewSession,
    [int]$TotalSessions) {
    $DateTime = Get-Date -f "dd-MM-yyyy HH:mm:ss"
    $ServerStats = [PSCustomObject]@{
        "Time" = $DateTime
        "ServerName" = $ServerName
        "Status" = $Status
        "AllowNewSession" = $AllowNewSession
        "TotalSessions" = $TotalSessions
    }
    $ServerStats | Export-CSV -Path $StatsPath -Append -NoTypeInformation
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
        $AzResource = Get-AzResource -Name $SessionHost.Name.Split('/')[1].Split(".")[0]
        $Tags = $AzResource.Tags

        # Checks if a session host should stop waiting for new connections after the 
        # time limit has elapsed.
        if ($Tags.UserConnectionRequested -eq "true" -and $null -ne $Tags.UserConnectionRequestDate) {
            $ConnectionRequestDateTime = Get-Date $Tags.UserConnectionRequestDate
            if ($ConnectionRequestDateTime.AddMinutes($ConnectionRequestTimeLimit) -lt (Get-Date))
            {
                Write-Log -Message "Connection request time limit for $($SessionHost.Name) has elapsed." -Category Warning
                $Tags.UserConnectionRequested = "false"
                $Tags.UserConnectionRequestDate = ""
                $AzResource | Set-AzResource -Tag $Tags -Force
            }
            else {
                Write-Log "$($SessionHost.Name) is is waiting mode." -Category Information
            }
        }

        if ($Tags.$MaintenanceTagName -eq "true" -or
            $SessionHost.Status -ne "Available") {
                Write-Log -Message `
                "Host $($SessionHost.Name) is offline or in maintenance mode. Setting it to not allow new sessions." -Category Warning
                Update-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName `
                -Name $SessionHost.Name.Split('/')[1] -AllowNewSession:$false | Out-Null
        }
        else {
            Write-Log -Message `
                "Host $($SessionHost.Name) is available. Setting it to allow new sessions." -Category Information
            Update-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName `
                -Name $SessionHost.Name.Split('/')[1] -AllowNewSession:$true | Out-Null
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
    $VMName = $SessionHost.Name.Split("/")[1].Split(".")[0]
    $VMInfo = Get-AzVM -Status | Where-Object { $_.Name -eq $VMName }
    $RoleSize = Get-AzVMSize -Location $VMInfo.Location | `
        Where-Object { $_.Name -eq $VMInfo.HardwareProfile.VmSize }
    return $RoleSize
}

# Gets the VM tags from Azure
function Get-SessionHostVMTags ($SessionHost) {
    $VMName = $SessionHost.Name.Split("/")[1].Split(".")[0]
    $VMInfo = Get-AzResource -Name $VMName
    return $VMInfo.Tags
}

function Start-SessionHost ($SessionHost) {
    $VMName = $SessionHost.Name.Split("/")[1].Split(".")[0]
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
        Update-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName `
            -Name $SessionHost.Name.Split('/')[1] -AllowNewSession:$true | Out-Null
    }
    catch {
        Write-Log -Message "Error while setting the session host state.`r`n $($_.Exception.Message)" -Category Error
    }
}

function Stop-SessionHost ($UserSessions, $SessionHost) {
    try {
        Update-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName `
            -Name $SessionHost.SessionHostName.Split('/')[1] -AllowNewSession:$false | Out-Null
    }
    catch {
        Write-Log -Message "Error while setting the session host state.`r`n $($_.Exception.Message)" -Category Error
    }
    
    $LocalSessions = $UserSessions | Where-Object { $_.Name.Split("/")[1] -eq $SessionHost.SessionHostName.Split("/")[1] }

    # Checks if there are running sessions and logs users off.
    # If no local sessions are found, shuts down server.
    # The Start-OffPeakProcedure function is responsible for calling the server
    # with the least amount of sessions, repeated on the while loop.
    # This means that if an user session takes some time to be logged off, or is
    # stuck, that function will try again until the server is shut down.
    # This prevents user sessions from being stuck on the RDS Broker.
    if ($null -ne $LocalSessions) {
        if ($LimitSecondsToForceLogOffUser -ne 0) {
            foreach ($LocalSession in $LocalSessions) {
                Send-AzWvdUserSessionMessage -MessageTitle $LogOffMessageTitle -MessageBody $LogOffMessageBody `
                    -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName `
                    -SessionHostName $LocalSession.Name.Split("/")[1] -UserSessionId $LocalSession.Id.Split("/")[-1] | Out-Null
                Write-Log -Message "Logging $($LocalSession.UserPrincipalName) off and sleeping for $LimitSecondsToForceLogOffUser seconds." -Category Information
            }
            
            # Waits before forcing a session logoff
            Start-Sleep -Seconds $LimitSecondsToForceLogOffUser

            foreach ($LocalSession in $LocalSessions) {
                Remove-AzWvdUserSession -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolName `
                    -SessionHostName $LocalSession.Name.Split("/")[1] -Id $LocalSession.Id.Split("/")[-1] -Force | Out-Null
            }
        }
        else {
            Write-Log -Message "Sessions were found on $($SessionHost.Name), but the script settings disallow user logoff." -Category Warning
        }
    }
    else {
        try {
            # Stops the Azure VM
            $VMName = $SessionHost.SessionHostName.Split("/")[1].Split(".")[0]
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
    Update-AzWvdHostPool -ResourceGroupName $ResourceGroupName -Name $HostPoolInfo.Name `
        -LoadBalancerType "DepthFirst" -MaxSessionLimit 99999 | Out-Null
    
    # Checks available session hosts, including those that do not allow new sessions,
    # except session hosts in maintenance mode and session hosts waiting for a user
    # connection (from the MonitorUserconnections.ps1 script)

    $AvailableSessionHosts = Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName `
        -HostPoolName $HostPoolInfo.Name | Where-Object { $_.Status -eq "Available" -and 
        ((Get-SessionHostVMTags $_).$MaintenanceTagName -ne "true") -and
        ((Get-SessionHostVMTags $_).UserConnectionRequested -ne "true")}

    # Calculates the number of sessions based on the off-peak threshold
    $NumberOfSessions = ($AvailableSessionHosts.Session | Measure-Object -Sum).Sum
    $SessionLimit = (Measure-AvailableCores $AvailableSessionHosts) * $offPeakSessionThresholdPerCPU

    Write-Log -Message "Found $NumberOfSessions open sessions." -Category Information

    Write-Log -Message "Number of available hosts: $($AvailableSessionHosts.Count)." -Category Information
    while (($AvailableSessionHosts.Count -gt $MinimumNumberOfRDSH) -and ($SessionLimit -gt $NumberOfSessions)){
        # Lists sessions
        $UserSessions = Get-AzWvdUserSession -HostPoolName $HostPoolInfo.Name -ResourceGroupName $ResourceGroupName

        # Builds object with server information to order by number of active sessions
        $ServerSessionTable = @()
        foreach ($SessionHost in $AvailableSessionHosts) {
            $ActiveUserSessions = ($UserSessions | Where-Object { `
                $_.Name.Split("/")[1] -eq $SessionHost.Name.Split("/")[1] -and $_.SessionState -eq "Active" }).Count
            $DisconnectedUserSessions = ($UserSessions | Where-Object { `
                $_.Name.Split("/")[1] -eq $SessionHost.Name.Split("/")[1] -and $_.SessionState -eq "Disconnected" }).Count
            $ServerSessionTable += [PSCustomObject]@{
                SessionHostName = $SessionHost.Name
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
    
        foreach ($Candidate in $Candidates) {
            Update-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostPoolInfo.Name `
                -Name $Candidate.SessionHostName.Split('/')[1] -AllowNewSession:$false
        }

        # If set to not log users off, exits loop if best candidate has sessions
        if ($LimitSecondsToForceLogOffUser -eq 0) {
            $BestCandidateSessions = $UserSessions | Where-Object { $_.Name.Split("/")[1] -eq $BestCandidate.SessionHostName }
            if ($null -ne $BestCandidateSessions) {
                Write-Log -Message "Sessions were found on $($BestCandidate.SessionHostName), but the script settings disallow user logoff." -Category Warning
                break
            }
        }

        Stop-SessionHost $UserSessions $BestCandidate

        # Waits for 60 seconds before reading session host status again,
        # to allow the service to update the heartbeat and user sessions
        Start-Sleep -Seconds 60

        # Updates number of running hosts
        $AvailableSessionHosts = Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName `
            -HostPoolName $HostPoolInfo.Name | Where-Object { $_.Status -eq "Available" -and 
            ((Get-SessionHostVMTags $_).$MaintenanceTagName -ne "true") -and
            ((Get-SessionHostVMTags $_).UserConnectionRequested -ne "true")}

        # Updates the number of sessions based on the off-peak threshold
        $NumberOfSessions = ($AvailableSessionHosts.Session | Measure-Object -Sum).Sum
        $SessionLimit = (Measure-AvailableCores $AvailableSessionHosts) * $offPeakSessionThresholdPerCPU
    }
    
    $Message = "No more hosts to shut down. Hosts available: $($AvailableSessionHosts.Count). " + `
    "Minimum number of hosts: $MinimumNumberOfRDSH."
    Write-Log -Message $Message -Category Information

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

    $SessionHosts = Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName `
        -HostPoolName $HostPoolInfo.Name | `
        Where-Object { (Get-SessionHostVMTags $_).$MaintenanceTagName -ne "true" }
    # Checks current number of sessions and compares it to the threshold
    $NumberOfSessions = ($SessionHosts.Session | Measure-Object -Sum).Sum
    $AvailableCores = Measure-AvailableCores $SessionHosts
    $SessionLimit = $AvailableCores * $SessionThresholdPerCPU

    # Sets host pool to breadth first mode
    Update-AzWvdHostPool -ResourceGroupName $ResourceGroupName -Name $HostPoolInfo.Name `
        -LoadBalancerType "BreadthFirst" -MaxSessionLimit $MaximumNumberOfSessions | Out-Null

    Write-Log -Message "Found $NumberOfSessions open sessions." -Category Information

    while (($NumberOfSessions -gt $SessionLimit) -or ($AvailableCores -eq 0) -or ($AvailableCores -lt $minimumNumberOfCores))
    {
        # Possible values: Available / Disconnected / Shutdown / Unavailable / UpgradeFailed / Upgrading
        # Finds offline session hosts and starts them
        $SessionHost = $SessionHosts | Where-Object { ($_.Status -eq "NoHeartbeat" -or $_.Status -eq "Shutdown" -or $_.Status -eq "Unavailable") -and 
            (Get-SessionHostVMTags $_).$MaintenanceTagName -ne "true" } | Select-Object -First 1
        if ($null -ne $SessionHost) {
            Start-SessionHost $SessionHost
        }
        else {
            Write-Log "Session threshold is above limit, but there are no hosts to start." Warning
            break
        }

        $SessionHosts = Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName `
            -HostPoolName $HostPoolInfo.Name | `
            Where-Object { (Get-SessionHostVMTags $_).$MaintenanceTagName -ne "true" }
        $AvailableCores = Measure-AvailableCores $SessionHosts
        $SessionLimit = $AvailableCores * $SessionThresholdPerCPU
    }
 }

 #endregion

 #region Main
function Main {

    Reset-Log

    Write-Log -Message "Starting WVD session host scaling script." -Category Information

    Import-Json $JsonPath

    # AADApplicationId is loaded from JSON
    try {
        $AppCreds = Get-StoredCredential -UserName $AADApplicationId
    }
    catch {
        Write-Log -Message "Failed to obtain credentials. Check if the user running the script is the same user that created the .cred file, or that the .cred file exists." -Category Error
        exit 1
    }
    

    try { 
        # Connects to Azure
        # AzureSubscriptionId is loaded from JSON
        $AzureAuthentication = Connect-AzAccount -SubscriptionId $CurrentAzureSubscriptionId -Credential $AppCreds
        Write-Log -Message "Connected to Azure subscription $($AzureAuthentication.Context.Subscription.Id)." -Category Information

    }
    catch {
        Write-Log -Message "Authentication failed. `r`n $($_.Exception.Message)" -Category Error
        exit 1
    }

    $HostpoolInfo = Get-AzWvdHostPool -ResourceGroupName $ResourceGroupName -Name $HostpoolName
    if ($null -eq $HostpoolInfo) {
        Write-Log -Message "Host pool '$HostpoolName' does not exist on '$TenantName'." -Category Information
        exit 1
    }

    $AllSessionHosts = Get-AzWvdSessionHost -ResourceGroupName $ResourceGroupName -HostPoolName $HostpoolName
    if ($null -eq $AllSessionHosts) {
        Write-Log -Message "No session hosts found on '$HostpoolName'." -Category Information
        exit 1
    }

    foreach ($SessionHost in $AllSessionHosts) {
        Write-Stats $SessionHost.Name $SessionHost.Status $SessionHost.AllowNewSession $SessionHost.Session
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

$WVDModule = Get-InstalledModule -Name "Az.DesktopVirtualization" -ErrorAction SilentlyContinue
if (!$WVDModule) {
  Write-Log "WVD module not found. Please install or update the Az module by running Update-Module Az'" -Category Error
}
$AzModule = Get-InstalledModule -Name "Az" -ErrorAction SilentlyContinue
if (!$AzModule) {
  Write-Log "Azure module not found. Please install the module by running Install-Module Az -AllowClobber'" -Category Error
}

if ($AzModule -and $WVDModule) {
    Import-Module "Az"
    Main
}

#endregion