<#
.SYNOPSIS
newScale.ps1
.NOTES
Written by Ulisses Righi
ulisses@righisoft.com.br
Version 1.0 2/1/2020
#>

#region Paths
$CurrentPath = Split-Path $script:MyInvocation.MyCommand.Path
$JsonPath = "$CurrentPath\Config.Json"
$WVDTenantLog = "$CurrentPath\WVDTenantScale.log"
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
            $Variable = Get-Content $JsonPath | Out-String | ConvertFrom-Json
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
    $Variable = Get-Content $JsonPath | Out-String | ConvertFrom-Json
    $Variable.WVDScale.Azure | ForEach-Object { $_.Variable } | Where-Object { $null -ne $_.Name } | `
        ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }
    $Variable.WVDScale.WVDScaleSettings | ForEach-Object { $_.Variable } | Where-Object { $null -ne $_.Name } | `
        ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }
    $Variable.WVDScale.Deployment | ForEach-Object { $_.Variable } | Where-Object { $null -ne $_.Name } | `
        ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }

    $Script:OffPeakDays = $Script:OffPeakDays.Split(',')
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

# Gets the total number of cores running, which is used
# for calculating the number of sessions per host.
function Measure-RunningCores ($SessionHosts) {
    $TotalRunningCores = 0
    $AvailableSessionHosts = $SessionHosts | Where-Object `
        { $_.Status -eq "Available" -and $_.AllowNewSession -eq "True" }
    foreach ($SessionHost in $AvailableSessionHosts) {
        # Finds the Azure VMs and counts the number of cores
        $TotalRunningCores += (Get-SessionHostVMInfo $SessionHost).NumberOfCores
    }
    Write-Log -Message "Found $TotalRunningCores running cores." -Category Information
    return $TotalRunningCores
}

# Gets the VM size information from Azure
function Get-SessionHostVMInfo ($SessionHost) {
    $VMName = $SessionHost.SessionHostName.Split(".")[0]
    $VMInfo = Get-AzVM -Status | Where-Object { $_.Name -eq $VMName }
    $RoleSize = Get-AzVMSize -Location $VMInfo.Location | `
        Where-Object { $_.Name -eq $VMInfo.HardwareProfile.VmSize }
    return $RoleSize
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
            else {
                Get-AzVM | Where-Object { $_.Name -eq $VMName } | Start-AzVM | Out-Null
                Start-Sleep -Seconds 10
            }
        }
    }
    catch {
        Write-Log -Message "Error while starting session host.`r`n $($_.Exception.Message)" -Category Error
    }
    try {
        # Sets the session host to allow new sessions
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
function Start-OffPeakProcedure ($HostPoolInfo, $SessionHosts) {
    # Sets host pool to depth first mode
    Set-RdsHostPool -TenantName $HostPoolInfo.TenantName -Name $HostPoolInfo.HostPoolName `
        -DepthFirstLoadBalancer:$true -MaxSessionLimit 99999 | Out-Null
    # Checks available session hosts, including those that do not allow new sessions
    $AvailableSessionHosts = $SessionHosts | Where-Object { $_.Status -eq "Available" }

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
        
        # Skips shutting down last session host if there are any sessions
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
            Set-RdsSessionHost -TenantName $HostPoolInfo.TenantName -Name $HostPoolInfo.HostPoolName `
                -Name $Candidate.SessionHostName -AllowNewSession $false
        }

        Stop-SessionHost $UserSessions $BestCandidate

        # Waits for 30 seconds before reading session host status again,
        # to allow the service to update the heartbeat
        Start-Sleep -Seconds 30

        # Updates session hosts information
        $SessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName
        # Updates number of running hosts
        $AvailableSessionHosts = $SessionHosts | Where-Object { $_.Status -eq "Available" }

    }
    
    $Message = "No more hosts to shut down. Hosts available: $($AvailableSessionHosts.Count). " + `
    "Minimum number of hosts: $MinimumNumberOfRDSH."
    Write-Log -Message $Message -Category Information

    $NumberOfSessions = ($SessionHosts.Sessions | Measure-Object -Sum).Sum
    $SessionLimit = (Measure-RunningCores $SessionHosts) * $SessionThresholdPerCPU

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
function Start-PeakProcedure ($HostPoolInfo, $SessionHosts) {
    # Sets host pool to breadth first mode
    Set-RdsHostPool -TenantName $HostPoolInfo.TenantName -Name $HostPoolInfo.HostPoolName `
        -BreadthFirstLoadBalancer | Out-Null
    # Checks current number of sessions and compares it to the threshold
    $NumberOfSessions = ($SessionHosts.Sessions | Measure-Object -Sum).Sum
    $RunningCores = Measure-RunningCores $SessionHosts
    $SessionLimit = $RunningCores * $SessionThresholdPerCPU

    Write-Log -Message "Found $NumberOfSessions open sessions." -Category Information

    while (($NumberOfSessions -gt $SessionLimit) -or ($RunningCores -eq 0))
    {
        # Finds offline session hosts and starts them
        $SessionHost = $SessionHosts | Where-Object { $_.Status -eq "NoHeartbeat" -or $false -eq $_.AllowNewSession } | Select-Object -First 1
        if ($SessionHost) {
            Start-SessionHost $SessionHost
        }
        else {
            Write-Log "Session threshold is above limit, but there are no hosts to start." Warning
            break
        }
        $RunningCores = Measure-RunningCores $SessionHosts
    }
 }

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
    
    if (Assert-PeakHours) {
        Write-Log -Message "Host pool is in peak hours. Starting peak procedure." -Category Information
        Start-PeakProcedure $HostPoolInfo $AllSessionHosts
        Write-Log -Message "Completed peak procedure." -Category Information
    }
    else {
        Write-Log -Message "Host pool is in off-peak hours. Starting off-peak procedure." -Category Information
        Start-OffPeakProcedure $HostPoolInfo $AllSessionHosts
        Write-Log -Message "Completed off-peak procedure." -Category Information
    }
}

#endregion

#region Main
$WVDModule = Get-InstalledModule -Name "Microsoft.RDInfra.RDPowershell" -ErrorAction SilentlyContinue
if (!$WVDModule) {
  Write-Log "WVD module not found. Please install the module by running Install-Module Microsoft.RDInfra.RDPowershell -AllowClobber'"
}
$AzModule = Get-InstalledModule -Name "Az" -ErrorAction SilentlyContinue
if (!$AzModule) {
  Write-Log "Azure module not found. Please install the module by running Install-Module Az -AllowClobber'"
}

if ($AzModule -and $WVDModule)
{
    Import-Module "Microsoft.RDInfra.RDPowershell"
    Import-Module "Az"
    Main
}


#endregion