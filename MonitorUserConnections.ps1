<#
.SYNOPSIS
MonitorUserConnections.ps1
.NOTES
Written by Ulisses Righi
ulisses@righisoft.com.br
Version 1.1 3/16/2020
#>

$CurrentPath = Split-Path $script:MyInvocation.MyCommand.Path
$JsonPath = "$CurrentPath\Config.Json"
$WVDTenantLog = "$CurrentPath\MonitorUserConnections.log"
$Global:KeyPath = $CurrentPath

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Imports stored credential handling script
. $CurrentPath\Functions-PSStoredCredentials.ps1

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

    $OffPeakDays = $OffPeakDays.Split(',')
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
# Gets the total number of cores running, which is used
# for calculating the number of sessions per host.

# Gets the VM tags from Azure
function Get-SessionHostVMTags ($SessionHost) {
    $VMName = $SessionHost.SessionHostName.Split(".")[0]
    $VMInfo = Get-AzResource -Name $VMName
    return $VMInfo.Tags
}

# Gets the VM size information from Azure
function Get-SessionHostVMSizeInfo ($SessionHost) {
    $VMName = $SessionHost.SessionHostName.Split(".")[0]
    $VMInfo = Get-AzVM -Status | Where-Object { $_.Name -eq $VMName }
    $RoleSize = Get-AzVMSize -Location $VMInfo.Location | `
        Where-Object { $_.Name -eq $VMInfo.HardwareProfile.VmSize }
    return $RoleSize
}
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

function Start-SessionHost ($SessionHost) {
    $VMName = $SessionHost.SessionHostName.Split(".")[0]
    Write-Log -Message "Starting session host $VMName." -Category Information
    try {
        Get-AzVM | Where-Object { $_.Name -eq $VMName } | Start-AzVM | Out-Null

        # Sets current date in universal time to the UserConnectionRequestDate.
        # This is used by the ScaleWVDSessionHosts.ps1 script to know if a session
        # host should be kept online to wait for user connections for up to a period
        # of time. The Assert-SessionHostStatus function on that script also modifies
        # this tag.
        $Tags = Get-SessionHostVMTags $SessionHost
        $Tags.UserConnectionRequested = "true"
        $Tags.UserConnectionRequestDate = (Get-Date).ToUniversalTime().ToString('u')
        Get-AzResource -Name $VMName | Set-AzResource -Tag $Tags -Force

        # Asserts that the VM is running before making the session host available
        $IsVMRunning = $false
        while (!$IsVMRunning)
        {
            $VMInfo = Get-AzVM -Status | Where-Object { $_.Name -eq $VMName }
            if ($VmInfo.PowerState -eq "VM running" -and $VmInfo.ProvisioningState -eq "Succeeded"){
                $IsVMRunning = $true
            }
            else {
                Start-Sleep -Seconds 10
            }
        }
    }
    catch {
        Write-Log -Message "Error while starting session host.`r`n $($_.Exception.Message)" -Category Error
    }
    try {
        # Waits before trying to read the status
        Start-Sleep -Seconds 90
        # Sets the session host to allow new sessions
        $SessionHostStatus = (Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostPoolName `
            -SessionHostName $SessionHost.SessionHostName).Status
        if ($SessionHostStatus -eq "Active") {
            Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostPoolName `
                -SessionHostName $SessionHost.SessionHostName -AllowNewSession $true | Out-Null
        }
        else {
            throw "Session host has no heartbeat."
        }
    }
    catch {
        Write-Log -Message "Error while setting the session host state.`r`n $($_.Exception.Message)" -Category Error
    }
}
function Main {

    Import-Json $JsonPath

    # AADApplicationId is loaded from JSON
    $AppCreds = Get-StoredCredential -UserName $AADApplicationId
    $RDSCreds = Get-StoredCredential -UserName $Username
    $EmailCreds = Get-StoredCredential -UserName $EmailAddress

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

    $AllSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName | `
        Where-Object { (Get-SessionHostVMTags $_).$MaintenanceTagName -ne "true" }
    if ($null -eq $AllSessionHosts) {
        Write-Log -Message "No session hosts available on '$HostpoolName'." -Category Warning
        exit 1
    }
    $StartDate = (Get-Date).AddMinutes(-6)

    $ConnectionFailures = Get-RdsDiagnosticActivities -TenantName $tenantName -StartTime $StartDate -ActivityType Connection -Outcome Failure
    if ($null -ne $ConnectionFailures) {
        Write-Log -Message "Found failed connection attempts in the last 5 minutes." -Category Information
        foreach ($ConnectionFailure in $ConnectionFailures) {
            Write-Log -Message "User: $($ConnectionFailure.UserName) Date: $($ConnectionFailure.StartTime)" -Category Information
        }
        $AvailableCores = Measure-AvailableCores $AllSessionHosts
        if ($AvailableCores -eq 0)
        {
            $UniqueUsers = $ConnectionFailures.UserName | Select-Object -Unique
            foreach ($User in $UniqueUsers) {
                try {
                    Send-MailMessage -From $emailAddress -To $User -SmtpServer $SmtpServer -Port $SmtpServerPort -UseSsl -Subject $emailSubjectAcknowledged -Body $emailBodyAcknowledged -Credential $EmailCreds
                }
                catch {
                    Write-Log -Message "Error sending e-mail to $User. `r`n $($_.Exception.Message)" -Category Error
                }
            }
            $SessionHost = $AllSessionHosts | Where-Object { $_.Status -eq "NoHeartbeat" } | Select-Object -First 1
            if ($null -ne $SessionHost) {
                Start-SessionHost $SessionHost
                foreach ($User in $UniqueUsers)
                {
                    try {
                    Send-MailMessage -From $emailAddress -To $User -SmtpServer $SmtpServer -Port 587 -UseSsl -Subject $emailSubjectAvailable -Body $emailBodyAvailable -Credential $EmailCreds
                    }
                    catch {
                        Write-Log -Message "Error sending e-mail to $User. `r`n $($_.Exception.Message)" -Category Error
                    }
                }
            }
            else {
                Write-Log -Message "No session hosts are available to be started. Please check servers for maintenance mode." -Category Warning
                try {
                    Send-MailMessage -From $emailAddress -To $User -SmtpServer $SmtpServer -Port 587 -UseSsl -Subject $emailSubjectErrors -Body $emailBodyErrors -Credential $EmailCreds
                    }
                    catch {
                        Write-Log -Message "Error sending e-mail to $User. `r`n $($_.Exception.Message)" -Category Error
                    }
            }
            
        }
    }
    else {
        Write-Log "No connection attempts found in the last 5 minutes." -Category Information
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

if ($AzModule -and $WVDModule) {
    Import-Module "Microsoft.RDInfra.RDPowershell"
    Import-Module "Az"
    Main
}

#endregion