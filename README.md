# wvd-scripts
Scripts for managing ~~Windows~~ Azure Virtual Desktop.

## What's new
**New:** Added support for the Spring 2020 Update. The ScaleWVDSessionHosts_SpringUpdate.ps1 and Config_SpringUpdate.json scripts use the Az.DesktopVirtualization module.

## Scaling scripts
### ScaleWVDSessionHosts.ps1
This script will scale the number of active session hosts based on time, day and session threshold. It performs the following functions:
* Ensures that online hosts have the status set to allow new sessions
* Ensures that offline or in maintenance hosts have the status set to not allow new sessions
* Updates the UserConnectionRequested and UserConnectionRequestDate Azure tags based on time (see MonitorUserConnectionAttempts.ps1)
* Logs usage to a CSV file, and rotates log files
* Checks if the host pool is on peak or off-peak hours
  * If the host pool is in peak hours:
    * Sets the host pool to BreadthFirst mode
    * Checks the number of running cores against the minimum, and starts hosts as needed
    * Checks the number of users against a core/user threshold
    * If the number of connected users is above the threshold, starts a new session host
    * If the number is lower, does nothing
  * If the host pool is in off-peak hours:
    * Checks if the number of running servers is above the minimum
    * Checks if the number of sessions is below the off-peak threshold
    * Finds the session host with the least amount of active, then disconnected sessions
    * Sets that session host to not accept new sessions
    * Sends a message to users asking them to log off
    * Waits for all users to be logged off on that session host
    * Shuts down the session host
    * If the minimum of servers is set to 0, shuts down the last server as long as there are no open sessions, and that there is no pending user connection request (see MonitorUserConnectionAttempts.ps1) for a specified amount of time
 
 ### MonitorUserConnectionAttempts.ps1
 ~~** This script is deprecated and kept here for reference only. ** Microsoft has removed RDS diagnostic logs. A new version is in development, supporting the Spring Update and Log Analytics.~~ Guess what, the RDS diagnostic logs were brought back. However, you will be wanting to use the new Start Virtual Machine on Connect feature: https://docs.microsoft.com/en-us/azure/virtual-desktop/start-virtual-machine-connect
 This script performs the following functions:
 * Detects user connection failures when hosts are offline, based on the RDS diagnostic logs
 * Starts a session host and updates the connection request tag in Azure with the current time
 * E-mails the user while the server is being prepared, then again when the server is ready
 
 ### Set-up
 
 #### Script configuration
 Both scripts share the same JSON configuration file. All parameters are documented inside the example Config.json file provided here.
 
 #### Credentials
 Credentials for Azure and RDS are stored by using the Functions-PSStoredCredentials script available here: https://github.com/cunninghamp/PowerShell-Stored-Credentials
 If you are using the Spring Update version, only the Azure credentials are needed.
 
 To store credentials, run:
 ```
 $KeyPath = "."
 . Functions-PSStoredCredentials.ps1
 New-StoredCredential
 ```
 
 Credentials need to be saved under the same context of the user that executes the scheduled task.
 
 #### Task Scheduler
 When running this script from Task Scheduler, make sure that the credentials are configured correctly, and that it runs on a reasonable interval (such as every 15 minutes). No local permissions are needed, but the task must execute as the same user that generated the stored credentials.
 
 ## Maintenance scripts
 ### Resize-WVDVHDs.ps1
 
 This script resizes all VHDs on a folder. Useful when users were provisioned small VHDs due to the FSLogix profile configuration, and then later require more space.
