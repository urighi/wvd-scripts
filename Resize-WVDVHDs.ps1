<#
.SYNOPSIS
Resize-WVDVHD.ps1 - Resizes FSLogix container virtual hard disks.
.PARAMETER SizeBytes
The size, in bytes, to which VHDs will be resized to. Defaults to 50GB.
.PARAMETER VHDFilesPath
The path holding the FSLogix container VHDs.
.NOTES
Make sure you have proper backups before starting the resize operation.
Users must be logged off to allow for drives to be mounted.

Ulisses Righi
ulisses@ulisoft.com.br
#>


[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$SizeBytes = 50GB,
    [Parameter(Mandatory=$false)]
    [string]$VHDFilesPath = "E:\FSLogixContainers"
)
$ErrorActionPreference = "Stop"

Get-ChildItem $VHDFilesPath -Include "*.vhdx" -Recurse

foreach ($VHDFile in $VHDFiles)
{
    try
    {
        $VHD = Get-VHD $VHDFile.FullName
        Write-Host "VHD: $($VHD.Path)" -ForegroundColor Yellow
        Write-Host "VHD size:                  $(($VHD.Size)/1GB)GB"
        $VHD | Resize-VHD -SizeBytes $SizeBytes
        $VHD = Get-VHD $VHDFile.FullName
        Write-Host "VHD new size:              $(($VHD.Size)/1GB)GB"
        $VHD | Mount-VHD
        Write-Host "VHD mounted."
        $Disk = Get-Disk | Where-Object { $_.Location -eq $VHD.Path }
        $Partition = $Disk | Get-Partition
        Write-Host "Partition size:            $(($Partition.Size)/1GB)GB"
        $SizeMax = ($Partition | Get-PartitionSupportedSize).SizeMax
        Write-Host "Partition max size:        $($SizeMax/1GB)GB"
        Write-Host "Resizing partition."
        $Partition | Resize-Partition -Size $SizeMax
        $Partition = $Disk | Get-Partition
        Write-Host "Partition new size:        $(($Partition.Size)/1GB)GB"
    }
    catch
    {
        Write-Host "Error found:"
        Write-Host $_.Exception.Message -ForegroundColor Red
    }
    finally
    {
        $VHD | Dismount-VHD
        Write-Host "VHD dismounted."
    }
}