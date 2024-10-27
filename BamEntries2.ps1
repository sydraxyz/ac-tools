Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public class WinAPI
{
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);
}
"@

function Get-DosDevice {
    param (
        [string]$DeviceName
    )
    $Buffer_Size = 1024
    $Buffer = New-Object Text.StringBuilder $Buffer_Size
    [uint32]$result = [WinAPI]::QueryDosDevice($DeviceName, $Buffer, $Buffer_Size)
    
    if ($Result -eq 0) {
        return $Null
    }
    return $Buffer.ToString()
}

function Get-DriveLetter {
    param (
        [string]$Dos_Device_Path,
        [hashtable]$Dos_Devices
    )
    foreach ($Drive in $Dos_Devices.Keys) {
        if ($Dos_Device_Path -eq $Dos_Devices[$Drive]) {
            return $Drive
        }
    }
    return $Null
}

$Dos_Devices = @{}
$Drives = Get-WmiObject -Class Win32_LogicalDisk | Select-Object -ExpandProperty DeviceID
foreach ($Drive in $Drives) {
    $Dos_Devices[$Drive] = Get-DosDevice -DeviceName $Drive
}

function Get-Signature {
    [CmdletBinding()]
    param (
        [string[]]$FilePath
    )
    $Existence = Test-Path -PathType "Leaf" -Path "$FilePath"
    $Authenticode = Get-AuthenticodeSignature -FilePath "$FilePath" -ErrorAction SilentlyContinue
    $Status = "Invalid Signature (UnknownError)"
    
    if ($Existence) {
        if ($($Authenticode.Status) -eq "Valid") {
            $Status = "Valid Signature"
        } elseif ($($Authenticode.Status) -eq "NotSigned") {
            $Status = "Invalid Signature (NotSigned)"
        } elseif ($($Authenticode.Status) -eq "HashMismatch") {
            $Status = "Malicious Signature (HashMismatch)"
        } elseif ($($Authenticode.Status) -eq "NotTrusted") {
            $Status = "Malicious Signature (NotTrusted)"
        } elseif ($($Authenticode.Status) -eq "UnknownError") {
            $Status = "Invalid Signature (UnknownError)"
        }
    } else {
        $Status = "File Was Not Found"
    }
    
    $Signature = [PSCustomObject]@{
        "Status" = $Status
        "Subject" = $($Authenticode.SignerCertificate.Subject)
        "IsOSFile" = $($Authenticode.IsOSBinary)
    }
    return $Signature
}

Clear-Host
$Stopwatch = [Diagnostics.Stopwatch]::StartNew()


if (!(Get-PSDrive -Name HKLM -PSProvider Registry)) {
    try {
        New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE
    } catch {
        Write-Warning "Error Mounting HKEY_LOCAL_MACHINE"
    }
}

Write-Host "";
Write-Host "";
Write-Host -ForegroundColor Red "         _ _                       _                  __         _   _      _                _   ";
Write-Host -ForegroundColor Red "        | (_)                     | |                / /        | | (_)    | |              | |  ";
Write-Host -ForegroundColor Red "      __| |_ ___  ___ ___  _ __ __| |  __ _  __ _   / /_ _ _ __ | |_ _  ___| |__   ___  __ _| |_ ";
Write-Host -ForegroundColor Red "     / _` | / __|/ __/ _ \| '__/ _` | / _` |/ _` | / / _` | '_ \| __| |/ __| '_ \ / _ \/ _` | __|";
Write-Host -ForegroundColor Red "    | (_| | \__ \ (_| (_) | | | (_| || (_| | (_| |/ / (_| | | | | |_| | (__| | | |  __/ (_| | |_ ";
Write-Host -ForegroundColor Red "     \__,_|_|___/\___\___/|_|  \__,_(_)__, |\__, /_/ \__,_|_| |_|\__|_|\___|_| |_|\___|\__,_|\__|";
Write-Host -ForegroundColor Red "                                       __/ | __/ |                                               ";
Write-Host -ForegroundColor Red "                                      |___/ |___/                                                ";
Write-Host "";
Write-Host -ForegroundColor Red "                         BY DANTE KİOUTSOUK";
Write-Host "";

$BAM_Versions = ("bam", "bam\State")
try {
    $Users = @()
    foreach ($BAM_Version in $BAM_Versions) {
        $Users += Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($BAM_Version)\UserSettings\" | Select-Object -ExpandProperty PSChildName
    }
} catch {
    Write-Warning "Error Parsing BAM Key. Likely Unsupported Windows Version | discord.gg/anticheat By Dante"
    break
}

$Registry_Paths = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\","HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\")

$User_Time = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").TimeZoneKeyName
$User_Bias = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").ActiveTimeBias
$User_Day = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").DaylightBias

$BAM = foreach ($SID in $Users) {
    foreach ($Registry_Path in $Registry_Paths) {
        Write-Progress -Id 1 -Activity "$($Registry_Path)"
        $BAM_Items = Get-Item -Path "$($Registry_Path)UserSettings\$SID" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
        Write-Progress -Id 2 -Activity "Collecting Security ID (SID) entries | discord.gg/anticheat By Dante" -Status "($($Users.Count)) SID: $($SID)" -ParentId 1 
        
        try {
            $SID_Object = New-Object System.Security.Principal.SecurityIdentifier($SID)
            $User = $SID_Object.Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            $User = ""
        }

        $i = 0
        foreach ($Item in $BAM_Items) {
            $i++
            $Key = Get-ItemProperty -Path "$($Registry_Path)UserSettings\$SID" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Item
            Write-Progress -Id 3 -Activity "Collecting BAM entries for SID: $($SID)" -Status "(Entry $i of $($BAM_Items.Count))" -ParentId 1 

            if ($Key.Length -eq 24) {
                $Hex = [System.BitConverter]::ToString($Key[7..0]) -replace "-", ""
                $Time_Local = Get-Date ([DateTime]::FromFileTime([Convert]::ToInt64($Hex, 16))) -Format "yyyy-MM-dd HH:mm:ss"
                $Time_UTC = Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))) -Format "yyyy-MM-dd HH:mm:ss"
                $Bias = -([Convert]::ToInt32([Convert]::ToString($User_Bias, 2), 2))
                $Day = -([Convert]::ToInt32([Convert]::ToString($User_Day, 2), 2))
                $Bias_Denomination = $Bias / 60
                $Day_Denomination = $Day / 60
                $Time_User = (Get-Date ([DateTime]::FromFileTimeUTC([Convert]::ToInt64($Hex, 16))).AddMinutes($Bias) -Format "yyyy-MM-dd HH:mm:ss tt")
                $Path = if ($Item -match "\\Device\\HarddiskVolume\d+") {
                    $Matched = $Matches[0]
                    $Drive_Letter = Get-DriveLetter -Dos_Device_Path "$Matched" -Dos_Devices $Dos_Devices -ErrorAction SilentlyContinue
                    $Item.Replace("$Matched","$Drive_Letter")
                } else {
                    $Item
                }
                $Signature = If ($Item -match "\\Device\\HarddiskVolume\d+") {
                    Get-Signature -Filepath "$Path" -ErrorAction SilentlyContinue
                }
                Else {
                    $Null
                }

                [PSCustomObject]@{
                    'Examiner Time' = $Time_Local
                    'Last Execution Time (UTC)' = $Time_UTC
                    'Last Execution User Time' = $Time_User
                    'Path' = $Path
                    "Signature Status" = $($Signature.Status)
                    "OS File" = $($Signature.IsOSFile)
                    "Signature Subject" = $($Signature.Subject)
                    'User' = $User
                    "Registry Path" = ($Registry_Path + $SID)
                }
            }
        }
    }
}
        Write-Host -ForegroundColor Red "                         BY DANTE KİOUTSOUK";

$BAM = $BAM | Sort-Object -Property "Last Execution Time (UTC)" -Descending
$BAM | Out-GridView -PassThru -Title "BAM Key Entries $($BAM.Count) - User TimeZone: ($User_Time) -> ActiveBias: ($Bias) - DayLightTime: ($Day)"

$Stopwatch.Stop()
$Time = $Stopwatch.Elapsed.TotalMinutes
Write-Host "Elapsed Time $Time Minutes" -ForegroundColor "Yellow"