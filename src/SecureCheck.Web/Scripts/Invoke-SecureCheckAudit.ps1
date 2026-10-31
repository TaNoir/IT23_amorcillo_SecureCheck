<#
.SYNOPSIS
    Read-only security audit script for SecureCheck. Emits one compressed JSON string.

.DESCRIPTION
    Compatible with both Windows PowerShell 5.1 and PowerShell 7 on Windows.
    Includes safe non-admin fallbacks so it runs cleanly on the local laptop without elevation
    as well as elevated over PowerShell Remoting (WinRM).
    Never modifies any computer settings and does not evaluate Pass/Fail.
#>

$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'

$isElevated = $false
try {
    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if ($null -ne $currentIdentity) {
        $currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal($currentIdentity)
        $isElevated = $currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
} catch {
    $isElevated = $false
}

function Get-ShortError {
    param($ErrorRecord)

    $msg = $null
    if ($null -ne $ErrorRecord) {
        if ($null -ne $ErrorRecord.Exception -and -not [string]::IsNullOrWhiteSpace($ErrorRecord.Exception.Message)) {
            $msg = $ErrorRecord.Exception.Message
        } else {
            $msg = $ErrorRecord.ToString()
        }
    }

    if ([string]::IsNullOrWhiteSpace($msg)) {
        return 'Unknown error'
    }

    $clean = ($msg -replace '\s+', ' ').Trim()
    if ($clean.Length -gt 240) {
        return ($clean.Substring(0, 237) + '...')
    }

    return $clean
}

function ConvertTo-BooleanValue {
    param($Value)

    if ($null -eq $Value) {
        return $false
    }
    if ($Value -is [bool]) {
        return $Value
    }

    # Get-NetFirewallProfile returns GpoBoolean enum (False = 0, True = 1, NotConfigured = 2).
    $text = $Value.ToString().Trim()
    if ($text -ieq 'True' -or $text -eq '1') {
        return $true
    }

    return $false
}

# 1. OS & PowerShell runtime metadata
$os = [ordered]@{
    caption   = $null
    version   = $null
    psVersion = $PSVersionTable.PSVersion.ToString()
    psMajor   = [int]$PSVersionTable.PSVersion.Major
}
try {
    $winOs = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop | Select-Object -First 1
    if ($null -ne $winOs) {
        if (-not [string]::IsNullOrWhiteSpace($winOs.Caption)) {
            $os['caption'] = ([string]$winOs.Caption).Trim()
        }
        if (-not [string]::IsNullOrWhiteSpace($winOs.Version)) {
            $os['version'] = ([string]$winOs.Version).Trim()
        }
    }
} catch {
    $os['error'] = Get-ShortError $_
}

# 2. Windows Firewall profiles
$firewall = [ordered]@{
    error    = $null
    profiles = [object[]]@()
}
try {
    $fwProfiles = New-Object System.Collections.Generic.List[object]
    $rawProfiles = @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object -Property Name, Enabled)
    foreach ($profileItem in $rawProfiles) {
        $fwProfiles.Add([ordered]@{
            name    = [string]$profileItem.Name
            enabled = [bool](ConvertTo-BooleanValue $profileItem.Enabled)
        })
    }
    $firewall['profiles'] = [object[]]$fwProfiles.ToArray()
} catch {
    $firewall['error'] = Get-ShortError $_
}

# 3. Windows Updates (Get-HotFix with Microsoft.Update.Session COM fallback)
$updates = [ordered]@{
    error           = $null
    lastInstalledOn = $null
    latestHotFixId  = $null
    hotFixCount     = $null
    source          = $null
}
try {
    $allHotFixes = @()
    $hotFixQuerySucceeded = $false
    try {
        $allHotFixes = @(Get-HotFix -ErrorAction Stop)
        $hotFixQuerySucceeded = $true
    } catch {
        # Fresh unpatched Windows installations can throw when zero hotfixes exist; fall back to update history.
        $allHotFixes = @()
    }

    $datedHotFixes = New-Object System.Collections.Generic.List[object]
    foreach ($hf in $allHotFixes) {
        if ($null -ne $hf.InstalledOn) {
            $parsedHfDate = [datetime]::MinValue
            if ($hf.InstalledOn -is [datetime]) {
                $datedHotFixes.Add($hf)
            } elseif ([datetime]::TryParse([string]$hf.InstalledOn, [ref]$parsedHfDate)) {
                $datedHotFixes.Add($hf)
            }
        }
    }

    if ($datedHotFixes.Count -gt 0) {
        $latestHotFix = $datedHotFixes.ToArray() |
            Where-Object { $null -ne $_.InstalledOn } |
            Sort-Object -Property { [datetime]$_.InstalledOn } -Descending |
            Select-Object -First 1

        $updates['lastInstalledOn'] = ([datetime]$latestHotFix.InstalledOn).ToString('o')
        if (-not [string]::IsNullOrWhiteSpace($latestHotFix.HotFixID)) {
            $updates['latestHotFixId'] = ([string]$latestHotFix.HotFixID).Trim()
        }
        $updates['hotFixCount'] = [int]$allHotFixes.Count
        $updates['source'] = 'Get-HotFix'
    } else {
        if ($hotFixQuerySucceeded) {
            $updates['hotFixCount'] = [int]$allHotFixes.Count
        } else {
            $updates['hotFixCount'] = 0
        }

        $updateSession = New-Object -ComObject 'Microsoft.Update.Session'
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $totalHistoryCount = [int]$updateSearcher.GetTotalHistoryCount()
        if ($totalHistoryCount -gt 0) {
            $latestHistory = $updateSearcher.QueryHistory(0, 1) | Select-Object -First 1
            if ($null -ne $latestHistory -and $null -ne $latestHistory.Date) {
                $historyDate = [datetime]$latestHistory.Date
                if ($historyDate.Year -gt 1980) {
                    $updates['lastInstalledOn'] = $historyDate.ToString('o')
                }
                if (-not [string]::IsNullOrWhiteSpace($latestHistory.Title) -and ($latestHistory.Title -match '(KB\d+)')) {
                    $updates['latestHotFixId'] = [string]$Matches[1]
                }
            }
        }
        $updates['source'] = 'WindowsUpdateHistory'
    }
} catch {
    $updates['error'] = Get-ShortError $_
}

# 4. Antivirus (Windows Defender)
$antivirus = [ordered]@{
    error                     = $null
    antivirusEnabled          = $null
    realTimeProtectionEnabled = $null
    signatureAgeDays          = $null
    signatureLastUpdated      = $null
}
try {
    $mpCommand = Get-Command -Name 'Get-MpComputerStatus' -ErrorAction SilentlyContinue
    if ($null -eq $mpCommand) {
        throw 'Get-MpComputerStatus not available'
    }

    $mpStatus = Get-MpComputerStatus -ErrorAction Stop
    if ($null -eq $mpStatus) {
        throw 'Get-MpComputerStatus returned null'
    }

    if ($null -ne $mpStatus.AntivirusEnabled) {
        $antivirus['antivirusEnabled'] = [bool]$mpStatus.AntivirusEnabled
    }
    if ($null -ne $mpStatus.RealTimeProtectionEnabled) {
        $antivirus['realTimeProtectionEnabled'] = [bool]$mpStatus.RealTimeProtectionEnabled
    }
    if ($null -ne $mpStatus.AntivirusSignatureAge) {
        $rawAge = [int64]$mpStatus.AntivirusSignatureAge
        # Offline Windows installations without initial signature updates report UInt32.MaxValue (4294967295).
        if ($rawAge -ge 0 -and $rawAge -lt [int]::MaxValue) {
            $antivirus['signatureAgeDays'] = [int]$rawAge
        }
    }
    if ($null -ne $mpStatus.AntivirusSignatureLastUpdated) {
        $sigUpdated = [datetime]$mpStatus.AntivirusSignatureLastUpdated
        if ($sigUpdated.Year -gt 1980) {
            $antivirus['signatureLastUpdated'] = $sigUpdated.ToString('o')
        }
    }
} catch {
    $antivirus['error'] = 'Windows Defender status not available (another antivirus may be installed)'
}

# 5. Accounts (Guest by SID *-501, Administrators by SID S-1-5-32-544 + ADSI fallback, Password policy via secedit / net accounts)
$accounts = [ordered]@{
    error          = $null
    guest          = $null
    administrators = $null
    passwordPolicy = $null
}
try {
    # 5a. Built-in Guest account (SID ending in -501)
    $guest = [ordered]@{
        exists  = $null
        enabled = $null
    }
    try {
        $localUserCmd = Get-Command -Name 'Get-LocalUser' -ErrorAction SilentlyContinue
        if ($null -ne $localUserCmd) {
            $guestUser = Get-LocalUser -ErrorAction Stop |
                Where-Object { $null -ne $_.SID -and $_.SID.Value -like '*-501' } |
                Select-Object -First 1

            if ($null -ne $guestUser) {
                $guest['exists'] = $true
                $guest['enabled'] = [bool]$guestUser.Enabled
            } else {
                $guest['exists'] = $false
                $guest['enabled'] = $false
            }
        } else {
            # ADSI fallback if Microsoft.PowerShell.LocalAccounts is unavailable in an embedded PS7 host.
            $adsiHost = [ADSI]("WinNT://{0}" -f $env:COMPUTERNAME)
            $foundGuestAdsi = $false
            foreach ($child in $adsiHost.Children) {
                if ($child.SchemaClassName -ieq 'User' -and $null -ne $child.Properties['objectSid'].Value) {
                    $sidObj = New-Object System.Security.Principal.SecurityIdentifier([byte[]]$child.Properties['objectSid'].Value, 0)
                    if ($sidObj.Value -like '*-501') {
                        $userFlags = [int]$child.Properties['UserFlags'].Value
                        $guest['exists'] = $true
                        # ADS_UF_ACCOUNTDISABLE = 0x2
                        $guest['enabled'] = [bool](($userFlags -band 2) -eq 0)
                        $foundGuestAdsi = $true
                        break
                    }
                }
            }
            if (-not $foundGuestAdsi) {
                $guest['exists'] = $false
                $guest['enabled'] = $false
            }
        }
    } catch {
        $guest['error'] = Get-ShortError $_
    }
    $accounts['guest'] = $guest

    # 5b. Local Administrators group (SID S-1-5-32-544)
    $administrators = [ordered]@{
        count   = $null
        members = [string[]]@()
    }
    try {
        $adminGroupSidString = 'S-1-5-32-544'
        $adminGroupSid = New-Object System.Security.Principal.SecurityIdentifier($adminGroupSidString)
        $translatedAdminGroup = $adminGroupSid.Translate([System.Security.Principal.NTAccount]).Value
        $localAdminGroupName = ($translatedAdminGroup -split '\\')[-1]

        $adminMembers = New-Object System.Collections.Generic.List[string]
        try {
            $groupMembers = @(Get-LocalGroupMember -SID $adminGroupSidString -ErrorAction Stop)
            foreach ($member in $groupMembers) {
                if (-not [string]::IsNullOrWhiteSpace($member.Name)) {
                    $adminMembers.Add([string]$member.Name)
                } elseif ($null -ne $member.SID) {
                    $adminMembers.Add([string]$member.SID.Value)
                }
            }
        } catch {
            # Get-LocalGroupMember throws when the group contains orphaned SIDs or Microsoft Accounts; fall back to ADSI.
            $adsiAdminGroup = [ADSI]("WinNT://{0}/{1},group" -f $env:COMPUTERNAME, $localAdminGroupName)
            $rawAdsiMembers = @($adsiAdminGroup.Invoke('Members'))
            foreach ($rawMember in $rawAdsiMembers) {
                $adsPath = [string]$rawMember.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $rawMember, $null)
                $memberName = [string]$rawMember.GetType().InvokeMember('Name', 'GetProperty', $null, $rawMember, $null)
                if ($adsPath -like 'WinNT://*') {
                    $pathParts = $adsPath.Substring(8) -split '/'
                    if ($pathParts.Count -ge 3) {
                        $adminMembers.Add(("{0}\{1}" -f $pathParts[$pathParts.Count - 2], $pathParts[$pathParts.Count - 1]))
                    } elseif ($pathParts.Count -eq 2) {
                        $adminMembers.Add(("{0}\{1}" -f $pathParts[0], $pathParts[1]))
                    } elseif (-not [string]::IsNullOrWhiteSpace($memberName)) {
                        $adminMembers.Add($memberName)
                    }
                } elseif (-not [string]::IsNullOrWhiteSpace($memberName)) {
                    $adminMembers.Add($memberName)
                }
            }
        }

        $administrators['count'] = [int]$adminMembers.Count
        $administrators['members'] = [string[]]$adminMembers.ToArray()
    } catch {
        $administrators['error'] = Get-ShortError $_
    }
    $accounts['administrators'] = $administrators

    # 5c. Effective password & account lockout policy (secedit when Admin, net accounts fallback when non-Admin)
    $passwordPolicy = [ordered]@{
        minimumPasswordLength = $null
        passwordComplexity    = $null
        lockoutBadCount       = $null
        source                = $null
    }
    try {
        $secEditSucceeded = $false
        $tempSecPolFile = Join-Path -Path $env:TEMP -ChildPath ("sc_secpol_{0}.inf" -f [guid]::NewGuid().ToString('N'))
        try {
            if ($isElevated) {
                $null = & secedit.exe /export /cfg $tempSecPolFile /areas SECURITYPOLICY /quiet 2>&1
                if (Test-Path -LiteralPath $tempSecPolFile) {
                    $secLines = @(Get-Content -LiteralPath $tempSecPolFile -ErrorAction Stop)
                    $inSystemAccessSection = $false
                    $hasSystemAccessSection = $false
                    $systemAccessMap = @{}

                    foreach ($rawLine in $secLines) {
                        if ($null -eq $rawLine) {
                            continue
                        }
                        $trimmedLine = $rawLine.Trim()
                        if ($trimmedLine.Length -eq 0 -or $trimmedLine.StartsWith(';')) {
                            continue
                        }

                        if ($trimmedLine -match '^\[(.+)\]$') {
                            $currentSection = $Matches[1].Trim()
                            if ($currentSection -ieq 'System Access') {
                                $inSystemAccessSection = $true
                                $hasSystemAccessSection = $true
                            } else {
                                $inSystemAccessSection = $false
                            }
                            continue
                        }

                        if ($inSystemAccessSection -and ($trimmedLine -match '^([^=]+?)\s*=\s*(.*)$')) {
                            $settingKey = $Matches[1].Trim()
                            $settingValue = $Matches[2].Trim()
                            $systemAccessMap[$settingKey] = $settingValue
                        }
                    }

                    if ($hasSystemAccessSection) {
                        $parsedSettingInt = 0
                        if ($systemAccessMap.ContainsKey('MinimumPasswordLength') -and [int]::TryParse($systemAccessMap['MinimumPasswordLength'], [ref]$parsedSettingInt)) {
                            $passwordPolicy['minimumPasswordLength'] = [int]$parsedSettingInt
                        } else {
                            $passwordPolicy['minimumPasswordLength'] = 0
                        }

                        if ($systemAccessMap.ContainsKey('PasswordComplexity') -and [int]::TryParse($systemAccessMap['PasswordComplexity'], [ref]$parsedSettingInt)) {
                            $passwordPolicy['passwordComplexity'] = [int]$parsedSettingInt
                        } else {
                            $passwordPolicy['passwordComplexity'] = 0
                        }

                        if ($systemAccessMap.ContainsKey('LockoutBadCount') -and [int]::TryParse($systemAccessMap['LockoutBadCount'], [ref]$parsedSettingInt)) {
                            $passwordPolicy['lockoutBadCount'] = [int]$parsedSettingInt
                        } else {
                            $passwordPolicy['lockoutBadCount'] = 0
                        }

                        $passwordPolicy['source'] = 'secedit'
                        $secEditSucceeded = $true
                    }
                }
            }
        } catch {
            $secEditSucceeded = $false
        } finally {
            if ($null -ne $tempSecPolFile -and (Test-Path -LiteralPath $tempSecPolFile)) {
                Remove-Item -LiteralPath $tempSecPolFile -Force -ErrorAction SilentlyContinue
            }
        }

        if (-not $secEditSucceeded) {
            # Non-admin fallback: parse `net accounts` output (Lockout threshold prints "Never" when 0).
            $netLines = @(& net.exe accounts 2>&1)
            if ($LASTEXITCODE -ne 0 -or $netLines.Count -eq 0) {
                throw ("net accounts failed (exit code {0})." -f $LASTEXITCODE)
            }

            $foundMinPwLen = $false
            $foundLockoutThreshold = $false
            $minPwLenValue = 0
            $lockoutValue = 0

            foreach ($netEntry in $netLines) {
                if ($null -eq $netEntry) {
                    continue
                }
                $netText = $netEntry.ToString().Trim()
                if ($netText -match '(?i)^Minimum password length\s*:\s*(.+)$') {
                    $rawMinPw = $Matches[1].Trim()
                    $parsedNetInt = 0
                    if ([int]::TryParse($rawMinPw, [ref]$parsedNetInt)) {
                        $minPwLenValue = [int]$parsedNetInt
                    } else {
                        $minPwLenValue = 0
                    }
                    $foundMinPwLen = $true
                } elseif ($netText -match '(?i)^Lockout threshold\s*:\s*(.+)$') {
                    $rawLockout = $Matches[1].Trim()
                    $parsedNetInt = 0
                    if ($rawLockout -ieq 'Never' -or $rawLockout -ieq 'None') {
                        $lockoutValue = 0
                    } elseif ([int]::TryParse($rawLockout, [ref]$parsedNetInt)) {
                        $lockoutValue = [int]$parsedNetInt
                    } else {
                        $lockoutValue = 0
                    }
                    $foundLockoutThreshold = $true
                }
            }

            if (-not ($foundMinPwLen -or $foundLockoutThreshold)) {
                throw 'Could not parse password policy from net accounts output.'
            }

            $passwordPolicy['minimumPasswordLength'] = [int]$minPwLenValue
            $passwordPolicy['passwordComplexity'] = 0
            $passwordPolicy['lockoutBadCount'] = [int]$lockoutValue
            $passwordPolicy['source'] = 'net accounts'
        }
    } catch {
        $passwordPolicy['source'] = 'net accounts'
        $passwordPolicy['error'] = Get-ShortError $_
    }
    $accounts['passwordPolicy'] = $passwordPolicy
} catch {
    $accounts['error'] = Get-ShortError $_
}

# 6. Services and Windows Optional Features
$servicesAndFeatures = [ordered]@{
    error          = $null
    remoteRegistry = $null
    rdpEnabled     = $null
    smb1           = $null
    telnetClient   = $null
}
try {
    # 6a. Remote Registry service
    $remoteRegistry = [ordered]@{
        exists    = $null
        status    = $null
        startType = $null
    }
    try {
        $rrSvc = Get-Service -Name 'RemoteRegistry' -ErrorAction Stop
        $remoteRegistry['exists'] = $true
        $remoteRegistry['status'] = $rrSvc.Status.ToString()
        $remoteRegistry['startType'] = $rrSvc.StartType.ToString()
    } catch {
        if ($null -ne $_.CategoryInfo -and $_.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::ObjectNotFound) {
            $remoteRegistry['exists'] = $false
            $remoteRegistry['status'] = $null
            $remoteRegistry['startType'] = $null
        } else {
            $remoteRegistry['error'] = Get-ShortError $_
        }
    }
    $servicesAndFeatures['remoteRegistry'] = $remoteRegistry

    # 6b. Remote Desktop (fDenyTSConnections == 0 means RDP is enabled)
    $rdpEnabled = $null
    try {
        $tsKeyPath = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
        $tsItem = Get-ItemProperty -LiteralPath $tsKeyPath -Name 'fDenyTSConnections' -ErrorAction Stop
        if ($null -ne $tsItem -and $null -ne $tsItem.fDenyTSConnections) {
            $rdpEnabled = [bool]([int]$tsItem.fDenyTSConnections -eq 0)
        }
    } catch {
        $rdpEnabled = $null
    }
    $servicesAndFeatures['rdpEnabled'] = $rdpEnabled

    # 6c. SMBv1 server protocol + SMB1Protocol feature (with safe non-admin registry & file fallbacks)
    $smb1 = [ordered]@{
        serverProtocolEnabled = $null
        featureState          = $null
    }
    $smb1PartErrors = New-Object System.Collections.Generic.List[string]
    try {
        try {
            $smbServerConfig = Get-SmbServerConfiguration -ErrorAction Stop
            if ($null -ne $smbServerConfig -and $null -ne $smbServerConfig.EnableSMB1Protocol) {
                $smb1['serverProtocolEnabled'] = [bool]$smbServerConfig.EnableSMB1Protocol
            }
        } catch {
            # Fallback to reading HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters value SMB1 (missing or 0 => false).
            $lanmanParamsPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            if (-not (Test-Path -LiteralPath $lanmanParamsPath)) {
                throw 'LanmanServer Parameters registry key not found.'
            }
            $lanmanProps = Get-ItemProperty -LiteralPath $lanmanParamsPath -Name 'SMB1' -ErrorAction SilentlyContinue
            if ($null -eq $lanmanProps -or $null -eq $lanmanProps.SMB1 -or ([int]$lanmanProps.SMB1 -eq 0)) {
                $smb1['serverProtocolEnabled'] = $false
            } else {
                $smb1['serverProtocolEnabled'] = $true
            }
        }
    } catch {
        $smb1PartErrors.Add((Get-ShortError $_))
    }

    try {
        $smb1FeatureResolved = $false
        if ($isElevated) {
            try {
                $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName 'SMB1Protocol' -ErrorAction Stop
                if ($null -eq $smb1Feature) {
                    $smb1['featureState'] = 'NotPresent'
                } else {
                    $smb1['featureState'] = $smb1Feature.State.ToString()
                }
                $smb1FeatureResolved = $true
            } catch {
                $smb1FeatureResolved = $false
            }
        }

        if (-not $smb1FeatureResolved) {
            # Non-admin fallback: default to Disabled when serverProtocolEnabled is false, else check srv.sys driver file.
            $srvSysPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\drivers\srv.sys'
            if ($smb1['serverProtocolEnabled'] -eq $false) {
                $smb1['featureState'] = 'Disabled'
            } elseif (Test-Path -LiteralPath $srvSysPath) {
                $smb1['featureState'] = 'Enabled'
            } else {
                $smb1['featureState'] = 'Disabled'
            }
        }
    } catch {
        $smb1PartErrors.Add((Get-ShortError $_))
    }

    if ($smb1PartErrors.Count -gt 0) {
        $smb1['error'] = ($smb1PartErrors.ToArray() -join '; ')
    }
    $servicesAndFeatures['smb1'] = $smb1

    # 6d. Telnet Client optional feature (with safe non-admin System32\telnet.exe fallback)
    $telnetClient = [ordered]@{
        featureState = $null
    }
    try {
        $telnetResolved = $false
        if ($isElevated) {
            try {
                $telnetFeature = Get-WindowsOptionalFeature -Online -FeatureName 'TelnetClient' -ErrorAction Stop
                if ($null -eq $telnetFeature) {
                    $telnetClient['featureState'] = 'NotPresent'
                } else {
                    $telnetClient['featureState'] = $telnetFeature.State.ToString()
                }
                $telnetResolved = $true
            } catch {
                $telnetResolved = $false
            }
        }

        if (-not $telnetResolved) {
            $telnetSystem32 = Join-Path -Path $env:SystemRoot -ChildPath 'System32\telnet.exe'
            $telnetSysnative = Join-Path -Path $env:SystemRoot -ChildPath 'Sysnative\telnet.exe'
            if ((Test-Path -LiteralPath $telnetSystem32) -or (Test-Path -LiteralPath $telnetSysnative)) {
                $telnetClient['featureState'] = 'Enabled'
            } else {
                $telnetClient['featureState'] = 'Disabled'
            }
        }
    } catch {
        $telnetClient['error'] = Get-ShortError $_
    }
    $servicesAndFeatures['telnetClient'] = $telnetClient
} catch {
    $servicesAndFeatures['error'] = Get-ShortError $_
}

$auditPayload = [ordered]@{
    schemaVersion       = 1
    computerName        = [string]$env:COMPUTERNAME
    collectedAt         = (Get-Date).ToString('o')
    os                  = $os
    firewall            = $firewall
    updates             = $updates
    antivirus           = $antivirus
    accounts            = $accounts
    servicesAndFeatures = $servicesAndFeatures
}

$auditPayload | ConvertTo-Json -Depth 6 -Compress
