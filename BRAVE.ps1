#region     ## HIDE ##
<#
.SYNOPSIS
    BRAVE Assessment Script
.DESCRIPTION
    Active Directory queries for the purpose of a BRAVE assessments.
    Includes automated evidence collection for Veeam Backup & Replication, as an alternative to screenshots.
.NOTES
    Author:         Patrick O'Brien
    Date:           June 23, 2025
    Purpose:        Consolidation of 'Trimarc' and 'Composite' scripts with standardized output, naming, time format and error handling.
    Requirements:   • A fresh PowerShell session, each run
                    • PowerShell v5+
                    • Powershell run using 'Run as Administrator'
                    • PowerShell modules: See '$RequiredModules'.
                    • Active Direct Certificate Services (ADCS), 
                      requires PowerShell module: see '$CertModule'
.EXAMPLE
    PS> .\BRAVE.ps1
#>

[CmdletBinding()]
param(
    [ValidateScript({
        if(-not (Test-Path $_) ) {
            try {
                New-Item -Path $_ -ItemType Directory -Force | Out-Null
            } catch {
                Write-Error "Can't create $($Directory): $_"
                return $false
            }
        }
        return $true
    })]
    [string]$Directory = "c:\temp\BRAVE\"
)

$ErrorActionPreference = "SilentlyContinue"
$script:StartTime = Get-Date
$Version = "2.9"
$RequiredModules = ('ActiveDirectory', 'GroupPolicy')
$CertModule = "PSPKI"
$GPODirectory = (Join-Path $Directory "GPO")

function LogThis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$m,
        [ValidateSet('Info', 'Debug', 'Done', 'Warn', 'Error',  'Header', 'Status')]
        [string]$lvl = 'Info',
        [System.Management.Automation.ErrorRecord]$ex,
        [switch]$NoLog,
        [string]$show,
        [switch]$redraw
    )
    $ts = & $script:Format (Get-Date) -Format Display
    $msg = "[$ts] [$lvl] $m"
    
    if (($lvl -eq 'Warn' -or $lvl -eq 'Error') -and $ex) {
        $exceptionDetails = @(
            "   EXCEPTION:",
            "   Type:", "$($ex.Exception.GetType().FullName)",
            "   Message:", "$($ex.Exception.Message)",
            "   StackTrace:", "$($ex.Exception.StackTrace)",
            "   Line:", "$($ex.InvocationInfo.ScriptLineNumber)",
            "   Position:", "$($ex.InvocationInfo.PositionMessage)"
        )
        $msg += "`n" + ($exceptionDetails -join "`n")
    }
                                                                            
    $ready = $script:Log -and (Test-Path $script:Log)
    if (-not $NoLog -and $ready) {
        try {        
            $msg | Out-File -FilePath $script:Log -Append -Force -Encoding UTF8
        } catch {
            Write-Warning "[!] LogThis failed: $msg"
        }
    } else {
        if ($lvl -eq 'Warn') { Write-Warning $m }
        elseif ($lvl -eq 'Error') { Write-Error $m }
    }

    if ($show) {
        switch ($lvl) {
            'Info'   { 
                if ($redraw) {
                    Write-Host "`r" + (" " * [Console]::WindowWidth) + "`r" -NoNewline
                    Write-Host $show -ForegroundColor Cyan -NoNewline
                } else {
                    Write-Host $show -ForegroundColor Cyan
                }
            }
            'Debug'  { Write-Host $show -ForegroundColor White }
            'Minor'  { Write-Host $show -ForegroundColor White }
            'Done'   { Write-Host $show -ForegroundColor Green }
            'Warn'   { Write-Host "[*] $show" -ForegroundColor Yellow }
            'Error'  { Write-Host "[!] $show" -ForegroundColor Red }
            'Header' {
                Write-Host "`n=================================" -ForegroundColor DarkGray
                Write-Host $show -ForegroundColor White
                Write-Host "=================================" -ForegroundColor DarkGray
            }
            'Status' { Write-Host $show -ForegroundColor White }
        }
    }
}

function Get-BackupTime($pattern) {
    if ($partitions) {
        $partition = $partitions | Where-Object { $_ -match $pattern } | Select-Object -First 1
        if ($partition) {
            $metadata = Get-ADReplicationAttributeMetadata -Object $partition -Properties dSASignature -Server $script:ADDomain.PDCEmulator
            $backup = $metadata.LastOriginatingChangeTime
            if ($backup) {
                $timeSpan = New-TimeSpan -Start $backup -End $script:StartTime
                $years = [math]::Floor($timeSpan.TotalDays / 365)
                $months = [math]::Floor(($timeSpan.TotalDays % 365) / 30)
                $days = [math]::Floor($timeSpan.TotalDays % 30)
                
                "$(Get-Date $backup -Format 'dd MMM yyyy') [${years}y:${months}m:${days}d]"
            }
        }
    }
    return $null
}

function Format-PartitionBackup {
    param($output)
    if ($output -match '\(LastBackup\) (.*?), \(Elapsed\) (\d+)y:(\d+)m:(\d+)d') {
        $date = $matches[1]
        $years = $matches[2]
        $months = $matches[3]
        $days = $matches[4]
        "$date [$years`y$months`m$days`d]"
    } else {
        $null
    }
}

function GetPrerequisites {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Verify
    )
    
    LogThis -m "Checking modules: $($Verify -join ', ')"
    $RequiredModules = $Verify.Clone()
    LogThis -m "Required modules: $($RequiredModules -join ', ')"
    try {
        $RSATInstalled = (Get-WindowsFeature -Name RSAT-AD-PowerShell).Installed
        if ($RSATInstalled) {
            $RequiredModules = $RequiredModules -notmatch "ActiveDirectory"
            LogThis -m "RSAT pre-installed; ActiveDirectory removed from list"
        }
    } catch {
        LogThis -m "Unable to verify RSAT " -lvl Warn
    }

    $ModulesLoaded = Get-Module | Where-Object { $_.Name -in $RequiredModules }
    $RequiredModules = $RequiredModules | Where-Object { $_ -notin $ModulesLoaded.Name }
    
    if ($ModulesLoaded) {
        LogThis -m "ModulesLoaded: $($ModulesLoaded.Name -join ', ')"
    }

    if ($RequiredModules.Count -gt 0) {
        LogThis -m "Processing modules: $($RequiredModules -join ', ')" -show "Installing Required Modules"
        
        foreach ($Module in $RequiredModules) {
            if (-not (Get-Module -Name $Module -ListAvailable)) {
                try {
                    LogThis -m "$($Module): Installing" -show "$($Module): Installing"
                    Install-Module -Name $Module -Force -Scope CurrentUser
                } catch {
                    LogThis -m "$($Module): Failed" -lvl Warn -ex $_ -show "$($Module): Failed"
                }
            }
            
            try {
                LogThis -m "$($Module): Importing" -lvl Done -show "$($Module): Importing"
                Import-Module -Name $Module -Force
            } catch {
                LogThis -m "$($Module): Failed" -lvl Warn -ex $_ "$($Module): Failed"
            }
        }
    }

    $FinalModules = Get-Module | Where-Object { $_.Name -in $Verify }
    $Missing = $Verify | Where-Object { $_ -notin $FinalModules.Name }
    
    if ($Missing.Count -eq 0) {
        LogThis -m "All modules verified" -lvl Done -show "Prerequisites: Ready"
    } else {
        LogThis -m "Missing modules: $($Missing -join ', ')" -lvl Error -show "Prerequisites: Failed"
    }
}

$script:Export = {
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$InputObject,
        [Parameter(Mandatory)]
        [string]$Name,
        [string]$Description = $Name,
        [switch]$IsSummary
    )
    begin {
        if (-not $script:ProcessedSections.Contains($Name)) {
            $script:SectionCounter++
            $script:ProcessedSections.Add($Name) | Out-Null
        }
        $currentOrder = $script:SectionCounter

        $summaryObjects = [System.Collections.ArrayList]@()
        $detailedData = [System.Collections.ArrayList]@()
    }
    process {
        foreach ($item in $InputObject) {
            if ($IsSummary) {
                if ($item -is [System.Collections.IDictionary]) {
                    $enumerable = $item.GetEnumerator()
                }
                elseif ($item -is [PSCustomObject]) {
                    $enumerable = $item.psobject.Properties
                }
                else {
                    $enumerable = @($item)
                }
                foreach ($entry in $enumerable) {
                    [void]$summaryObjects.Add([PSCustomObject]@{
                        Order    = $currentOrder
                        Section  = $Name
                        Property = if ($entry.Key) { $entry.Key } else { $entry.Name }
                        Value    = & $script:Format $entry.Value
                    })
                }
            } else {
                if (-not ($item -is [PSCustomObject])) {
                    $clonedItem = [PSCustomObject]@{}
                    foreach ($prop in $item.PSObject.Properties) {
                        $clonedItem | Add-Member -MemberType NoteProperty -Name $prop.Name -Value (& $script:Format $prop.Value)
                    }
                    [void]$detailedData.Add($clonedItem)
                }
                else {
                    [void]$detailedData.Add($item)
                }
            }
        }
    }
    end {
        if ($summaryObjects) {
            $summaryPath = Join-Path $script:Directory "$($script:Filename)_summary.csv"
            $allEntries = if (Test-Path $summaryPath) {
                @(Import-Csv -Path $summaryPath) + @($summaryObjects)
            } else {
                $summaryObjects
            }
            $allEntries | Sort-Object { [int]$_.Order } |
                Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8
        }
        if ($detailedData -and -not $IsSummary) {
            $detailedData | Export-Csv -Path (Join-Path $script:Directory "$($script:Filename)-$Name.csv") -NoTypeInformation -Encoding UTF8
        }
    }
}

$script:ExportRaw = {
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$InputObject
    )
    process {
        $items = @($InputObject)
        $name = $section
        $file = Join-Path $script:Directory "$($script:Filename)-$name.xml"
        if (-not $items) {
            $items = [PSCustomObject]@{ Info = "No results collected" }
        }
        $items | Export-Clixml -Path $file -Force
    }
}

$script:Format = {
    param(
        [Parameter(ValueFromPipeline)]
        $Value,
        [ValidateSet('Display', 'File')]
        [string]$Format = 'Write'
    )

    if ($null -eq $Value) { return '' }

    switch ($Value) {
        { $_ -is [DateTime] } { 
            $utcTime = $_.ToUniversalTime()
            switch($Format) {
                'Display' { return $utcTime.ToString('dd MMM yyyy HH:mm UTC') }
                'File'  { return $utcTime.ToString('ddMMMyyyy_HHmmss_UTC') }
            }
        }
        { $_ -is [TimeSpan] } { return $_.TotalDays }
        default { return $_ }
    }
}

$script:Recursive = {
    param (
        [string]$GroupSID,
        [string]$GroupName,
        [string]$SecurityGroup,
        [string]$ParentPath = "",
        [hashtable]$AccessPaths
    )
    try {
        $results = @()
        $members = Get-ADGroupMember -Identity $GroupSID -Server $script:ADDomain.PDCEmulator

        $currentPath = if ($ParentPath) { "$ParentPath -> $GroupName" } else { $GroupName }

        foreach ($member in $members) {
            if ($member.objectClass -eq 'group') {
                # Add the group entry.
                $results += [PSCustomObject]@{
                    Name              = $member.Name
                    SamAccountName    = $member.SamAccountName
                    Group             = $GroupName
                    Enabled           = $true
                    ObjectType        = "Group"
                    NestedPath        = $currentPath
                    DistinguishedName = $member.DistinguishedName
                }

                # Recurse into nested group.
                $nestedMembers = & $script:Recursive -GroupSID $member.SID `
                                                       -GroupName $member.Name `
                                                       -SecurityGroup $SecurityGroup `
                                                       -ParentPath $currentPath `
                                                       -AccessPaths $AccessPaths
                if ($nestedMembers) {
                    $results += $nestedMembers
                }
            }
            else {
                # Process user member.
                $user = Get-ADUser $member -Properties LastLogonDate, PasswordLastSet, ServicePrincipalName, Enabled, DistinguishedName -Server $script:ADDomain.PDCEmulator

                $results += [PSCustomObject]@{
                    Name              = $user.Name
                    SamAccountName    = $user.SamAccountName
                    Group             = $GroupName
                    Enabled           = $user.Enabled
                    LastLogonDate     = & $script:Format $user.LastLogonDate
                    PasswordLastSet   = & $script:Format $user.PasswordLastSet
                    SPNs              = $user.ServicePrincipalName -join ','
                    ObjectType        = "User"
                    NestedPath        = $currentPath
                    DistinguishedName = $user.DistinguishedName
                }

                # *** This block populates AccessPaths ***
                if ($AccessPaths) {
                    if (-not $AccessPaths.ContainsKey($user.SamAccountName)) {
                        $AccessPaths[$user.SamAccountName] = @{}
                    }
                    $isDirect = $currentPath -eq $SecurityGroup
                    if (-not ($AccessPaths[$user.SamAccountName].ContainsKey($SecurityGroup) -and 
                           $AccessPaths[$user.SamAccountName][$SecurityGroup] -eq "Direct member")) {
                        $AccessPaths[$user.SamAccountName][$SecurityGroup] = if ($isDirect) { "Direct member" } else { $currentPath }
                    }
                }
            }
        }
        return $results
    }
    catch {
        LogThis -m "Error processing group $($GroupName)" -lvl Warn -ex $_
    }
}


$script:Validate = {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    try {
        $null = [System.IO.Compression.ZipFile]::OpenRead($Path) # Expand zip for integrity check
        return $true
    }
    catch {
        LogThis -m "Archive validation failed" -lvl Error -ex $_
        return $false
    }
    finally {
        if ($zip) { $zip.Dispose() }
    }
}

if ($PSVersionTable.PSVersion.Major -lt 5) {
    LogThis "PowerShell 5 or higher required. Current version: $($PSVersionTable.PSVersion)"
    throw
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    LogThis "Script requires elevation. Run PowerShell with 'Run As Administrator'."
    throw
}

#endregion  ## HIDE ##

function Get-Controls {
    [CmdletBinding()]
    param()

    $not = "Not Found"
    $nul = "<null>"
    $ope = "Error"
    $0 = "0"
    
    try {
        LogThis -m "Starting Get-Controls" -lvl Header -show "GATHERING ACTIVE DIRECTORY" 

        $Controls = [ordered]@{ # [ordered] maintains execution order
            'RUNTIME' = {
                $system = Get-CimInstance -ClassName Win32_ComputerSystem
                $os = Get-CimInstance -ClassName Win32_OperatingSystem
                $domainType = if ($system.PartOfDomain) { 'Domain-Joined' } else { 'Workgroup-Joined' }
                $domainName = if ($system.PartOfDomain) { $system.Domain } else { $system.Workgroup }
                @($system) | & $script:ExportRaw  
                [ordered]@{
                    'Time' = & $script:Format $script:StartTime -Format Display
                    'User' = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                    'Host (+)' = "(Name) $($env:COMPUTERNAME), (OS) $($os.Caption), (Build) $($os.Version)"
                    'Network (+)' = "(Type) $domainType, (Name) $domainName"
                    'PowerShell (+)' = "(User) $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name), (Host) $($Host.Name), (Version) $($PSVersionTable.PSVersion), (InvokePath) $($PSCommandPath)"
                } | & $script:Export -Name $section -IsSummary
            }
            
            'TOPOLOGY' = {
                Get-ADObject -Filter * -SearchBase ((Get-ADRootDSE).configurationNamingContext) -Server $script:ADDomain.PDCEmulator -Properties * | & $script:ExportRaw

                try {
                    $configuration = (Get-ADRootDSE).configurationNamingContext
                    $ds = Get-ADObject -Filter 'objectClass -eq "nTDSService"' -SearchBase $configuration -Properties dSHeuristics -Server $script:ADDomain.PDCEmulator
                    
                    $dcs = foreach ($dc in $script:ADDomain.ReplicaDirectoryServers) {
                        try {
                            $dcInfo = Get-ADDomainController $dc -Server $script:ADDomain.PDCEmulator
                            "$dc ($($dcInfo.OperatingSystem) $($dcInfo.OperatingSystemVersion))"
                        } catch {
                            "$dc (Unidentified)"
                        }
                    }

                    $rootDSE = Get-ADRootDSE -Server $script:ADDomain.PDCEmulator
                    $partitions = $rootDSE.namingContexts

                    ([pscustomobject][ordered]@{
                        Configuration = $configuration
                        NTDSObjects = $ds
                        DomainControllers = $dcs
                        NamingContexts = $partitions
                        Domain = $script:ADDomain
                        Forest = $script:ADForest
                    })

                    [ordered]@{
                        'Heirarchy (+)' = "(Current/Target Domain) $($script:ADDomain.Name), (Parent) $(if ($script:ADDomain.ParentDomain) { $script:ADDomain.ParentDomain } else { 'I Am Root' })"
                        'FunctionalLevels (+)' = "(Forest) $($script:ADForest.ForestMode), (Domain) $($script:ADDomain.DomainMode)"
                        'Sites (+)' = "(Count) $(($script:ADForest.Sites | Measure-Object).Count), (List) $($script:ADForest.Sites -join ', ')"
                        'Domains (+)' = "(Count) $(($script:ADForest.Domains | Measure-Object).Count), (List) $($script:ADForest.Domains -join ', ')"
                        'DomainControllers (+)' = "(Replicas) $(($script:ADDomain.ReplicaDirectoryServers | Measure-Object).Count)$(if ($script:ADDomain.ReadOnlyReplicaDirectoryServers) { ", (RODCs) $(($script:ADDomain.ReadOnlyReplicaDirectoryServers | Measure-Object).Count)" }), (List) $($dcs -join ', ')"
                        'Domain (+)' = "(DSHeuristics) $(if ($ds.dSHeuristics) { $ds.dSHeuristics } else { $nu }), (DNSRoot) $($script:ADDomain.DNSRoot), (NetBIOS) $($script:ADDomain.NetBIOSName), (SID) $($script:ADDomain.DomainSID.Value)"
                        'GlobalCatalogs (+)' = "(Count) $(($script:ADForest.GlobalCatalogs | Measure-Object).Count), (List) $($script:ADForest.GlobalCatalogs -join ', ')"
                        'FSMORoleHolders (+)' = "(SchemaMaster) $($script:ADForest.SchemaMaster), (DomainNamingMaster) $($script:ADForest.DomainNamingMaster), (PDCEmulator) $($script:ADDomain.PDCEmulator), (RIDMaster) $($script:ADDomain.RIDMaster), (InfrastructureMaster) $($script:ADDomain.InfrastructureMaster)"
                        'PartitionBackup_Forest_DNSZones' = Get-BackupTime "DC=ForestDnsZones,"
                        'PartitionBackup_Domain' = Get-BackupTime "^DC=(?!.*DnsZones)"
                        'PartitionBackup_Domain_Schema' = Get-BackupTime "CN=Schema,"
                        'PartitionBackup_Configuration' = Get-BackupTime "CN=Configuration,"
                        'PPartitionBackup_DomainDNSZones' = Get-BackupTime "DC=DomainDnsZones,"
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    LogThis -m "Failed getting topology info: $_" -lvl Error
                    [ordered]@{
                        'Heirarchy (+)' = "(Current/Target) $ope, (Parent) $ope"
                        'FunctionalLevels (+)' = "(Forest) $ope, (Domain) $ope"
                        'Sites (+)' = "(Count) $ope, (List) $ope"
                        'Domains (+)' = "(Count) $ope, (List) $ope"
                        'DomainControllers (+)' = "(Replicas) $ope, (RODCs) $ope, (List) $ope"
                        'Domain (+)' = "(DSHeuristics) $ope, (DNSRoot) $ope, (NetBIOS) $ope, (SID) $ope"
                        'GlobalCatalogs (+)' = "(Count) $ope, (List) $ope"
                        'FSMORoleHolders (+)' = "(SchemaMaster) $ope, (DomainNamingMaster) $ope, (PDCEmulator) $ope, (RIDMaster) $ope, (InfrastructureMaster) $ope"
                        'PartitionBackup_Forest_DNSZones' = $ope
                        'PartitionBackup_Domain_Schema' = $ope
                        'PartitionBackup_Configuration' = $ope
                        'PPartitionBackup_DomainDNSZones' = $ope
                    } | & $script:Export -Name $section -IsSummary
                }
            }

            'PASSWORD_POLICY' = {
                Get-ADDefaultDomainPasswordPolicy -Server $script:ADDomain.PDCEmulator | & $script:ExportRaw

                try {
                    $policy = Get-ADDefaultDomainPasswordPolicy -Server $script:ADDomain.PDCEmulator

                    [ordered]@{
                        'ComplexityEnabled' = if ($policy) { $policy.ComplexityEnabled } else { $not }
                        'MinLength' = if ($policy) { $policy.MinPasswordLength } else { $not }
                        'Age (+)' = if ($policy) { "(Min) $($policy.MinPasswordAge.Days)d:$($policy.MinPasswordAge.Hours)h:$($policy.MinPasswordAge.Minutes)m, (Max) $($policy.MaxPasswordAge.Days)d:$($policy.MaxPasswordAge.Hours)h:$($policy.MaxPasswordAge.Minutes)m" } else { "(Min) $not, (Max) $not" }
                        'Lockout (+)' = if ($policy) { "(Threshold) $($policy.LockoutThreshold), (Duration) $($policy.LockoutDuration.Days)d:$($policy.LockoutDuration.Hours)h:$($policy.LockoutDuration.Minutes)m" } else { "(Threshold) $not, (Duration) $not" }
                        'HistoryCount' = if ($policy) { $policy.PasswordHistoryCount } else { $not }
                        'ReversibleEncryptionEnabled' = if ($policy) { $policy.ReversibleEncryptionEnabled } else { $not }
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    LogThis -m "Failed getting password policy: $_" -lvl Error
                    @{
                        'ComplexityEnabled' = $ope
                        'MinLength' = $ope
                        'Age (+)' = "(Min) $ope, (Max) $ope"
                        'Lockout (+)' = "(Threshold) $ope, (Duration) $ope"
                        'HistoryCount' = $ope
                        'ReversibleEncryptionEnabled' = $ope
                    } | & $script:Export -Name $section -IsSummary
                }
            }

            'GROUP_POLICY' = {
                try {
                    LogThis -m "Creating GPO directory" -lvl Debug
                    New-Item -Path $script:GPODirectory -ItemType Directory -Force > $null
                    
                    LogThis -m "Getting GPOs from $($script:ADDomain.PDCEmulator)" -lvl Debug
                    $Gpos = Get-GPO -All -Server $script:ADDomain.PDCEmulator
                    LogThis -m "Found $($Gpos.Count) GPOs" -lvl Debug
                    
                    foreach ($gpo in $Gpos) {
                        LogThis -m "Processing GPO: $($gpo.DisplayName)" -lvl Debug
                        Get-GPOReport -Name $gpo.DisplayName -ReportType Xml -Path (Join-Path $script:GPODirectory "$($gpo.DisplayName).xml") -Server $script:ADDomain.PDCEmulator
                    }

                    [ordered]@{
                        'GroupPolicyObjects (+)' = "(Total) $(($Gpos | Measure-Object).Count), (Orphaned) $(($Gpos | Where-Object { -not $_.LinkedSitesCount -and -not $_.LinkedOUsCount } | Measure-Object).Count), (AllSettingsDisabled) $(($Gpos | Where-Object { $_.GpoStatus -eq 'AllSettingsDisabled' } | Measure-Object).Count), (ComputerSettingsDisabled) $(($Gpos | Where-Object { $_.GpoStatus -match 'ComputerSettingsDisabled' } | Measure-Object).Count), (UserSettingsDisabled) $(($Gpos | Where-Object { $_.GpoStatus -match 'UserSettingsDisabled' } | Measure-Object).Count)"
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    LogThis -m "Failed processing GPOs" -lvl Error -ex $_
                    [ordered]@{
                        'GroupPolicyObjects (+)' = "(Total) $not, (Orphaned) $not, (AllSettingsDisabled) $not, (ComputerSettingsDisabled) $not, (UserSettingsDisabled) $not"
                    } | & $script:Export -Name $section -IsSummary
                }
            }

            'TRUSTS' = {
                Get-ADTrust -Filter * -Properties * -Server $script:ADDomain.PDCEmulator | & $script:ExportRaw
                try {
                    $trusts = Get-ADTrust -Filter * -Properties * -Server $script:ADDomain.PDCEmulator
                    if ($trusts) {
                        $trusts | ForEach-Object {
                            [PSCustomObject][ordered]@{
                                'Name' = $_.Name
                                'Direction' = $_.Direction
                                'Type' = $_.TrustType
                                'Created' = & $script:Format $_.Created -Format Display
                                'Modified' = & $script:Format $_.Modified -Format Display
                                'SIDFiltering' = $_.SIDFilteringEnabled
                                'Selective' = $_.SelectiveAuthentication
                                'TGTDelegation' = $_.TGTDelegationEnabled
                                'Transitive' = $_.IsTreeRoot
                                'Status' = if ($_.IntraForest) { 'Intra-Forest' } else { 'Inter-Forest' }
                            } 
                        } | & $script:Export -Name $section
                    }
                    
                    [PSCustomObject][ordered]@{
                        'Summary (+)' = "(Total) $($trusts.Count), " +
                                    "(Bidirectional) $(($trusts | Where-Object Direction -eq 'BiDirectional').Count), " +
                                    "(Inbound) $(($trusts | Where-Object Direction -eq 'Inbound').Count), " +
                                    "(Outbound) $(($trusts | Where-Object Direction -eq 'Outbound').Count)"
                    } | & $script:Export -Name $section -IsSummary
                }
                catch {
                    Write-Warning "Error in TRUSTS section: $_"
                    [ordered]@{
                        'Summary (+)' = "(Error) Unable to enumerate trusts"
                    } | & $script:Export -Name $section -IsSummary
                }
            }

            'SID500' = {
                $sid = "$($script:ADDomain.DomainSID.Value)-500"; Get-ADUser -Identity $sid -Properties * -Server $script:ADDomain.PDCEmulator | & $script:ExportRaw
                try {
                    $sid = "$($script:ADDomain.DomainSID.Value)-500"
                    $administrator = Get-ADUser -Identity $sid -Properties LastLogonDate, PasswordLastSet -Server $script:ADDomain.PDCEmulator

                    $logonAge = New-TimeSpan -Start $administrator.LastLogonDate -End $script:StartTime
                    $passwordAge = New-TimeSpan -Start $administrator.PasswordLastSet -End $script:StartTime

                    [ordered]@{
                        'Default' = "(SamAccountName) $($administrator.SamAccountName), (Name) $($administrator.Name), (Enabled) $($administrator.Enabled)"
                        'Logon' = "$(Get-Date $administrator.LastLogonDate -Format 'dd MMM yyyy') [$([math]::Floor($logonAge.TotalDays / 365))y$([math]::Floor(($logonAge.TotalDays % 365) / 30))m$([math]::Floor($logonAge.TotalDays % 30))d]"
                        'Password' = "$(Get-Date $administrator.PasswordLastSet -Format 'dd MMM yyyy') [$([math]::Floor($passwordAge.TotalDays / 365))y$([math]::Floor(($passwordAge.TotalDays % 365) / 30))m$([math]::Floor($passwordAge.TotalDays % 30))d]"
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    LogThis -m "Failed checking SID500: $_" -lvl Error
                    [ordered]@{
                        'Default' = $ope
                        'Logon' = $ope
                        'Password' = $ope
                    } | & $script:Export -Name $section -IsSummary
                }
            }

            'PRIVILIGED' = {
                $script:PrivilegedGroups.Values | ForEach-Object { Get-ADGroup -Identity $_ -Properties * -Server $script:ADDomain.PDCEmulator } | & $script:ExportRaw

                $groups = @()
                $accessPaths = @{}
                $summary = @{}

                foreach ($group in $script:PrivilegedGroups.GetEnumerator()) {
                    try {
                        LogThis -m "Processing: $($group.Key), SID: $($group.Value)" -lvl Debug
                        
                        $members = & $script:Recursive -GroupSID $group.Value `
                                                    -GroupName $group.Key `
                                                    -SecurityGroup $group.Key `
                                                    -AccessPaths $accessPaths
                        LogThis -m "$($group.Key) contains: $($members.Count) members" -lvl Debug

                        if ($members) {
                            $groups += $members
                            $enabled = ($members | Where-Object { $_.ObjectType -eq 'User' } | Sort-Object -Unique SamAccountName).Count
                            $disabled = ($members | Where-Object { $_.ObjectType -eq 'User' -and -not $_.Enabled } | Sort-Object -Unique SamAccountName).Count
                            $summary["[$($group.Key)] Enabled: $enabled Disabled: $disabled"] = ""
                        }
                    }
                    catch {
                        LogThis -m "Failed processing: $($group.Key), SID: $($group.Value)" -lvl Debug
                        $summary["[$($group.Key)] Enabled: Error Disabled: Error"] = ""
                    }
                }
                
                try { # Pre-Windows 2000
                    $pre2000 = Get-ADGroupMember -Identity "S-1-5-32-554" -Server $script:ADDomain.PDCEmulator
                    [ordered]@{
                        'Total' = ($pre2000 | Measure-Object).Count
                        '[Everyone] is member' = ($pre2000.SID -contains 'S-1-1-0').ToString()
                        '[ANONYMOUS LOGON] is member' = ($pre2000.SID -contains 'S-1-5-7').ToString()
                        '[Authenticated Users] is member' = ($pre2000.SID -contains 'S-1-5-11').ToString()
                    } | & $script:Export -Name $section -IsSummary
                }
                catch {
                    [ordered]@{
                        'Total' = "Error"
                        '[Everyone] is member' = "Error"
                        '[ANONYMOUS LOGON] is member' = "Error"
                        '[Authenticated Users] is member' = "Error"
                    } | & $script:Export -Name $section -IsSummary
                }

                try {
                    LogThis -m "Creating privileged matrix for $($accessPaths.Count) accounts" -lvl Debug
                    $script:PrivilegedUsers = @()
                    
                    foreach ($account in $accessPaths.Keys | Sort-Object) {
                        LogThis -m "Processing: $account" -lvl Debug
                        LogThis -m "PrivilegedGroups keys: $($script:PrivilegedGroups.Keys -join ', ')" -lvl Debug
                        LogThis -m "AccessPaths Keys: $($accessPaths.Keys -join ', ')" -lvl Debug
                        LogThis -m "Groups count: $($groups.Count)" -lvl Debug
                        $member = $groups | Where-Object { $_.SamAccountName -eq $account } | Select-Object -First 1
                        
                        if ($member -and $member.ObjectType -eq 'User') {
                            $obj = [PSCustomObject]@{
                                SamAccountName  = $account
                                ObjectType      = "User"
                                Enabled         = $member.Enabled
                                LastLogonDate   = & $script:Format $member.LastLogonDate
                                PasswordLastSet = & $script:Format $member.PasswordLastSet
                            }
                            
                            foreach ($grp in $script:PrivilegedGroups.Keys) {
                                $value = if ($accessPaths[$account].ContainsKey($grp)) { 
                                    $accessPaths[$account][$grp].Replace(' -> ', ' <- ')
                                } else { 
                                    ""
                                }
                                $obj | Add-Member -NotePropertyName $grp -NotePropertyValue $value
                            }
                            
                            $script:PrivilegedUsers += $obj
                        }
                    }
                }
                catch {
                    LogThis -m "Privileged matrix failed" -lvl Warn -ex $_
                }

                if ($groups -or $script:PrivilegedUsers) {
                    try {
                        $groups | ConvertTo-Csv -NoTypeInformation | 
                            Out-File -FilePath (Join-Path $script:Directory "$($script:Filename)-$section-GROUPS.csv") -Encoding UTF8
                    }
                    catch {
                        LogThis -m "Failed exporting privileged groups" -lvl Error -ex $_
                    }

                    try {
                        $script:PrivilegedUsers | ConvertTo-Csv -NoTypeInformation | 
                            Out-File -FilePath (Join-Path $script:Directory "$($script:Filename)-$section-USER_MATRIX.csv") -Encoding UTF8
                    }
                    catch {
                        LogThis -m "Failed exporting privileged user matrix" -lvl Error -ex $_
                    }

                    $summary | & $script:Export -Name $section -IsSummary
                }
                else {
                    [ordered]@{ 'Status' = "No privileged accounts found" } | & $script:Export -Name $section -IsSummary
                }
            }

            'USERS' = {
                Get-ADUser -Filter * -Properties * -Server $script:ADDomain.PDCEmulator | & $script:ExportRaw
                try {
                    $users = Get-ADUser -Filter * -Properties $script:UserProperties -Server $script:ADDomain.PDCEmulator
                    [ordered]@{
                        'Counts (*)' = if ($users) { "(Total) $(($users | Measure-Object).Count), (Enabled) $(($users | Where-Object {$_.Enabled} | Measure-Object).Count), (Disabled) $(($users | Where-Object {-not $_.Enabled} | Measure-Object).Count), (Stale) $(($users | Where-Object { $_.LastLogonDate -and $_.PasswordLastSet -and ((New-TimeSpan -Start $_.LastLogonDate -End $script:StartTime).TotalDays -ge $script:LogonAge) -and ((New-TimeSpan -Start $_.PasswordLastSet -End $script:StartTime).TotalDays -ge $script:PasswordAge) } | Measure-Object).Count)" } else { "(Total) $not, (Enabled) $not, (Disabled) $not, (Stale) $not" }
                        'Passwords (*)' = if ($users) { "(NOTREQD) $(($users | Where-Object {$_.UserAccountControl -band 0x0020} | Measure-Object).Count), (CANT_CHANGE) $(($users | Where-Object {$_.UserAccountControl -band 0x0040} | Measure-Object).Count), (DONT_EXPIRE) $(($users | Where-Object {$_.UserAccountControl -band 0x10000} | Measure-Object).Count)" } else { "(NOTREQD) $not, (CANT_CHANGE) $not, (DONT_EXPIRE) $not" }
                        'Delegation (*)' = if ($users) { "(TRUSTED) $(($users | Where-Object {$_.UserAccountControl -band 0x80000} | Measure-Object).Count), (NOT_DELEGATED) $(($users | Where-Object {$_.UserAccountControl -band 0x100000} | Measure-Object).Count)" } else { "(TRUSTED_FOR) $not, (NOT_DELEGATED) $not" }
                        'InterdomainTrust' = if ($users) { ($users | Where-Object {$_.UserAccountControl -band 0x0800} | Measure-Object).Count } else { $not }
                        'DesKeyOnly' = if ($users) { ($users | Where-Object {$_.UserAccountControl -band 0x200000} | Measure-Object).Count } else { $not }
                        'NoPreAuth' = if ($users) { ($users | Where-Object {$_.UserAccountControl -band 0x400000} | Measure-Object).Count } else { $not }
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    LogThis -m "Failed checking users: $_" -lvl Error
                    [ordered]@{
                        'Counts (*)' = $ope
                        'Passwords (*)' = $ope
                        'Delegation (*)' = $ope
                        'InterdomainTrust' = $ope
                        'DesKeyOnly' = $ope
                        'NoPreAuth' = $ope
                    } | & $script:Export -Name $section -IsSummary
                }
            }

            'KRBTGT' = {
                Get-ADUser -Identity 'krbtgt' -Properties * -Server $script:ADDomain.PDCEmulator | & $script:ExportRaw

                try {
                    $krbtgt = Get-ADUser 'krbtgt' -Properties PasswordLastSet -Server $script:ADDomain.PDCEmulator
                    [ordered]@{
                        'Password' = "(LastSet) $(& $script:Format $krbtgt.PasswordLastSet -Format Display) $(Format-PartitionBackup (Get-BackupTime $krbtgt.PasswordLastSet))  [$([math]::Floor($passwordAge.TotalDays / 365))y$([math]::Floor(($passwordAge.TotalDays % 365) / 30))m$([math]::Floor($passwordAge.TotalDays % 30))d]"
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    LogThis -m "Failed checking KRBTGT: $_" -lvl Error
                    [ordered]@{
                        'Password' = $ope
                    } | & $script:Export -Name $section -IsSummary
                }
            }

            'DELEGATION' = {
                Get-ADObject -Filter * -Properties * -Server $script:ADDomain.PDCEmulator | & $script:ExportRaw

                try {
                    $delegatedAccounts = Get-ADObject -Filter {
                        ((UserAccountControl -BAND 0x0080000) -OR 
                        (UserAccountControl -BAND 0x1000000) -OR 
                        (msDS-AllowedToDelegateTo -like '*') -OR 
                        (msDS-AllowedToActOnBehalfOfOtherIdentity -like '*')) -AND 
                        (PrimaryGroupID -ne '516') -AND 
                        (PrimaryGroupID -ne '521')
                    } -Properties @(
                        "Name", "ObjectClass", "PrimaryGroupID", 
                        "UserAccountControl", "ServicePrincipalName", 
                        "msDS-AllowedToDelegateTo", 
                        "msDS-AllowedToActOnBehalfOfOtherIdentity",
                        "DistinguishedName"
                    ) -Server $script:ADDomain.PDCEmulator
                    $delegatedAccounts | & $script:ExportRaw
                    if ($delegatedAccounts) {
                        $delegatedAccounts | ForEach-Object {
                            $delegationType = switch ($true) {
                                { $_.UserAccountControl -BAND 0x0080000 } { 'Unconstrained' }
                                { $_.UserAccountControl -BAND 0x1000000 } { 'Constrained with Protocol Transition' }
                                { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' } { 'Resource-Based Constrained Delegation' }
                                { $_.'msDS-AllowedToDelegateTo' } { 'Constrained' }
                                default { 'Unknown' }
                            }

                            [PSCustomObject][ordered]@{
                                'Default' = "(Name) $($_.Name), (Type) $delegationType"
                                'Services' = if ($_.UserAccountControl -BAND 0x0080000) { "All" } else { "Specific" }
                                'Protocol' = if ($_.UserAccountControl -BAND 0x1000000) { "Any" } else { "Kerberos" }
                                'Domain' = $script:ADDomain.DNSRoot
                            } | & $script:Export -Name $section
                        }

                        [ordered]@{
                            'Summary (+)' = "(Total) $($delegatedAccounts.Count), (Unconstrained) $(($delegatedAccounts | Where-Object { $_.UserAccountControl -BAND 0x0080000 }).Count), (Constrained) $(($delegatedAccounts | Where-Object { $_.'msDS-AllowedToDelegateTo' }).Count), (Resource) $(($delegatedAccounts | Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' }).Count)"
                        } | & $script:Export -Name $section -IsSummary
                    } else {
                        [ordered]@{
                            'Summary (+)' = "(Total) $not, (Unconstrained) $not, (Constrained) $not, (Resource) $not"
                        } | & $script:Export -Name $section -IsSummary
                    }
                } catch {
                    LogThis -m "Failed checking delegation: $_" -lvl Error
                    [ordered]@{
                        'Summary (+)' = "(Total) $ope, (Unconstrained) $ope, (Constrained) $ope, (Resource) $ope"
                    } | & $script:Export -Name $section -IsSummary
                }
            }

            'MSA' = {
                Get-ADObject -LDAPFilter "(|(objectClass=msDS-ManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount))" -Properties * -Server $script:ADDomain.PDCEmulator | & $script:ExportRaw
                try {
                    $sMSA = Get-ADObject -Filter 'ObjectClass -eq "msDS-ManagedServiceAccount"' `
                        -Properties Name, ObjectClass, SamAccountName, Created, Modified, Description, DNSHostName, Enabled, MemberOf, 'msDS-HostServiceAccount' `
                        -Server $script:ADDomain.PDCEmulator

                    $gMSA = Get-ADObject -Filter 'ObjectClass -eq "msDS-GroupManagedServiceAccount"' `
                        -Properties Name, ObjectClass, SamAccountName, Created, Modified, Description, DNSHostName, Enabled, MemberOf, 'msDS-GroupMSAMembership' `
                        -Server $script:ADDomain.PDCEmulator

                    if ($sMSA -or $gMSA) {
                        $sMSA | ForEach-Object {
                            [PSCustomObject][ordered]@{
                                'Default' = "(Name) $($_.Name), (Type) sMSA, (Enabled) $($_.Enabled)"
                                'Created' = "$(& $script:Format $_.Created -Format Display) $(Format-PartitionBackup (Get-BackupTime $_.Created))"
                                'Modified' = "$(& $script:Format $_.Modified -Format Display) $(Format-PartitionBackup (Get-BackupTime $_.Modified))"
                                'Hostname (+)' = if ($_.DNSHostName) { $_.DNSHostName } else { $nul }
                                'Computers (+)' = if ($_.'msDS-HostServiceAccount') { 
                                    (($_.'msDS-HostServiceAccount' | ForEach-Object { try { (Get-ADComputer $_ -Server $script:ADDomain.PDCEmulator).Name } catch { $null } }) -join ', ') 
                                } else { 
                                    $nul 
                                }
                                'Groups (+)' = if ($_.MemberOf) { 
                                    (($_.MemberOf | ForEach-Object { try { (Get-ADGroup $_ -Server $script:ADDomain.PDCEmulator).Name } catch { $null } }) -join ', ') 
                                } else { 
                                    $nul 
                                }
                            } | & $script:Export -Name $section
                        }

                        $gMSA | ForEach-Object {
                            [PSCustomObject][ordered]@{
                                'Default' = "(Name) $($_.Name), (Type) gMSA, (Enabled) $($_.Enabled)"
                                'Created' = "$(& $script:Format $_.Created -Format Display) $(Format-PartitionBackup (Get-BackupTime $_.Created))"
                                'Modified' = "$(& $script:Format $_.Modified -Format Display) $(Format-PartitionBackup (Get-BackupTime $_.Modified))"
                                'Hostname (+)' = if ($_.DNSHostName) { $_.DNSHostName } else { $nul }
                                'Principals (+)' = if ($_.'msDS-GroupMSAMembership') { 
                                    (($_.'msDS-GroupMSAMembership' | ForEach-Object { try { (Get-ADObject $_ -Server $script:ADDomain.PDCEmulator).Name } catch { $null } }) -join ', ') 
                                } else { 
                                    $nul 
                                }
                                'Groups (+)' = if ($_.MemberOf) { 
                                    (($_.MemberOf | ForEach-Object { try { (Get-ADGroup $_ -Server $script:ADDomain.PDCEmulator).Name } catch { $null } }) -join ', ') 
                                } else { 
                                    $nul 
                                }
                            } | & $script:Export -Name $section
                        }

                        [ordered]@{
                            'Summary (+)' = "(Total) $(($sMSA + $gMSA).Count), (sMSA) $(($sMSA | Measure-Object).Count), (gMSA) $(($gMSA | Measure-Object).Count)"
                        } | & $script:Export -Name $section -IsSummary
                    } else {
                        [ordered]@{
                            'Summary (+)' = "(Total) $not, (sMSA) $not, (gMSA) $not"
                        } | & $script:Export -Name $section -IsSummary
                    }
                } catch {
                    LogThis -m "Failed checking MSAs: $_" -lvl Error
                    [ordered]@{
                        'Summary (+)' = "(Total) $ope, (sMSA) $ope, (gMSA) $ope"
                    } | & $script:Export -Name $section -IsSummary
                }
            }

            'SPN' = {
                Get-ADObject -Filter { ServicePrincipalName -like "*" } -Properties * -Server $script:ADDomain.PDCEmulator | & $script:ExportRaw
                try {
                    $spnObjects = Get-ADObject -Filter { ServicePrincipalName -like "*" } `
                        -Properties ServicePrincipalName, ObjectClass, Name, DistinguishedName, SamAccountName, UserAccountControl `
                        -Server $script:ADDomain.PDCEmulator

                    $spnObjects | & $script:ExportRaw

                    $totalSPNs = 0
                    $totalObjects = 0
                    $totalUsers = 0
                    $totalPrivileged = 0
                    $totalDuplicates = 0

                    if ($spnObjects) {
                        $userSPNs = $spnObjects | Where-Object { $_.ObjectClass -eq 'user' }
                        $totalUsers = ($userSPNs | Measure-Object).Count
                        if ($userSPNs) {
                            $userSPNs | ForEach-Object {
                                [PSCustomObject][ordered]@{
                                    'Default' = "(Name) $($_.Name), (SamAccountName) $($_.SamAccountName)"
                                    'SPNs (+)' = $_.ServicePrincipalName -join ', '
                                } | & $script:Export -Name "$section-STANDALONE"
                            }
                        }

                        $privilegedSPNs = $spnObjects | Where-Object {
                            $_.ObjectClass -eq 'user' -and
                            $_.SamAccountName -in $script:PrivilegedUsers.SamAccountName
                        }
                        $totalPrivileged = ($privilegedSPNs | Measure-Object).Count
                        if ($privilegedSPNs) {
                            $privilegedSPNs | ForEach-Object {
                                [PSCustomObject][ordered]@{
                                    'Default' = "(Name) $($_.Name), (SamAccountName) $($_.SamAccountName)"
                                    'SPNs (+)' = $_.ServicePrincipalName -join ', '
                                } | & $script:Export -Name "$section-PRIVILEGED"
                            }
                        }

                        $spnCheck = SetSPN -X -F
                        $duplicates = $spnCheck | Where-Object { 
                            $_ -notlike "Checking forest*" -and 
                            $_ -notlike "Operation will be*" -and 
                            $_ -notlike "Processing entry*" -and
                            $_ -notlike "found * group of duplicate SPNs*"
                        }
                        $totalDuplicates = ($duplicates | Measure-Object).Count
                        if ($duplicates) {
                            foreach ($dupe in $duplicates) {
                                [PSCustomObject][ordered]@{
                                    'Duplicate' = $dupe
                                } | & $script:Export -Name "$section-DUPLICATE"
                            }
                        }

                        $totalSPNs = ($spnObjects | ForEach-Object { $_.ServicePrincipalName.Count } | Measure-Object -Sum).Sum
                        $totalObjects = ($spnObjects | Measure-Object).Count
                    }

                    [ordered]@{
                        'Summary (+)' = "(Total) $totalSPNs, (Objects) $totalObjects, (Users) $totalUsers, (Privileged) $totalPrivileged, (Duplicates) $totalDuplicates"
                    } | & $script:Export -Name $section -IsSummary

                } catch {
                    LogThis -m "Failed checking SPNs: $_" -lvl Error
                    [ordered]@{
                        'Summary (+)' = "(Total) $ope, (Objects) $ope, (Users) $ope, (Privileged) $ope, (Duplicates) $ope"
                    } | & $script:Export -Name $section -IsSummary
                }
            }

            'FGPP' = {
             Get-ADFineGrainedPasswordPolicy -Filter * -Properties * -Server $script:ADDomain.PDCEmulator | & $script:ExportRaw
               try {
                    $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * -Server $script:ADDomain.PDCEmulator
                    $fgpp | & $script:ExportRaw

                    if ($fgpp) {
                        $totalPolicies = ($fgpp | Measure-Object).Count

                        $fgpp | ForEach-Object {
                            $policy = $_
                            
                            try {
                                $subjects = Get-ADFineGrainedPasswordPolicySubject -Identity $policy -Server $script:ADDomain.PDCEmulator -ErrorAction Stop
                            }
                            catch {
                                LogThis -m "Failed getting subjects for policy $($policy.Name): $_" -lvl Warn
                                $subjects = @()
                            }
                            
                            $allMembers = @()
                            foreach ($subject in $subjects) {
                                try {
                                    $members = & $script:Recursive -GroupSID $subject.SID `
                                                                    -GroupName $subject.Name `
                                                                    -SecurityGroup $subject.Name `
                                                                    -AccessPaths @{}
                                    $allMembers += $members
                                }
                                catch {
                                    LogThis -m "Failed getting members for $($subject.Name): $_" -lvl Warn
                                }
                            }
                            
                            $uniqueUsers = $allMembers | Where-Object { $_.ObjectType -eq 'User' } | Select-Object -ExpandProperty Name -Unique
                            $uniqueGroups = $allMembers | Where-Object { $_.ObjectType -eq 'Group' } | Select-Object -ExpandProperty Name -Unique

                            # Create a raw (ungrouped) detailed object with separate columns
                            [PSCustomObject][ordered]@{
                                Name                     = $policy.Name
                                Precedence               = $policy.Precedence
                                MinPasswordLength        = $policy.MinPasswordLength
                                PasswordHistoryCount     = $policy.PasswordHistoryCount
                                ComplexityEnabled        = $policy.ComplexityEnabled
                                ReversibleEncryption     = $policy.ReversibleEncryptionEnabled
                                MinPasswordAge           = $policy.MinPasswordAge
                                MaxPasswordAge           = $policy.MaxPasswordAge
                                LockoutThreshold         = $policy.LockoutThreshold
                                LockoutDuration          = $policy.LockoutDuration
                                LockoutObservationWindow = $policy.LockoutObservationWindow
                                AppliedTo                = if ($subjects) { ($subjects | Select-Object -ExpandProperty Name | Sort-Object) -join ', ' } else { $null }
                                AffectedUsers            = if ($uniqueUsers) { ($uniqueUsers | Sort-Object) -join ', ' } else { $null }
                                AffectedGroups           = if ($uniqueGroups) { ($uniqueGroups | Sort-Object) -join ', ' } else { $null }
                            } | & $script:Export -Name $section
                        }
                    }

                    [ordered]@{
                        'Summary (+)' = "(Total) $totalPolicies"
                    } | & $script:Export -Name $section -IsSummary

                }
                catch {
                    LogThis -m "Failed checking FGPPs: $_" -lvl Error
                    [ordered]@{
                        'Summary (+)' = "(Total) $ope"
                    } | & $script:Export -Name $section -IsSummary
                }
            }

            'SYSVOL' = {
                $script:DCs | ForEach-Object { Get-ChildItem -Path "\\$($_.Name)\SYSVOL" -Recurse -Depth 2 } | & $script:ExportRaw
                try {
                    $results = foreach ($dc in $script:DCs) {
                        LogThis -m "Processing SYSVOL on $($dc.Name)"
                        try {
                            # Recursively enumerate folders within SYSVOL up to a depth of 2
                            $allFolders = Get-ChildItem -Path "\\$($dc.Name)\SYSVOL" -Directory -Recurse -Depth 2
                            foreach ($folder in $allFolders) {
                                $acl = Get-Acl -Path $folder.FullName
                                # For each access entry that isn't one of the standard ones, output a clean object
                                $acl.Access | Where-Object { 
                                    @("BUILTIN\Administrators", "NT AUTHORITY\SYSTEM", "CREATOR OWNER") -notcontains $_.IdentityReference -and 
                                    $_.FileSystemRights -notmatch "^-?[\d\.]+$" 
                                } | ForEach-Object {
                                    [PSCustomObject][ordered]@{
                                        DC          = $dc.Name
                                        Folder      = $folder.FullName
                                        Identity    = $_.IdentityReference
                                        Permissions = $_.FileSystemRights
                                        Inherited   = $_.IsInherited
                                    }
                                }
                            }

                            
                        } catch {
                            LogThis -m "Failed to process DC: $($dc.Name)" -lvl Warn -ex $_
                            continue
                        }
                    }

                    if ($results) {
                        # Detailed export: raw dump of each SYSVOL access entry
                        $results | & $script:Export -Name $section
                        
                        # Also export a summary with a clean PSCustomObject
                        [PSCustomObject][ordered]@{
                            'DCs Processed'      = ($script:DCs | Measure-Object).Count
                            'Custom Permissions' = ($results | Measure-Object).Count
                        } | & $script:Export -Name $section -IsSummary
                    } else {
                        [PSCustomObject][ordered]@{
                            'DCs Processed'      = ($script:DCs).Count
                            'Custom Permissions' = 0
                        } | & $script:Export -Name $section -IsSummary
                    }
                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }

            'LOGGING' = {
                try {
                    $dll = [string]::Join("`r`n", '[DllImport("advapi32.dll")]', 'public static extern bool') 
                    $auditpol = Add-Type -Name 'AuditPol' -Namespace 'Win32' -PassThru -MemberDefinition "
                        $dll AuditEnumerateCategories(out IntPtr catList, out uint count);
                        $dll AuditLookupCategoryName(Guid catGuid, out string catName);
                        $dll AuditEnumerateSubCategories(Guid catGuid, bool all, out IntPtr subList, out uint count);
                        $dll AuditLookupSubCategoryName(Guid subGuid, out String subName);
                        $dll AuditQuerySystemPolicy(Guid subGuid, uint count, out IntPtr policy);
                        $dll AuditFree(IntPtr buffer);"

                    Add-Type -TypeDefinition "
                        using System;
                        public struct AUDIT_POLICY_INFORMATION {
                            public Guid AuditSubCategoryGuid;
                            public UInt32 AuditingInformation;
                            public Guid AuditCategoryGuid;
                        }"

                    function Get-PolicyInfo($sub) {
                        $pol = new-object AUDIT_POLICY_INFORMATION
                        $size = $ms::SizeOf($pol)
                        $ptr = $ms::AllocHGlobal($size)
                        $null = $ms::StructureToPtr($pol, $ptr, $false)
                        $null = $auditpol::AuditQuerySystemPolicy($sub, 1, [ref]$ptr)
                        $pol = $ms::PtrToStructure($ptr, [type][AUDIT_POLICY_INFORMATION])

                        $pol | & $script:ExportRaw
                        $guid | & $script:ExportRaw

                        $null = $ms::FreeHGlobal($ptr)
                        @{
                            category = $pol.AuditCategoryGuid
                            success = [bool]($pol.AuditingInformation -band 1)
                            failure = [bool]($pol.AuditingInformation -band 2)
                        }
                    }

                    $ms = [System.Runtime.InteropServices.Marshal]
                    $count = [uint32]0
                    $buffer = [IntPtr]::Zero
                    $size = $ms::SizeOf([type][guid])
                    $null = $auditpol::AuditEnumerateCategories([ref]$buffer,[ref]$count)
                    $ptr = [int64]$buffer
                    $name = [System.Text.StringBuilder]::new()
                    $catList = @{}
                    foreach($id in 1..$count) {
                        $guid = $ms::PtrToStructure([IntPtr]$ptr,[type][guid])
                        $null = $auditpol::AuditLookupCategoryName($guid,[ref]$name)
                        $catList[$guid] = $name
                        $ptr += $size
                    }
                    $null = $auditpol::AuditFree($buffer)

                    $guid = [guid]::Empty
                    $null = $auditpol::AuditEnumerateSubCategories($guid, $true, [ref]$buffer, [ref]$count)
                    $ptr = [int64]$buffer
                    $results = @()
                    foreach($id in 1..$count) {
                        $guid = $ms::PtrToStructure([IntPtr]$ptr,[type][guid])
                        $null = $auditpol::AuditLookupSubCategoryName($guid,[ref]$name)
                        $pol = Get-PolicyInfo $guid
                        
                        $results += @{
                            Category = $catList[$pol.category]
                            Subcategory = $name.ToString()
                            Success = $pol.success
                            Failure = $pol.failure
                        }
                        $ptr += $size
                    }

                    if ($results) {
                        $results | ForEach-Object {
                            [PSCustomObject][ordered]@{
                                'Default' = "(Category) $($_.Category), (Subcategory) $($_.Subcategory)"
                                'Settings (+)' = "(Success) $($_.Success), (Failure) $($_.Failure)"
                            } | & $script:Export -Name "$section-POLICY"
                        }
            
                        [ordered]@{
                            'Status' = "Evidence Collected"
                        } | & $script:Export -Name $section -IsSummary
                    } else {
                        [ordered]@{
                            'Status' = "Evidence Failed"
                        } | & $script:Export -Name $section -IsSummary
                    }
            
                    $null = $auditpol::AuditFree($buffer)
            
                } catch {
                    LogThis -m "Failed checking audit policies: $_" -lvl Error
                    [ordered]@{
                        'Status' = $ope
                    } | & $script:Export -Name $section -IsSummary
                }
            }

            'COMPUTERS' = {
                $rawComputers = Get-ADComputer -Filter * -Properties * -Server $script:ADDomain.PDCEmulator
                $rawComputers | & $script:ExportRaw
                try {
                    $computers = Get-ADComputer -Filter * -Properties @(
                        'Name', 'DistinguishedName', 'OperatingSystem', 
                        'OperatingSystemVersion', 'LastLogonDate', 'Enabled',
                        'TrustedForDelegation', 'whenCreated'
                    ) -Server $script:ADDomain.PDCEmulator
                    
                    $computers | & $script:ExportRaw

                    if ($computers) {
                        $computers | & $script:Export -Name $section

                        $osCounts = $computers | Group-Object { "$($_.OperatingSystem) ($($_.OperatingSystemVersion))" } | 
                            Select-Object @{N='OS';E={$_.Name}}, Count

                        [ordered]@{
                            'Summary (+)' = ($osCounts | ForEach-Object { "($($_.OS)) $($_.Count)" }) -join ', '
                        } | & $script:Export -Name $section -IsSummary
                    } else {
                        [ordered]@{
                            'Summary (+)' = "(None) 0"
                        } | & $script:Export -Name $section -IsSummary
                    }
                } catch {
                    LogThis -m "Failed gathering computers: $_" -lvl Error
                    [ordered]@{
                        'Summary (+)' = $ope
                    } | & $script:Export -Name $section -IsSummary
                }
            }

            'SPOOLER' = {
                $script:DCs | ForEach-Object { Get-WmiObject -Class Win32_Service -Filter "Name='Spooler'" -ComputerName $_.Name} | & $script:ExportRaw
                try {
                    $spoolerInfo = $script:DCs | ForEach-Object {
                        try {
                            $spoolerService = Get-Service -ComputerName $_.Name -Name Spooler
                            $startupConfig = (Get-WmiObject -Class Win32_Service -Filter "Name='Spooler'" -ComputerName $_.Name).StartMode
                            
                            [PSCustomObject][ordered]@{
                                'Default' = "(DC) $($_.Name), (Site) $($_.Site)"
                                'Status (+)' = "(Running) $($spoolerService.Status), (Startup) $startupConfig"
                            } | & $script:Export -Name $section
                        } catch {
                            LogThis -m "Spooler check failed: $($_.Name): $_" -lvl Warn
                            [PSCustomObject][ordered]@{
                                'Default' = "(DC) $($_.Name), (Site) $($_.Site)"
                                'Status (+)' = "(Running) $not, (Startup) $not"
                            } | & $script:Export -Name $section
                        }
                    }
                    
                    $spoolerInfo | & $script:ExportRaw

                    [ordered]@{
                        'Summary (+)' = "(Total) $($script:DCs.Count), (Running) $(($spoolerInfo | Where-Object { $_.Status -eq 'Running' } | Measure-Object).Count), (Stopped) $(($spoolerInfo | Where-Object { $_.Status -eq 'Stopped' } | Measure-Object).Count), (Disabled) $(($spoolerInfo | Where-Object { $_.Startup -eq 'Disabled' } | Measure-Object).Count)"
                    } | & $script:Export -Name $section -IsSummary

                } catch {
                    LogThis -m "Failed checking spooler: $_" -lvl Error
                    [ordered]@{
                        'Summary (+)' = "(Total) $ope, (Running) $ope, (Stopped) $ope, (Disabled) $ope"
                    } | & $script:Export -Name $section -IsSummary
                }
            }

            'NETWORK' = {
                $script:DCs | ForEach-Object { Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name *;Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name *;Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\LSA\MSV1_0" -Name *} | & $script:ExportRaw

                try {
                    $registryKeys = @(
                        @{
                            Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
                            Keys = @("RestrictNullSessAccess", "NullSessionShares")
                        },
                        @{
                            Path = "HKLM:\System\CurrentControlSet\Control\Lsa"
                            Keys = @("RestrictAnonymousSAM", "RestrictAnonymous", "EveryoneIncludesAnonymous")
                        },
                        @{
                            Path = "HKLM:\System\CurrentControlSet\Control\LSA\MSV1_0"
                            Keys = @("allownullsessionfallback")
                        }
                    )

                    $results = @()
                    foreach ($dc in $script:DCs) {
                        LogThis -m "Gathering registry for $($dc.Name)"
                        
                        foreach ($reg in $registryKeys) {
                            foreach ($key in $reg.Keys) {
                                try {
                                    $value = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                                        param($path, $key)
                                        try {
                                            $val = Get-ItemProperty -Path $path -Name $key
                                            if ($null -eq $val.$key) { return "<null>" }
                                            return $val.$key
                                        } catch {
                                            return "Not Found"
                                        }
                                    } -ArgumentList $reg.Path, $key

                                    $results += [PSCustomObject]@{
                                        Server = $dc.Name
                                        Key = $key
                                        Value = $value
                                    }

                                } catch {
                                    LogThis -m "Failed checking registry on $($dc.Name) for $key : $_" -Level WARN
                                    $results += [PSCustomObject]@{
                                        Server = $dc.Name
                                        Key = $key
                                        Value = "Error: Unable to connect"
                                    }
                                }
                            }
                        }

                        try {
                            $lsaValue = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                                $tempPath = Join-Path $env:TEMP "secexport.cfg"
                                try {
                                    $null = secedit /export /cfg $tempPath
                                    if (Test-Path $tempPath) {
                                        $content = Get-Content $tempPath
                                        $lookup = $content | Select-String "LSAAnonymousNameLookup"
                                        $value = if ($lookup) { $lookup.ToString().Split('=')[1].Trim() } else { "Not Found" }
                                        Remove-Item -Path $tempPath -Force
                                        return $value
                                    }
                                    return "Export Failed"
                                } catch {
                                    if (Test-Path $tempPath) { Remove-Item -Path $tempPath -Force }
                                    return "Error: $_"
                                }
                            }

                            $results | & $script:ExportRaw

                            $results += [PSCustomObject]@{
                                Server = $dc.Name
                                Key = "LSAAnonymousNameLookup"
                                Value = $lsaValue
                            }

                        } catch {
                            LogThis "Failed secedit export on $($dc.Name)" -lvl Warn -ex $_
                            $results += [PSCustomObject]@{
                                Server = $dc.Name
                                Key = "LSAAnonymousNameLookup"
                                Value = "Error: Unable to connect"
                            }
                        }
                    }

                    $results | Select-Object Server, Key, Value | Export-Csv -Path "$($script:Paths.Export)\$section.csv" -NoTypeInformation

                    $summary = foreach ($key in ($results | Select-Object -ExpandProperty Key -Unique | Sort-Object)) {
                        $keyResults = $results | Where-Object Key -eq $key
                        $enabled = ($keyResults | Where-Object { $_.Value -eq 1 }).Count
                        $disabled = ($keyResults | Where-Object { $_.Value -eq 0 }).Count
                        $errors = ($keyResults | Where-Object { $_.Value -like 'Error:*' -or $_.Value -eq 'Not Found' }).Count
                        
                        [PSCustomObject][ordered]@{
                            Key = $key
                            Summary = "Enabled: $enabled, Disabled: $disabled" + $(if($errors -gt 0) { ", Errors: $errors" })
                        }
                    }

                    $summary | Export-Csv -Path "$($script:Paths.Export)\$section-summary.csv" -NoTypeInformation

                } catch {
                    LogThis -m "Failed checking network registry settings: $_" -lvl Error
                    "Operation Failed" | Out-File -FilePath "$($script:Paths.Export)\$section-summary.csv"
                }
            }

            <#'CERTIFICATES' = {
                try {
                    $caCheck = certutil -CA
                    if ($LASTEXITCODE -eq 0) {
                        LogThis -m "ADCS found: $($caCheck[0])"

                        LogThis -m "Verifying PSPKI module" -show "Verifying PSPKI module"
                        GetPrerequisites -Verify $script:CertModule
                        
                        LogThis -m "Processing CAs" -show "CERTIFICATES"
                        $cas = Get-CertificationAuthority
                        if ($cas) {
                            LogThis -m "CAs found: $($cas.Count)"
                            $authorities = @(foreach ($ca in $cas) {
                                LogThis -m "Processing: $($ca.Name), $i of $($cas.Count)"
                                
                                $endpointDetails = if ($ca.EnrollmentEndpoints) {
                                    $ca.EnrollmentEndpoints | ForEach-Object {
                                        $isHttps = $_.Uri -like "https://*"
                                        $usesNTLM = $_.Authentication -like "*NTLM*"
                                        
                                        "EndpointUri=$($_.Uri); IsHttps=$isHttps; Auth=$($_.Authentication); UsesNTLM=$usesNTLM"
                                    }
                                }
                                $enrollmentEndpoints = if ($endpointDetails) { $endpointDetails -join " | " } else { $not }
                                
                                @{
                                    Name               = $ca.Name
                                    DisplayName        = $ca.DisplayName
                                    ComputerName       = $ca.ComputerName
                                    Type               = $ca.Type
                                    IsEnterprise       = $ca.IsEnterprise
                                    IsRoot             = $ca.IsRoot
                                    IsAccessible       = $ca.IsAccessible
                                    RegistryOnline     = $ca.RegistryOnline
                                    ServiceStatus      = $ca.ServiceStatus
                                    Ping               = $ca.Ping()
                                    PingAdmin          = $ca.PingAdmin()
                                    PingRequest        = $ca.PingRequest()
                                    SetupStatus        = $ca.SetupStatus
                                    ConfigString       = $ca.ConfigString
                                    EnrollmentEndpoints = $enrollmentEndpoints
                                    EnrollmentPrincipals = ($ca.EnrollmentPrincipals -join ", ")
                                    DistinguishedName  = $ca.DistinguishedName
                                    Certificate        = $ca.Certificate
                                    OS                 = $ca.OperatingSystem
                                }
                            
                            })
                            $authorities | & $script:Export -Name "$section-AUTHORITY"
                            LogThis -m "Exported '$section-AUTHORITY'"
                            [ordered]@{
                                'Total' = ($authorities | Measure-Object).Count
                                'Root' = ($authorities | Where-Object { $_.IsRoot }).Name
                                'Enterprise' = ($authorities | Where-Object IsEnterprise | Select-Object -ExpandProperty Name -Unique) -join ', ' -replace '^$', 'None found'
                                'Stand-Alone' = ($authorities | Where-Object { -not $_.IsEnterprise } | Select-Object -ExpandProperty Name -Unique) -join ', ' -replace '^$', 'None found'
                                'Subordinate' = ($authorities | Where-Object { $_.IsEnterprise -and -not $_.IsRoot } | Select-Object -ExpandProperty Name -Unique) -join ', ' -replace '^$', 'None found'
                                'Accessible' = ($authorities | Where-Object IsAccessible | Select-Object -ExpandProperty Name -Unique) -join ', ' -replace '^$', 'None found'
                            } | & $script:Export -Name "$section-AUTHORITY" -IsSummary
                            LogThis -m "Exported '$section-AUTHORITY'-IsSummary"
                        } else {
                            LogThis -m "No CAs found on second attempt" -lvl Warn
                            [PSCustomObject][ordered]@{
                                'Status' = "No CAs found on second attmpt"
                            } | & $script:Export -Name "$section-AUTHORITY-NONE-FOUND"
                        }

                    # Templates
                        LogThis -m "Processing Certificate Templates" -show "Certificate Templates"
                        $Templates = Get-CertificateTemplate
                        if ($Templates) {
                            LogThis -m "Templates found: $($Templates.Count)"
                            $LowPrivilegedGroups = "Domain Users|Authenticated Users|Everyone"
                            
                            $filteredResults = @(foreach($Template in $Templates) {
                                LogThis -m "Analyzing: $($Template.Name)"
                                
                                $TemplateDACL = Get-ADObject -Identity $Template.DistinguishedName -Properties nTSecurityDescriptor |
                                    Select-Object -ExpandProperty nTSecurityDescriptor
                                
                                $EnrollmentRights = $TemplateDACL.Access | Where-Object {
                                    ($_.ActiveDirectoryRights -match "ExtendedRight" -or 
                                    $_.ActiveDirectoryRights -match "GenericAll")
                                }
                                
                                $LowPrivilegedEnrollment = $EnrollmentRights | Where-Object {
                                    $_.IdentityReference -match $LowPrivilegedGroups
                                }

                                $TemplateProps = Get-ADObject -Identity $Template.DistinguishedName -Properties * 

                                # Check if template has sensitive capabilities
                                $SensitiveKeyUsage = @(
                                    # Has authentication EKUs
                                    [bool]($TemplateProps.'pKIExtendedKeyUsage' | Where-Object { 
                                        $_ -in @(
                                            "1.3.6.1.5.5.7.3.2",    # Client Authentication
                                            "1.3.6.1.5.2.3.4",      # PKINIT Client Authentication
                                            "1.3.6.1.4.1.311.20.2.2" # Smart Card Logon
                                        )
                                    }),
                                    # Has dangerous EKUs
                                    [bool]($TemplateProps.'pKIExtendedKeyUsage' -contains "2.5.29.37.0" -or 
                                        $null -eq $TemplateProps.'pKIExtendedKeyUsage'),
                                    # Allows SAN specification
                                    [bool]($TemplateProps.'msPKI-Certificate-Name-Flag' -band 0x00000001)
                                ) -contains $true

                                # Check for CA Manager Approval requirement
                                $CAManagerApproval = [bool]($TemplateProps.'msPKI-Enrollment-Flag' -band 0x02)

                                # Determine risk level
                                $riskLevel = if ($SensitiveKeyUsage -and $LowPrivilegedEnrollment -and !$CAManagerApproval) {
                                    "CRITICAL - Authentication keys with broad enrollment, no manager approval"
                                } elseif ($SensitiveKeyUsage -and $LowPrivilegedEnrollment) {
                                    "HIGH - Authentication keys with broad enrollment, requires approval"
                                } elseif ($LowPrivilegedEnrollment) {
                                    "MEDIUM - Broad enrollment rights"
                                } elseif ($SensitiveKeyUsage) {
                                    "LOW - Authentication keys with limited enrollment"
                                } else {
                                    "INFO - Limited enrollment scope"
                                }

                                @{
                                    'Name' = $Template.Name
                                    'SensitiveKeyUsage' = $SensitiveKeyUsage
                                    'LowPrivilegedEnrollment' = [bool]$LowPrivilegedEnrollment
                                    'CAManagerApproval' = $CAManagerApproval
                                    'EnrollmentPrincipals' = ($EnrollmentRights | ForEach-Object {
                                        "$($_.IdentityReference)"
                                    }) -join ', '
                                    'EnhancedKeyUsage' = ($TemplateProps.'pKIExtendedKeyUsage' -join ', ')
                                    'Risk' = $riskLevel
                                }
                            })
                            $filteredResults | & $script:Export -Name "$section-TEMPLATES"
                            LogThis -m "Exported '$section-TEMPLATES'"
                            # Generate and export summary
                            [ordered]@{
                                'Total' = ($filteredResults | Measure-Object).Count
                                'Sensitive' = ($filteredResults | Where-Object { $_.SensitiveKeyUsage }).Count
                                'Critical' = ($filteredResults | Where-Object { $_.Risk -like "CRITICAL*" }).Count
                                'High' = ($filteredResults | Where-Object { $_.Risk -like "HIGH*" }).Count
                                'Medium' = ($filteredResults | Where-Object { $_.Risk -like "MEDIUM*" }).Count
                                'Low' = ($filteredResults | Where-Object { $_.Risk -like "LOW*" }).Count
                                'Info' = ($filteredResults | Where-Object { $_.Risk -like "INFO*" }).Count
                            } | & $script:Export -Name "$section-TEMPLATES" -IsSummary
                            LogThis -m "Exported '$section-TEMPLATES'-IsSummary"
                        } else {
                            [PSCustomObject][ordered]@{
                                'Status' = "No Templates found on second attempt"
                            } | & $script:Export -Name "$section-TEMPLATES-NONE-FOUND"
                            
                            [ordered]@{
                                'Status' = "No Templates found" 
                            } | & $script:Export -Name "$section-TEMPLATES" -IsSummary
                            LogThis -m "Exported '$section-TEMPLATES'-IsSummary"
                        }

                    # NTAuth  
                        LogThis -m "Processing NTAuth Certificates" -show "NTAuth Certificates"
                        $domain = (Get-ADDomain).DNSRoot
                        if ($domain) {
                            $ntAuthPath = "CN=NtAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$($domain -replace '\.',',DC=')"
                            $ntAuthCertificates = @(Get-ADObject -Filter * -SearchBase $ntAuthPath -Properties * | 
                                Select-Object CanonicalName, CN, Created, Description, DisplayName, objectClass)
                            $ntAuthCertificates | & $script:Export -Name "$section-NTAUTH"
                            LogThis -m "Exported '$section-NTAUTH'"
                            [ordered]@{
                                'Total' = ($ntAuthCertificates).Count
                            } | & $script:Export -Name "$section-NTAUTH" -IsSummary
                            LogThis -m "Exported '$section-NTAUTH'-IsSummary"
                        } else {
                            [ordered]@{
                                'Status' = "No NTAuth Certificates found"
                            } | & $script:Export -Name "$section-NTAUTH-NONE-FOUND"
                            LogThis -m "Exported '$section-NTAUTH-NONE-FOUND'"
                            [ordered]@{ 
                                'Status' = "No NTAuth Certificates found" 
                            } | & $script:Export -Name "$section-NTAUTH" -IsSummary
                            LogThis -m "Exported '$section-NTAUTH'-IsSummary"
                        }

                    # Logging
                        LogThis -m "Processing CA Logging Configuration" -show "CA Logging"
                        $logging = @(foreach ($ca in $cas) {
                            LogThis -m "Auditing logging for: $($ca.ComputerName)" -lvl Debug

                            # Category Logging (Success & Failure)
                            $auditPolicy = try { 
                                $output = auditpol /get /subcategory:"Certification Services" | Out-String
                                if ($output -match 'Certification Services\s+(.+)$') {
                                    $matches[1].Trim()
                                    LogThis -m "Audit Policy: $($matches[1].Trim())" -lvl Debug
                                } else {
                                    "No policy found"
                                    LogThis -m "No policy found" -lvl Debug
                                }
                            } catch { 
                                "Error: $($_.Exception.Message)"
                            }

                            # Subcategory Logging (127)
                            $auditConfig = try {
                                $output = certutil -getreg CA\AuditFilter | Out-String
                                if ($output -match 'AuditFilter REG_DWORD = ([\da-fA-F]+)') {
                                    $value = $matches[1]
                                    switch ($value) {
                                        "0" { "No auditing configured" }
                                        "1" { "Success auditing only" }
                                        "2" { "Failure auditing only" }
                                        "3" { "Success and failure auditing" }
                                        default { "Unknown configuration: $value" }
                                    }
                                } else {
                                    "No configuration found"
                                }
                            } catch {
                                "Error: $($_.Exception.Message)"
                            }

                            # Subcategory supercedes category (1)
                            $scePolicy = try { 
                                $value = Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy'
                                if ($null -eq $value) { "Not configured" } else { $value }
                            } catch {
                                if ($_.Exception.Message -match "Property SCENoApplyLegacyAuditPolicy does not exist") {
                                    "Not configured"
                                } else {
                                    "Error: $($_.Exception.Message)"
                                }
                            }

                            # Result Object
                            @{
                                Name = $ca.ComputerName
                                SCEPolicy = $scePolicy
                                AuditPolicy = $auditPolicy
                                AuditConfiguration = $auditConfig
                                HasSCEPolicy = $scePolicy -notmatch "Error|Not configured"
                                HasAuditPolicy = $auditPolicy -match "Success|Failure"
                                HasAuditConfig = $auditConfig -match "Success|Failure"
                            }
                        }) 
                        $logging | & $script:Export -Name "$section-LOGGING"
                        LogThis -m "Exported '$section-LOGGING'"
                        [ordered]@{
                            'CAs' = ($cas | Measure-Object).Count
                            'Compliant' = ($logging | Where-Object { 
                                $_.HasSCEPolicy -and $_.HasAuditPolicy -and $_.HasAuditConfig 
                            } | Measure-Object).Count
                            'Compliant SCE' = ($logging | Where-Object HasSCEPolicy | Measure-Object).Count
                            'Compliant Policy' = ($logging | Where-Object HasAuditPolicy | Measure-Object).Count
                            'Compliant Config' = ($logging | Where-Object HasAuditConfig | Measure-Object).Count
                        } | & $script:Export -Name "$section-LOGGING" -IsSummary

                        # Generate detailed audit log
                        $auditLog = foreach ($ca in $logging) {
                            "CA: $($ca.Name)"
                            "SCE Policy: $($ca.SCEPolicy)"
                            "Audit Policy: $($ca.AuditPolicy)"
                            "Audit Configuration: $($ca.AuditConfiguration)"
                            "----------------------------------------"
                        }

                        # Export audit log
                        $auditLog | Out-File -FilePath (Join-Path $script:Directory "$($script:Filename)-$section-audit.txt") -Encoding UTF8

                    } else {
                        LogThis -m "ADCS not found (Exit Code: $LASTEXITCODE)" -lvl Info
                        [ordered]@{
                            'Status' = "ADCS not installed"
                        } | & $script:Export -Name "$section-NONE-FOUND" -IsSummary
                    }
                } catch {
                    LogThis -m "Certificate processing failed" -lvl Error -ex $_
                    [ordered]@{
                        'Status' = "Error: $($_.Exception.Message)"
                    } | & $script:Export -Name "$section-ERROR" -IsSummary
                }
            }#>
        }
        
        $sectionsToProcess = $Controls.Keys
        foreach ($section in $sectionsToProcess) {
            $script:SectionCounter++  # Add counter increment here
            LogThis -m "Processing: $section ($script:SectionCounter)" -show "$($section)"
            
            try {  # Nest each scriptblock in a try/catch
                $scriptBlock = $Controls[$section]
                if ($scriptBlock -is [ScriptBlock]) {
                    
                    $wrappedBlock = { # Wrap scriptblocks
                        $result = & $scriptBlock
                        if ($result -is [hashtable] -and $result -isnot [System.Collections.Specialized.OrderedDictionary]) { # Enforce ordered hashtables
                            [ordered]@{} + $result
                        } else {
                            $result
                        }
                    }
                    $result = & $wrappedBlock # Store scriptblock return value
                } else {
                    LogThis -m "Error processing: $section" -lvl warn -ex $_
                    [ordered]@{
                        'Status' = $_.Exception.Message
                    } | & $script:Export -Name $section -IsSummary
                }
            } catch {
                LogThis -m "$section failed" -lvl Warn -ex $_
                [ordered]@{
                    'Status' = $_.Exception.Message
                } | & $script:Export -Name $section -IsSummary
            }
        }

        LogThis -m "Controls successfully completed" -lvl Debug -show "COMPLETE"

    } catch {
        LogThis -m "Get-ActiveDirectory" -lvl Warn -ex $_ - show "Error gathering Active Directory details"
    }
}

function Initialize{
    [CmdletBinding()]
    param(
    )

    LogThis -m "Delcare core variables"
    Get-Variable script:* | Remove-Variable -Force
    $script:SectionCounter = 0
    $script:ProcessedSections = [System.Collections.Generic.HashSet[string]]::new()
    $script:StartTime = [System.DateTime]::UtcNow
    $script:RequiredModules = $RequiredModules
    $script:CertModule = $CertModule   
    $script:Version = $Version
    $script:Directory = $Directory # from global script param
    try {
        $script:ADDomain = Get-ADDomain
        $script:Filename = "$($script:ADDomain.DNSRoot)_$(& $script:Format (Get-Date) -Format File)" # Get-ADDomain succeeded
    } catch {
        $script:Filename = "$($env:COMPUTERNAME)_$(& $script:Format (Get-Date) -Format File)"        # Get-ADDomain failed
    }
    $script:Log = Join-Path $script:Directory "$($script:Filename).log"
    $script:Archive = Join-Path (Split-Path $script:Directory) "$($script:Filename).zip"

    # 2. Initalize log file
    try {
        if (-not (Test-Path $script:Directory)) {
            New-Item -Path $script:Directory -ItemType Directory -Force | Out-Null
            LogThis -m "Created: $($script:Directory)"
        }
        
        "=== BRAVE Assessment Started ===" | Set-Content -Path $script:Log -Force -Encoding UTF8
        LogThis -m "Initalized $($script:Log)"
    } catch {
        LogThis "Failed initalizing $($script:Log)" -lvl Error -ex $_
        return
    }

    try {
        if (Test-Path $script:Directory) {
            Get-ChildItem -Path $script:Directory -Exclude "$($script:Filename).log" | 
                Remove-Item -Recurse -Force -Confirm:$false
            LogThis -m "Cleaned up previous run"
        }
        
        New-Item -Path $script:Directory -ItemType Directory -Force | Out-Null
        LogThis -m "Created $($script:Directory)"
    } catch {
        LogThis -m "Failed creating $($script:Directory)" -lvl Error -ex $_ -show "Failed creating BRAVE directory"
    }

    
    # 3. Inialize Active Directory
    LogThis -m "Initializing AD varaibles"
    
    $script:LogonAge = 90 # Stale age thresholds
    $script:PasswordAge = 90 # Stale age thresholds
    try {
        try {
            $script:ADForest = Get-ADForest
            LogThis -m "Foret: $($script:ADForest)" -lvl Debug
        } catch {
            LogThis -m "Get-ADForest failed" -lvl Error -ex $_
        }
            
        try {
            $script:DCs = Get-ADDomainController -Server $script:ADDomain.PDCEmulator -Filter * | 
            Select-Object HostName, Name, Enabled, OperationMasterRoles, 
                OperatingSystem, OperatingSystemVersion, ComputerObjectDN, 
                IsGlobalCatalog, IsReadOnly, IPv4Address, Site
        } catch {
            LogThis -m "Get-ADDomainController failed" -lvl Error -ex $_
        }

        try {
            $script:PrivilegedGroups = @{ # Privileged groups for recursive lookups
            "Schema Admins"     = "$($script:ADDomain.DomainSID.Value)-518" # Universal
            "Enterprise Admins" = "$($script:ADDomain.DomainSID.Value)-519" # Universal
            "Domain Admins"     = "$($script:ADDomain.DomainSID.Value)-512" # Global
            "Protected Users"   = "$($script:ADDomain.DomainSID.Value)-525" # Global
            "(Built-in) Administrators"    = "S-1-5-32-544"                 # Built-in
            "(Built-in) Server Operators"   = "S-1-5-32-549"                # Built-in
            "(Built-in) Hyper-V Administrators" = "S-1-5-32-578"            # Built-in
            "(Built-in) Remote Desktop Users" = "S-1-5-32-555"              # Built-in alias
            }
        } catch {
            LogThis -m "Privileged groups" -lvl Error -ex $_
        }
    } catch {
        LogThis -m "Failed AD initalization" -lvl Error -ex $_ -show "Failed initalizing Active Directory"
        return $false
    }
    
    # 4. Initalize user & computer property lists
    $script:UserProperties = @(
        'SAMAccountname', 'Enabled', 'Name','DisplayName', 'LastLogonDate', 'Created',
        'Modified', 'AccountExpirationDate','PasswordLastSet', 'PasswordNeverExpires',
        'PasswordNotRequired', 'PasswordExpired','CannotChangePassword',
        'LastBadPasswordAttempt','badpwdcount', 'logonWorkStations',
        'AdminCount', 'UserAccountControl','DoesNotRequirePreAuth',
        'msDS-SupportedEncryptionTypes','DistinguishedName',
        'CanonicalName', 'ServicePrincipalName'
    )

    $script:ComputerProperties = @(
        'Name', 'DistinguishedName', 'OperatingSystem', 'OperatingSystemVersion', 
        'LastLogonDate', 'Enabled','TrustedForDelegation', 'whenCreated'
    )

     # 5. Broadcast Status
     $summary = @(
        "SCRIPT: v$script:Version"
        "START:  $(& $script:Format $script:StartTime -Format Display)"
    ) -join "`n"

    $details = @(
        "HOST:   $env:COMPUTERNAME"
        "OS:     $((Get-CimInstance -ClassName Win32_OperatingSystem).Caption)"
        "USER:   $([Security.Principal.WindowsIdentity]::GetCurrent().Name)"
        "OUTPUT: $script:Directory"
        "LOG:    $script:Log"
        "PS APP: $($Host.Name)"
        "PS CALL: $($MyInvocation.InvocationName)"
        "PS PTH: $($PSCommandPath)"
        "PS CMD: $($MyInvocation.MyCommand.Name)"
        "FOREST: $($script:ADForest.Name)"
        "DOMAIN: $($script:ADDomain.DNSRoot)"
        "PDC:    $($script:ADDomain.PDCEmulator)"
        "DCs:    $($script:DCs.Count)"
    ) -join "`n"

    LogThis -m "$($details)" -lvl Status -show "$($summary)"

    # 5. Prereqs
    LogThis -m "Checking prerequisites" -show "CHECKING PREREQUISITES" -lvl Header
    GetPrerequisites -Verify $script:RequiredModules
    
}

function BRAVE {
    [CmdletBinding()]
    param (
        [string[]]$Functions
    )

    LogThis -m "BRAVE running"
    
    try {
        # 1. Discover functions to turn into scriptblocks
        LogThis -m "Discovering Get-* functions"
        LogThis -m "Script Path: $($PSCommandPath)" -lvl Debug

        $getFunctions = Get-Command -CommandType Function | 
            Where-Object {
                $_.ScriptBlock.File -eq $PSCommandPath -and 
                $_.Name -like 'Get-*'
            }
                    
        $scriptblocks = @($getFunctions | ForEach-Object { [scriptblock]::Create($_.Name) })
        $functionNames = $scriptblocks | ForEach-Object { $_.ToString() }
        LogThis -m "Executing: $($functionNames -join ', ')" -lvl Debug

        # 2. Initialize progress bar
        $progressParams = @{
            Activity = "Executing BRAVE Assessment"
            Status = "Starting..."
            PercentComplete = 0
        }
        Write-Progress @progressParams

        # 3. Execute scriptblocks
        $total = $scriptblocks.Count
        foreach ($i in 0..($total-1)) {
            $command = $scriptblocks[$i]
            $percentComplete = ($i / $total) * 100
            
            $progressParams.Status = "Running $($command.ToString())"
            $progressParams.PercentComplete = $percentComplete
            Write-Progress @progressParams

            LogThis -m "Running: $($command.ToString())" -lvl Debug

            try {
                & $command
            }
            catch {
                LogThis -m "Failed: $($command.ToString())" -lvl Warn -ex $_
            }
        }

        # 4. Create archive file
        LogThis -m "Creating archive file" -show "CREATING ARCHIVE FILE" -lvl Header

        try {
            $itemsToArchive = @()
            $itemsToArchive += @(Get-ChildItem -Path $script:Directory -File)
            $itemsToArchive += @(Get-ChildItem -Path $script:Directory -Directory | 
                Where-Object { $_.FullName -ne $script:GPODirectory })

            LogThis -m "Archiving $($itemsToArchive.Count) files" -lvl Info
            LogThis -m "Archiving: $($itemsToArchive.Name -join ', ')" -lvl Debug

            if ($itemsToArchive.Count -gt 0) {
                try {
                    $nonLogFiles = $itemsToArchive | Where-Object { $_.FullName -ne $script:Log }
                    if ($nonLogFiles) {
                        Compress-Archive -Path $nonLogFiles.FullName -DestinationPath $script:Archive -Force
                        LogThis -m "Added: $($nonLogFiles.FullName -join ', ')" -lvl Debug
                        Start-Sleep -Milliseconds 500
                    }
                } catch {
                    LogThis -m "Failed creating zip" -lvl Warn -ex $_ -show "Failed Creating Archive File"
                }
            }

            if (Test-Path $script:GPODirectory) {
                try {
                    Compress-Archive -Path $script:GPODirectory -DestinationPath $script:Archive -Update
                    LogThis -m "Added $($script:GPODirectory) to $($script:Archive)" -lvl Debug
                    Start-Sleep -Milliseconds 500
                } catch {
                    LogThis -m "Failed adding $($script:GPODirectory) to $($script:Archive)" -lvl Warn -ex $_
                }
            }

            try {
                Compress-Archive -Path $PSCommandPath -DestinationPath $script:Archive -Update
                LogThis -m "Added $($PSCommandPath) to $($script:Archive)" -lvl Debug
                Start-Sleep -Milliseconds 250
            } catch {
                LogThis -m "Failed adding $($PSCommandPath) to $($script:Archive)" -lvl Warn -ex $_
            }

            $duration = [datetime]::UtcNow - $script:StartTime
            $durationFormatted = if ($duration.TotalHours -ge 1) {
                $duration.ToString('hh\:mm\:ss')
            } else {
                $duration.ToString('mm\:ss')
            }

            $summary = @(
                "STARTED:  $(& $script:Format $script:StartTime -Format Display)"
                "FINISHED: $(& $script:Format (Get-Date) -Format Display)"
                "DURATION: $durationFormatted"
                "CREATED:  $script:Archive"
            ) -join "`n"

            LogThis  -m "$summary" -lvl Info -show "$summary"
            LogThis -m "=== BRAVE Assessment Complete ==="
            Start-Sleep -Milliseconds 500

            Compress-Archive -Path $script:Log -DestinationPath $script:Archive -Update
            LogThis -m "Added $($script:Log) to $($script:Archive)"
            Start-Sleep -Milliseconds 500

            if (Test-Path $script:Archive) { # Verify archive and cleanup
                if (& $script:Validate -Path $script:Archive) {
                    try {
                        Get-ChildItem -Path $script:Directory -Exclude (Split-Path $script:Log -Leaf) |
                            Remove-Item -Recurse -Force -Confirm:$false
                        Remove-Item -Path $script:Log -Force -Confirm:$false
                        Remove-Item -Path $script:Directory -Force -Confirm:$false
                    }
                    catch {
                        LogThis -m "Failed post cleanup" -lvl Error -ex $_
                    }
                } else {
                    LogThis -m "Archive validation failed - skipping cleanup" -lvl Error -ex $_ -show "Invalid archive"
                }
            } else {
                LogThis -m "Archive not found - skipping post-run cleanup" -lvl Warn -ex $_
            }
        } catch {
            LogThis -m "Error creating archive" -lvl Error -ex $_ -show "Unable to create archive"
        }
    } catch {
        LogThis -m "BRAVE failed" -lvl Warn -ex $_ -show "BRAVE execution failed"
    }
    finally {
        Write-Progress -Activity "Executing BRAVE Script" -Completed
    }
}

try {
    LogThis -m "Main script block executing"
    Initialize
    BRAVE
} 
catch {
    LogThis -m "Main script block failed" -lvl Error -ex $_ -show "BRAVE failed executing"
}