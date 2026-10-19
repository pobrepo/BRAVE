
# ============================================================================
# BRAVE v4.4 - Active Directory security evidence collection script
#
# What it does
#   Runs a series of read-only checks against the current Active Directory
#   domain (users, groups, GPOs, trusts, delegation, password policy, audit
#   policy, certificate services and more). Results are written to CSV files
#   plus a log, then bundled into a single zip file.
#
# Requirements
#   - PowerShell 5 or higher, run as Administrator
#   - ActiveDirectory and GroupPolicy modules (RSAT). PSPKI is installed
#     automatically from the PowerShell Gallery if certificate checks are needed.
#
# Parameters
#   -Directory  Working/output folder (default c:\temp\BRAVE\)
#   -Duo        Also query the Duo Admin API (prompts for credentials)
#   -Proxy      Also collect a Duo Authentication Proxy config (prompts for server)
#
# Output
#   A zip file in the parent of the output folder, named <domain>_<timestamp>.zip.
#   The working folder is deleted once the zip is verified.
# ============================================================================
 
[CmdletBinding()]
param(
    # Output folder. If it doesn't exist yet, create it. Fail if it can't be created.
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
    [string]$Directory = "c:\temp\BRAVE\",
    # Optional switches (see header at the top of the file)
    [switch]$Duo,
    [switch]$Proxy,
    [switch]$Dns
)
 
# Script version and global settings. Errors are silenced so one failed check does not stop the whole run.
$Version = "4.4"
$ErrorActionPreference = "SilentlyContinue"
$script:StartTime = Get-Date
# PowerShell modules the script needs. PowerDuo is only added when -Duo is used.
$RequiredModules = ('ActiveDirectory', 'GroupPolicy')
if ($Duo) {
    $RequiredModules += 'PowerDuo'
}
# PSPKI is used for the certificate services (ADCS) checks. GPO reports get their own subfolder.
$CertModule = "PSPKI"
$GPODirectory = (Join-Path $Directory "GPO")
 
# LogThis - central logging helper.
# Writes a timestamped entry to the log file. Add -show to also print a colored
# message to the screen. Pass -ex with an error record to log full exception details.
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
 
# Format-PartitionBackup - reformats a backup string into 'date [YyMmDd]'. Not currently called anywhere in this script.
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
 
# GetPrerequisites - makes sure the required PowerShell modules are available.
# Installs any that are missing, imports them (with retries) and reports what is still missing.
function GetPrerequisites {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Verify
    )
    
    LogThis -m "Checking modules: $($Verify -join ', ')"
    $RequiredModules = $Verify.Clone()
    LogThis -m "Required modules: $($RequiredModules -join ', ')"
    # If the RSAT feature is already installed, the ActiveDirectory module doesn't need to be installed separately
    try {
        $RSATInstalled = (Get-WindowsFeature -Name RSAT-AD-PowerShell).Installed
        if ($RSATInstalled) {
            $RequiredModules = $RequiredModules -notmatch "ActiveDirectory"
            LogThis -m "RSAT pre-installed; ActiveDirectory removed from list"
        }
    } catch {
        LogThis -m "Unable to verify RSAT " -lvl Warn
    }
 
    # Skip any modules that are already loaded in this session
    $ModulesLoaded = Get-Module | Where-Object { $_.Name -in $RequiredModules }
    $RequiredModules = $RequiredModules | Where-Object { $_ -notin $ModulesLoaded.Name }
    
    if ($ModulesLoaded) {
        LogThis -m "ModulesLoaded: $($ModulesLoaded.Name -join ', ')"
    }
 
    if ($RequiredModules.Count -gt 0) {
        LogThis -m "Processing modules: $($RequiredModules -join ', ')" -show "Installing Required Modules"
        
        # For each remaining module, install it if it isn't present on the machine
        foreach ($Module in $RequiredModules) {
            $ModuleAvailable = Get-Module -Name $Module -ListAvailable
            if (-not $ModuleAvailable) {
                try {
                    LogThis -m "Installing: $Module" -show "Installing: $Module"
                    Install-Module -Name $Module -Force -Scope CurrentUser
                    LogThis -m "$($Module): Install successful" -lvl Done
                } catch {
                    LogThis -m "$($Module): Install failed - $($_.Exception.Message)" -lvl Error -show "$($Module): Failed"
                    continue
                }
            } else {
                LogThis -m "$($Module): Already available" -lvl Done
            }
            
            # Import the module and retry up to 3 times if it doesn't load
            $ImportSuccess = $false
            $RetryCount = 0
            $MaxRetries = 3
            
            while (-not $ImportSuccess -and $RetryCount -lt $MaxRetries) {
                try {
                    LogThis -m "Importing: $Module (attempt $($RetryCount + 1))" -show "Importing: $Module"
                    Import-Module -Name $Module -Force
                    
                    Start-Sleep -Milliseconds 500
                    
                    $ImportedModule = Get-Module -Name $Module
                    if ($ImportedModule) {
                        LogThis -m "$($Module): Import successful" -lvl Done
                        $ImportSuccess = $true
                    } else {
                        throw "Module not found after import"
                    }
                } catch {
                    $RetryCount++
                    LogThis -m "$($Module): Import attempt $RetryCount failed - $($_.Exception.Message)" -lvl Warn
                    if ($RetryCount -lt $MaxRetries) {
                        Start-Sleep -Seconds 1
                    } else {
                        LogThis -m "$($Module): All import attempts failed" -lvl Error -show "$($Module): Failed"
                    }
                }
            }
        }
    }
 
    # Final check that every required module is now loaded
    $FinalModules = Get-Module | Where-Object { $_.Name -in $Verify }
    $Missing = $Verify | Where-Object { $_ -notin $FinalModules.Name }
    
    if ($Missing.Count -eq 0) {
        LogThis -m "All modules verified" -show "MODULES VERIFIED"
        LogThis -m "All modules verified" -lvl Done -show "`nCOMPLETED"
    } else {
        LogThis -m "Missing modules: $($Missing -join ', ')" -lvl Error -show "Prerequisites: Failed"
    }
}
 
# Export helper - takes objects from the pipeline and saves them to disk.
#   -IsSummary  adds rows to the shared summary CSV (one row per finding)
#   (default)   writes a detail CSV named <Section>-<Domain>.csv
#   -NoResults / -IsError  write an empty file with -NORESULTS or -ERROR in the name
$script:Export = {
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$InputObject,
        [Parameter(Mandatory)]
        [string]$Name,
        [string]$Description = $Name,
        [switch]$IsSummary,
        [switch]$NoResults,
        [switch]$IsError
    )
    begin {
        if (-not $script:ProcessedSections.Contains($Name)) {
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
            $summaryPath = Join-Path $script:Directory "summary-$($script:Filename).csv"
            $allEntries = if (Test-Path $summaryPath) {
                @(Import-Csv -Path $summaryPath) + @($summaryObjects)
            } else {
                $summaryObjects
            }
            $allEntries | Sort-Object { [int]$_.Order } |
                Export-Csv -Path $summaryPath -NoTypeInformation -Encoding UTF8
            $script:SummarySections += $summaryPath
        }
        if (-not $IsSummary) {
            $suffix = if ($IsError) { "-ERROR" } elseif ($NoResults) { "-NORESULTS" } else { "" }
            $detailPath = Join-Path $script:Directory "$Name-$($script:Filename)$suffix.csv"
            if ($detailedData) {
                $detailedData | Export-Csv -Path $detailPath -NoTypeInformation -Encoding UTF8
            } else {
                "" | Out-File -FilePath $detailPath -Encoding UTF8  # Create empty file
            }
            $script:ExportedFiles += $detailPath
        }
        if ($script:ExportedFiles.Count) {
            LogThis -m "File exported: $($script:ExportedFiles -join ', ')" -lvl Info
            $script:ExportedFiles = @()
        }
        if ($script:SummarySections.Count) {
            LogThis -m "Summary exported: $($script:SummarySections -join ', ')" -lvl Info
            $script:SummarySections = @()
        }
    }
}
 
 
# Format helper - cleans up values before export. Dates become UTC text and time spans become a number of days.
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
 
# Recursive group walker - lists every member of a group, including members of nested groups.
# Each result records the nesting path (for example Group A <- Group B) so you can see how
# an account got its access. Also fills in the $AccessPaths lookup used by the privileged group matrix.
$script:Recursive = {
    param (
        [string]$GroupSID,
        [string]$GroupName,
        [string]$SecurityGroup,
        [string]$ParentPath = "",
        [ref]$AccessPaths
    )
    try {
        $results = @()
        
        # Try to turn the SID into a readable group name (fall back to the SID if that fails)
        $groupIdentity = $GroupSID
        try {
            $groupObject = Get-ADGroup -Identity $GroupSID -Server $script:ADDomain.PDCEmulator -ErrorAction Stop
            $groupIdentity = $groupObject.Name
            LogThis -m "Resolved SID $GroupSID to group name: $groupIdentity" -lvl Debug
        } catch {
            LogThis -m "Could not resolve SID $GroupSID to group name, using SID directly" -lvl Debug
            $groupIdentity = $GroupSID
        }
        
        # Get the direct members of this group
        try {
            $members = Get-ADGroupMember -Identity $groupIdentity -Server $script:ADDomain.PDCEmulator
            LogThis -m "Successfully retrieved $($members.Count) members from group $groupIdentity" -lvl Debug
        } catch {
            LogThis -m "Failed to get members from group $groupIdentity (SID: $GroupSID): $_" -lvl Warn
            return @()
        }
 
        $currentPath = if ($ParentPath) { "$ParentPath <- $GroupName" } else { $GroupName }
 
        # Process each member. Groups get recursed into, users and computers get their details looked up.
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
 
                # Member is a user or computer. Look up its account details.
                try {
                    if ($member.objectClass -eq 'computer') {
 
                        $computer = Get-ADComputer $member -Properties LastLogonDate, PasswordLastSet, ServicePrincipalName, Enabled, DistinguishedName, CanonicalName -Server $script:ADDomain.PDCEmulator
                        
                        $results += [PSCustomObject]@{
                            Name              = $computer.Name
                            SamAccountName    = $computer.SamAccountName
                            Group             = $GroupName
                            Enabled           = $computer.Enabled
                            LastLogonDate     = $computer.LastLogonDate
                            PasswordLastSet   = $computer.PasswordLastSet
                            SPNs              = $computer.ServicePrincipalName -join ','
                            ObjectType        = "Computer"
                            NestedPath        = $currentPath
                            DistinguishedName = $computer.DistinguishedName
                            CanonicalName     = $computer.CanonicalName
                        }
                    } else {
 
                        $user = Get-ADUser $member -Properties LastLogonDate, PasswordLastSet, ServicePrincipalName, Enabled, DistinguishedName, CanonicalName -Server $script:ADDomain.PDCEmulator
 
                        $results += [PSCustomObject]@{
                            Name              = $user.Name
                            SamAccountName    = $user.SamAccountName
                            Group             = $GroupName
                            Enabled           = $user.Enabled
                            LastLogonDate     = $user.LastLogonDate
                            PasswordLastSet   = $user.PasswordLastSet
                            SPNs              = $user.ServicePrincipalName -join ','
                            ObjectType        = "User"
                            NestedPath        = $currentPath
                            DistinguishedName = $user.DistinguishedName
                            CanonicalName     = $user.CanonicalName
                        }
                    }
 
                    # Remember how this account gets into the privileged group (direct member or via nesting)
                    if ($AccessPaths) {
                        $accountName = if ($member.objectClass -eq 'computer') { $computer.SamAccountName } else { $user.SamAccountName }
                        if (-not $AccessPaths.Value.ContainsKey($accountName)) {
                            $AccessPaths.Value[$accountName] = @{}
                        }
                        $isDirect = $currentPath -eq $SecurityGroup
                        if (-not ($AccessPaths.Value[$accountName].ContainsKey($SecurityGroup) -and 
                               $AccessPaths.Value[$accountName][$SecurityGroup] -eq "Direct member")) {
                            $AccessPaths.Value[$accountName][$SecurityGroup] = if ($isDirect) { "Direct member" } else { $currentPath }
                        }
                    }
                # Member couldn't be resolved. Label well-known built-in SIDs, otherwise skip it.
                } catch {
                    $orphanedSID = $member.SID.Value
                    
                    # Handle well-known built-in SIDs
                    $wellKnownName = switch ($orphanedSID) {
                        'S-1-1-0' { 'Everyone' }
                        'S-1-5-7' { 'Anonymous Logon' }
                        'S-1-5-11' { 'Authenticated Users' }
                        'S-1-5-32-544' { 'Administrators' }
                        default { 
                            LogThis -m "Failed to resolve SID $orphanedSID in group $GroupName - skipping" -lvl Warn
                            continue
                        }
                    }
 
                    if ($wellKnownName) {
                        LogThis -m "Well-known SID found in group $GroupName - $orphanedSID ($wellKnownName)" -lvl Info
                        $results += [PSCustomObject]@{
                            Name = $wellKnownName
                            SamAccountName = $wellKnownName
                            Group = $GroupName
                            Enabled = $true
                            ObjectType = "WellKnownSID"
                            NestedPath = $currentPath
                        }
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
 
# Validate helper - confirms the finished zip file can be opened.
$script:Validate = {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )
    
    try {
        # Expand zip for integrity check
        $null = [System.IO.Compression.ZipFile]::OpenRead($Path)
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
 
# Preflight checks - stop if PowerShell is too old or the session is not elevated.
if ($PSVersionTable.PSVersion.Major -lt 5) {
    LogThis "PowerShell 5 or higher required. Current version: $($PSVersionTable.PSVersion)"
    throw
}
 
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    LogThis "Script requires elevation. Run PowerShell with 'Run As Administrator'."
    throw
}
 
# Get-Controls - the main assessment function.
# Builds an ordered list of checks (each one a script block), runs them one at a time
# and writes the results out. BRAVE (below) finds and runs this because of its Get- prefix.
function Get-Controls {
    [CmdletBinding()]
    param()
 
    # Standard text used in the output when a value is missing, empty or a check fails
    $notFound = "Not Found"
    $nullValue = "<null>"
    $errorValue = "Error"
    
    try {
        LogThis -m "Starting Get-Controls" -lvl Header -show "GATHERING ACTIVE DIRECTORY" 
 
        # Each entry below is one check. The key is the section name and the script block is the logic.
        # In every section, results go to a detail CSV and/or the summary, with a fallback entry if the check fails.
        # [ordered] maintains execution order
        $Controls = [ordered]@{ 
            
            # RUNTIME - who ran the script, from which host and network (location is an approximate public IP lookup)
            'RUNTIME' = {
                $system = Get-CimInstance -ClassName Win32_ComputerSystem
                $os = Get-CimInstance -ClassName Win32_OperatingSystem
                $domainType = if ($system.PartOfDomain) { 'Domain-Joined' } else { 'Workgroup-Joined' }
                $domainName = if ($system.PartOfDomain) { $system.Domain } else { $system.Workgroup }
                $commandLine = $PSCommandPath
                if ($Duo) { $commandLine += " -Duo" }
                if ($Proxy) { $commandLine += " -Proxy" }
                if ($Dns) { $commandLine += " -Dns" }
                
                $location = $notFound 
                try {
                    $publicIP = (Invoke-RestMethod -Uri "https://ipinfo.io/ip" -TimeoutSec 2 -ErrorAction Stop).Trim()
                    $geoData = Invoke-RestMethod -Uri "https://ipinfo.io/$publicIP/json" -TimeoutSec 2 -ErrorAction Stop
                    $location = "$($geoData.city), $($geoData.region), $($geoData.country)"
                    if ($geoData.org) { $location += " ($($geoData.org))" }
                } catch {
                    LogThis -m "$notFound : $($_.Exception.Message)" -lvl Debug
                }
                
                [ordered]@{
                    'Time' = & $script:Format $script:StartTime -Format Display
                    'User' = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                    'Host (+)' = "(Name) $($env:COMPUTERNAME), (OS) $($os.Caption), (Build) $($os.Version)"
                    'Network (+)' = "(Type) $domainType, (Name) $domainName"
                    'Location' = "**Approximate Only** $location"
                    'PowerShell (+)' = "(User) $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name), (Host) $($Host.Name), (Version) $($PSVersionTable.PSVersion), (InvokePath) $commandLine"
                } | & $script:Export -Name $section -IsSummary
            }
            
            # TOPOLOGY - forest and domain layout. Functional levels, sites, domain controllers, global catalogs and FSMO role holders.
            'TOPOLOGY' = {
                try {
                    $configuration = (Get-ADRootDSE).configurationNamingContext
                    $ds = Get-ADObject -Filter 'objectClass -eq "nTDSService"' -SearchBase $configuration -Properties dSHeuristics -Server $script:ADDomain.PDCEmulator
                    LogThis -m "dSHeuristics object retrieved: $($ds.DistinguishedName)" -lvl Debug
                    LogThis -m "dSHeuristics value: '$($ds.dSHeuristics)' (Type: $(if ($ds.dSHeuristics) { $ds.dSHeuristics.GetType().Name } else { 'null' }))" -lvl Debug
                    
                    $dcs = foreach ($dc in $script:ADDomain.ReplicaDirectoryServers) {
                        try {
                            $dcInfo = Get-ADDomainController $dc -Server $script:ADDomain.PDCEmulator
                            "$dc ($($dcInfo.OperatingSystem) $($dcInfo.OperatingSystemVersion))"
                        } catch {
                            "$dc (Unidentified)"
                        }
                    }
 
                    [ordered]@{
                        'Heirarchy (+)' = "(Current/Target Domain) $($script:ADDomain.DNSRoot), (Parent) $(if ($script:ADDomain.ParentDomain) { $script:ADDomain.ParentDomain } else { 'I Am Root' })"
                        'FunctionalLevels (+)' = "(Forest) $($script:ADForest.ForestMode), (Domain) $($script:ADDomain.DomainMode)"
                        'Sites (+)' = "(Count) $(($script:ADForest.Sites | Measure-Object).Count), (List) $($script:ADForest.Sites -join ', ')"
                        'Domains (+)' = "(Count) $(($script:ADForest.Domains | Measure-Object).Count), (List) $($script:ADForest.Domains -join ', ')"
                        'DomainControllers (+)' = "(Replicas) $(($script:ADDomain.ReplicaDirectoryServers | Measure-Object).Count)$(if ($script:ADDomain.ReadOnlyReplicaDirectoryServers) { ", (RODCs) $(($script:ADDomain.ReadOnlyReplicaDirectoryServers | Measure-Object).Count)" }), (List) $($dcs -join ', ')"
                        'Domain (+)' = "(DSHeuristics) $(if ($ds.dSHeuristics) { $ds.dSHeuristics } else { $nullValue }), (DNSRoot) $($script:ADDomain.DNSRoot), (NetBIOS) $($script:ADDomain.NetBIOSName), (SID) $($script:ADDomain.DomainSID.Value)"
                        'GlobalCatalogs (+)' = "(Count) $(($script:ADForest.GlobalCatalogs | Measure-Object).Count), (List) $($script:ADForest.GlobalCatalogs -join ', ')"
                        'FSMORoleHolders (+)' = "(SchemaMaster) $($script:ADForest.SchemaMaster), (DomainNamingMaster) $($script:ADForest.DomainNamingMaster), (PDCEmulator) $($script:ADDomain.PDCEmulator), (RIDMaster) $($script:ADDomain.RIDMaster), (InfrastructureMaster) $($script:ADDomain.InfrastructureMaster)"
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    LogThis -m "Failed getting topology: $_" -lvl Error
                    @() | & $script:Export -Name $section -IsError
                    [ordered]@{
                        'Heirarchy (+)' = "(Current/Target) $errorValue, (Parent) $errorValue"
                        'FunctionalLevels (+)' = "(Forest) $errorValue, (Domain) $errorValue"
                        'Sites (+)' = "(Count) $errorValue, (List) $errorValue"
                        'Domains (+)' = "(Count) $errorValue, (List) $errorValue"
                        'DomainControllers (+)' = "(Replicas) $errorValue, (RODCs) $errorValue, (List) $errorValue"
                        'Domain (+)' = "(DSHeuristics) $errorValue, (DNSRoot) $errorValue, (NetBIOS) $errorValue, (SID) $errorValue"
                        'GlobalCatalogs (+)' = "(Count) $errorValue, (List) $errorValue"
                        'FSMORoleHolders (+)' = "(SchemaMaster) $errorValue, (DomainNamingMaster) $errorValue, (PDCEmulator) $errorValue, (RIDMaster) $errorValue, (InfrastructureMaster) $errorValue"
                    } | & $script:Export -Name $section -IsSummary
                }
            }
 
            # PARTITIONS - estimates how recently each AD partition was backed up.
            # It uses the last change time in the partition's replication metadata as a stand-in for backup date.
            # The blocks below repeat the same steps for each partition (DNS zones, domain, schema, configuration).
            'PARTITIONS' = {
                try {
                    $rootDSE = Get-ADRootDSE -Server $script:ADDomain.PDCEmulator
                    $partitions = $rootDSE.namingContexts
 
                    $backupData = @()               
                    $partition = $partitions | Where-Object { $_ -match "DC=ForestDnsZones," } | Select-Object -First 1
                    if ($partition) {
                        $metadata = Get-ADReplicationAttributeMetadata -Object $partition -Properties dSASignature -Server $script:ADDomain.PDCEmulator
                        $backup = $metadata.LastOriginatingChangeTime
                        if ($backup) {
                            $timeSpan = New-TimeSpan -Start $backup -End $script:StartTime
                            $years = [math]::Floor($timeSpan.TotalDays / 365)
                            $months = [math]::Floor(($timeSpan.TotalDays % 365) / 30)
                            $days = [math]::Floor($timeSpan.TotalDays % 30)
                            $backupData += [PSCustomObject][ordered]@{
                                'Partition' = 'Forest DNS Zones'
                                'LastBackup' = "$(Get-Date $backup -Format 'dd MMM yyyy')"
                                'Elapsed' = "${years}y:${months}m:${days}d"
                                'BackupDate' = $backup
                            }
                        }
                    }
 
                    $partition = $partitions | Where-Object { $_ -match "^DC=(?!.*DnsZones)" } | Select-Object -First 1
                    if ($partition) {
                        $metadata = Get-ADReplicationAttributeMetadata -Object $partition -Properties dSASignature -Server $script:ADDomain.PDCEmulator
                        $backup = $metadata.LastOriginatingChangeTime
                        if ($backup) {
                            $timeSpan = New-TimeSpan -Start $backup -End $script:StartTime
                            $years = [math]::Floor($timeSpan.TotalDays / 365)
                            $months = [math]::Floor(($timeSpan.TotalDays % 365) / 30)
                            $days = [math]::Floor($timeSpan.TotalDays % 30)
                            $backupData += [PSCustomObject][ordered]@{
                                'Partition' = 'Domain'
                                'LastBackup' = "$(Get-Date $backup -Format 'dd MMM yyyy')"
                                'Elapsed' = "${years}y:${months}m:${days}d"
                                'BackupDate' = $backup
                            }
                        }
                    }
 
                    $partition = $partitions | Where-Object { $_ -match "CN=Schema," } | Select-Object -First 1
                    if ($partition) {
                        $metadata = Get-ADReplicationAttributeMetadata -Object $partition -Properties dSASignature -Server $script:ADDomain.PDCEmulator
                        $backup = $metadata.LastOriginatingChangeTime
                        if ($backup) {
                            $timeSpan = New-TimeSpan -Start $backup -End $script:StartTime
                            $years = [math]::Floor($timeSpan.TotalDays / 365)
                            $months = [math]::Floor(($timeSpan.TotalDays % 365) / 30)
                            $days = [math]::Floor($timeSpan.TotalDays % 30)
                            $backupData += [PSCustomObject][ordered]@{
                                'Partition' = 'Domain Schema'
                                'LastBackup' = "$(Get-Date $backup -Format 'dd MMM yyyy')"
                                'Elapsed' = "${years}y:${months}m:${days}d"
                                'BackupDate' = $backup
                            }
                        }
                    }
 
                    $partition = $partitions | Where-Object { $_ -match "CN=Configuration," } | Select-Object -First 1
                    if ($partition) {
                        $metadata = Get-ADReplicationAttributeMetadata -Object $partition -Properties dSASignature -Server $script:ADDomain.PDCEmulator
                        $backup = $metadata.LastOriginatingChangeTime
                        if ($backup) {
                            $timeSpan = New-TimeSpan -Start $backup -End $script:StartTime
                            $years = [math]::Floor($timeSpan.TotalDays / 365)
                            $months = [math]::Floor(($timeSpan.TotalDays % 365) / 30)
                            $days = [math]::Floor($timeSpan.TotalDays % 30)
                            $backupData += [PSCustomObject][ordered]@{
                                'Partition' = 'Configuration'
                                'LastBackup' = "$(Get-Date $backup -Format 'dd MMM yyyy')"
                                'Elapsed' = "${years}y:${months}m:${days}d"
                                'BackupDate' = $backup
                            }
                        }
                    }
 
                    $partition = $partitions | Where-Object { $_ -match "DC=DomainDnsZones," } | Select-Object -First 1
                    if ($partition) {
                        $metadata = Get-ADReplicationAttributeMetadata -Object $partition -Properties dSASignature -Server $script:ADDomain.PDCEmulator
                        $backup = $metadata.LastOriginatingChangeTime
                        if ($backup) {
                            $timeSpan = New-TimeSpan -Start $backup -End $script:StartTime
                            $years = [math]::Floor($timeSpan.TotalDays / 365)
                            $months = [math]::Floor(($timeSpan.TotalDays % 365) / 30)
                            $days = [math]::Floor($timeSpan.TotalDays % 30)
                            $backupData += [PSCustomObject][ordered]@{
                                'Partition' = 'Domain DNS Zones'
                                'LastBackup' = "$(Get-Date $backup -Format 'dd MMM yyyy')"
                                'Elapsed' = "${years}y:${months}m:${days}d"
                                'BackupDate' = $backup
                            }
                        }
                    }
 
                    if ($backupData.Count -gt 0) {
                        $backupData | ForEach-Object {
                            [ordered]@{
                                $_.Partition = "$($_.LastBackup) [$($_.Elapsed)]"
                            }
                        } | & $script:Export -Name $section -IsSummary
                    } else {
                        [ordered]@{
                            'Summary (+)' = "No partition backup data found"
                        } | & $script:Export -Name $section -IsSummary
                    }
                } catch {
                    LogThis -m "Failed checking partition backups: $_" -lvl Error
                    @() | & $script:Export -Name $section -IsError
                    [ordered]@{
                        'Summary (+)' = "(Total Partitions) $errorValue, (Oldest) $errorValue, (Newest) $errorValue"
                    } | & $script:Export -Name $section -IsSummary
                }
            }
 
            # PASSWORD_POLICY - the default domain password and lockout policy
            'PASSWORD_POLICY' = {
                try {
                    $policy = Get-ADDefaultDomainPasswordPolicy -Server $script:ADDomain.PDCEmulator
                    
                    [ordered]@{
                        'Settings (+)' = if ($policy) { "(ComplexityEnabled) $($policy.ComplexityEnabled), (MinLength) $($policy.MinPasswordLength), (HistoryCount) $($policy.PasswordHistoryCount), (ReversibleEncryptionEnabled) $($policy.ReversibleEncryptionEnabled)" } else { "(ComplexityEnabled) $notFound, (MinLength) $notFound, (HistoryCount) $notFound, (ReversibleEncryptionEnabled) $notFound" }
                        'Age (+)' = if ($policy) { "(Min) $($policy.MinPasswordAge.Days)d:$($policy.MinPasswordAge.Hours)h:$($policy.MinPasswordAge.Minutes)m, (Max) $($policy.MaxPasswordAge.Days)d:$($policy.MaxPasswordAge.Hours)h:$($policy.MaxPasswordAge.Minutes)m" } else { "(Min) $notFound, (Max) $notFound" }
                        'Lockout (+)' = if ($policy) { "(Threshold) $($policy.LockoutThreshold), (Duration) $($policy.LockoutDuration.Days)d:$($policy.LockoutDuration.Hours)h:$($policy.LockoutDuration.Minutes)m" } else { "(Threshold) $notFound, (Duration) $notFound" }
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    LogThis -m "Failed getting password policy: $_" -lvl Error
                    @() | & $script:Export -Name $section -IsError
                    [ordered]@{
                        'Settings (+)' = "(ComplexityEnabled) $errorValue, (MinLength) $errorValue, (HistoryCount) $errorValue, (ReversibleEncryptionEnabled) $errorValue"
                        'Age (+)' = "(Min) $errorValue, (Max) $errorValue"
                        'Lockout (+)' = "(Threshold) $errorValue, (Duration) $errorValue"
                    } | & $script:Export -Name $section -IsSummary
                }
            }
 
            # GROUP_POLICY - exports every GPO as XML and HTML, then records GPO link order for each OU
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
                        Get-GPOReport -Name $gpo.DisplayName -ReportType Html -Path (Join-Path $script:GPODirectory "$($gpo.DisplayName).html") -Server $script:ADDomain.PDCEmulator
                    }
 
                    # GPO OU precedence
                    LogThis -m "Getting GPO precedence order" -lvl Debug
                    $precedenceData = @()
                    $ous = Get-ADOrganizationalUnit -Filter * -Server $script:ADDomain.PDCEmulator
                    
                    foreach ($ou in $ous) {
                        try {
                            $gpoLinks = Get-GPInheritance -Target $ou.DistinguishedName -Server $script:ADDomain.PDCEmulator
                            
                            # Computer precedence
                            foreach ($gpo in $gpoLinks.GpoInheritance) {
                                if ($null -ne $gpo.GpoId) {
                                    $gpoInfo = Get-GPO -Guid $gpo.GpoId -Server $script:ADDomain.PDCEmulator
                                    $precedenceData += [PSCustomObject]@{
                                        'OU' = $ou.Name
                                        'OUDN' = $ou.DistinguishedName
                                        'GPOName' = $gpoInfo.DisplayName
                                        'GPOId' = $gpo.GpoId
                                        'Precedence' = $gpo.Order
                                        'Enforced' = $gpo.Enforced
                                        'BlockInheritance' = $gpoLinks.BlockInheritance
                                        'SettingsType' = 'Computer'
                                    }
                                }
                            }
                            
                            # User precedence
                            foreach ($gpo in $gpoLinks.GpoInheritance) {
                                if ($null -ne $gpo.GpoId) {
                                    $gpoInfo = Get-GPO -Guid $gpo.GpoId -Server $script:ADDomain.PDCEmulator
                                    $precedenceData += [PSCustomObject]@{
                                        'OU' = $ou.Name
                                        'OUDN' = $ou.DistinguishedName
                                        'GPOName' = $gpoInfo.DisplayName
                                        'GPOId' = $gpo.GpoId
                                        'Precedence' = $gpo.Order
                                        'Enforced' = $gpo.Enforced
                                        'BlockInheritance' = $gpoLinks.BlockInheritance
                                        'SettingsType' = 'User'
                                    }
                                }
                            }
                        } catch {
                            LogThis -m "Failed getting GPO precedence for OU: $($ou.Name)" -lvl Debug
                        }
                    }
                    
                    if ($precedenceData) {
                        $precedenceData | & $script:Export -Name "$section-Precedence"
                    }
 
                    [ordered]@{
                        'GroupPolicyObjects (+)' = "(Total) $(($Gpos | Measure-Object).Count), (Orphaned) $(($Gpos | Where-Object { -not $_.LinkedSitesCount -and -not $_.LinkedOUsCount } | Measure-Object).Count), (AllSettingsDisabled) $(($Gpos | Where-Object { $_.GpoStatus -eq 'AllSettingsDisabled' } | Measure-Object).Count), (ComputerSettingsDisabled) $(($Gpos | Where-Object { $_.GpoStatus -match 'ComputerSettingsDisabled' } | Measure-Object).Count), (UserSettingsDisabled) $(($Gpos | Where-Object { $_.GpoStatus -match 'UserSettingsDisabled' } | Measure-Object).Count)"
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    LogThis -m "Failed processing GPOs" -lvl Error -ex $_
                    @() | & $script:Export -Name $section -IsError
                    [ordered]@{
                        'GroupPolicyObjects (+)' = "(Total) $notFound, (Orphaned) $notFound, (AllSettingsDisabled) $notFound, (ComputerSettingsDisabled) $notFound, (UserSettingsDisabled) $notFound"
                    } | & $script:Export -Name $section -IsSummary
                }
            }
 
            # TRUSTS - domain and forest trusts, with direction, type, SID filtering and selective authentication
            'TRUSTS' = {
                try {
                    $trusts = Get-ADTrust -Filter * -Server $script:ADDomain.PDCEmulator
                    if ($trusts) {
                        $trusts | ForEach-Object {
                            [PSCustomObject][ordered]@{
                                'Source' = $_.Source
                                'Target' = $_.Target
                                'Direction' = $_.Direction
                                'IntraForest' = $_.IntraForest
                                'SelectiveAuth' = if ($_.SelectiveAuth -is [boolean]) { if ($_.SelectiveAuth) { 'TRUE' } else { 'FALSE' } } elseif ($_.SelectiveAuth) { $_.SelectiveAuth } else { '<null> Not Forest Trust' }
                                'TrustType' = switch ($_.TrustType) {
                                    'MIT'       { 'MIT (Realm)' }
                                    'Downlevel' { 'Downlevel (External)' }
                                    'Uplevel'   { if ($_.IntraForest) { 'Uplevel (Forest)' } else { 'Uplevel (External)' } }
                                    default     { "$($_.TrustType) (Unknown)" }
                                }
                                'SIDFilteringForestAware' = if ($_.SIDFilteringForestAware -is [boolean]) { if ($_.SIDFilteringForestAware) { 'TRUE' } else { 'FALSE' } } elseif ($_.SIDFilteringForestAware) { $_.SIDFilteringForestAware } else { '' }
                                'SIDFilteringQuarantined' = if ($_.SIDFilteringQuarantined -is [boolean]) { if ($_.SIDFilteringQuarantined) { 'TRUE' } else { 'FALSE' } } elseif ($_.SIDFilteringQuarantined) { $_.SIDFilteringQuarantined } else { '' }
                                'Transitive' = if ($_.IsTransitive) { 'TRUE' } else { 'FALSE' }
                            }
                        } | & $script:Export -Name $section
                    } else {
                        @() | & $script:Export -Name $section -NoResults
                    }
                    $trustList = @()
                    if ($trusts) {
                        if ($trusts -is [System.Array]) {
                            $trustList = $trusts
                        } else {
                            $trustList = @($trusts)
                        }
                    }
                    $partnerList = if ($trustList.Count -gt 0) { ($trustList | ForEach-Object { $_.Target }) -join ', ' } else { '<none>' }
                    $totalTrusts = $trustList.Count
                    [PSCustomObject][ordered]@{
                        'Summary (+)' = "(Total) $totalTrusts, (Partners) $partnerList"
                    } | & $script:Export -Name $section -IsSummary
                }
                catch {
                    Write-Warning "Error in TRUSTS section: $_"
                    @() | & $script:Export -Name $section -IsError
                    [ordered]@{
                        'Summary (+)' = "(Error) Unable to enumerate trusts"
                    } | & $script:Export -Name $section -IsSummary
                }
            }
 
            # SID500 - checks the built-in Administrator account (RID 500) for enabled status, last logon and password age
            'SID500' = {
                try {
                    $sid = "$($script:ADDomain.DomainSID.Value)-500"
                    $administrator = Get-ADUser -Identity $sid -Properties LastLogonDate, PasswordLastSet -Server $script:ADDomain.PDCEmulator
 
                    $logonAge = New-TimeSpan -Start $administrator.LastLogonDate -End $script:StartTime
                    $passwordAge = New-TimeSpan -Start $administrator.PasswordLastSet -End $script:StartTime
 
                    [ordered]@{
                        'Default' = "(SamAccountName) $($administrator.SamAccountName), (Name) $($administrator.Name), (Enabled) $($administrator.Enabled)"
                        'Administrator (+) ' = "(LastLogonDate) $(Get-Date $administrator.LastLogonDate -Format 'dd MMM yyyy') [$([math]::Floor($logonAge.TotalDays / 365))y:$([math]::Floor(($logonAge.TotalDays % 365) / 30))m:$([math]::Floor($logonAge.TotalDays % 30))d], (PasswordLastSet) $(Get-Date $administrator.PasswordLastSet -Format 'dd MMM yyyy') [$([math]::Floor($passwordAge.TotalDays / 365))y:$([math]::Floor(($passwordAge.TotalDays % 365) / 30))m:$([math]::Floor($passwordAge.TotalDays % 30))d]"
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    LogThis -m "Failed checking SID500: $_" -lvl Error
                    @() | & $script:Export -Name $section -IsError
                    [ordered]@{
                        'Default' = $notFound
                        'Administrator (+) ' = "(LastLogonDate) $notFound, (PasswordLastSet) $notFound"
                    } | & $script:Export -Name $section -IsSummary
                }
            }
 
            # PRIVILEGED - resolves membership of the high-privilege groups, including nested groups.
            # Produces a matrix showing which account is in which group and by what path, plus summary counts.
            'PRIVILEGED' = {
                $groups = @()
                $accessPaths = @{}
                $summary = @{}
                $adminGroupTotals = @{}
 
                foreach ($group in $script:PrivilegedGroups.GetEnumerator()) {
                    try {
                        LogThis -m "Processing: $($group.Key), SID: $($group.Value)" -lvl Debug
                        
                        # Validate SID before processing
                        if ([string]::IsNullOrWhiteSpace($group.Value)) { 
                            LogThis -m "Skipping $($group.Key) - invalid SID: $($group.Value)" -lvl Warn
                            continue
                        }
                        
                        try {
                            $members = & $script:Recursive -GroupSID $group.Value `
                                                        -GroupName $group.Key `
                                                        -SecurityGroup $group.Key `
                                                        -AccessPaths ([ref]$accessPaths)
                            LogThis -m "Recursive call successful for $($group.Key)" -lvl Debug
                        } catch {
                            LogThis -m "Recursive call failed for $($group.Key): $_" -lvl Error
                            $members = @()
                        }
                        LogThis -m "$($group.Key) contains: $($members.Count) members" -lvl Debug
                        
                        # Log Administrators membership
                        if ($group.Key -eq 'Administrators') {
                            $adminGroups = $members | Where-Object { $_.ObjectType -eq 'Group' }
                            if ($adminGroups) {
                                LogThis -m "Administrators contains nested groups: $($adminGroups.Name -join ', ')" -lvl Info
                                foreach ($adminGroup in $adminGroups) {
                                    LogThis -m "  - $($adminGroup.Name) (Path: $($adminGroup.NestedPath))" -lvl Info
                                }
                            } else {
                                LogThis -m "Administrators doesn't contain nested groups" -lvl Info
                            }
                        }
 
                        $groups += $members
                       
                        $enabled = ""
                        $disabled = ""
                        
                        # Only count if array populated
                        if ($members -and $members -is [array] -and $members.Count -gt 0) {
                            $enabled = ($members | Where-Object { $_.ObjectType -eq 'User' -and $_.Enabled -eq $true } | Sort-Object -Unique SamAccountName).Count
                            $disabled = ($members | Where-Object { $_.ObjectType -eq 'User' -and $_.Enabled -eq $false } | Sort-Object -Unique SamAccountName).Count
                        } elseif ($members -and $members -is [array] -and $members.Count -eq 0) {
                            $enabled = 0
                            $disabled = 0
                        }
                        
                        # Else leave enabled blank
                        if ($group.Key -eq 'Protected Users') {
                            LogThis -m "Protected Users - Total members: $($members.Count), Users: $(($members | Where-Object { $_.ObjectType -eq 'User' }).Count), Enabled: $enabled, Disabled: $disabled" -lvl Debug
                            LogThis -m "Protected Users - User objects: $(($members | Where-Object { $_.ObjectType -eq 'User' } | ForEach-Object { "$($_.SamAccountName):$($_.Enabled)" }) -join ', ')" -lvl Debug
                            LogThis -m "Protected Users - All members: $(($members | ForEach-Object { "$($_.SamAccountName):$($_.ObjectType):$($_.Enabled)" }) -join ', ')" -lvl Debug
                            LogThis -m "Protected Users - Members type: $($members.GetType().FullName), IsNull: $($null -eq $members), IsArray: $($members -is [array])" -lvl Debug
                            LogThis -m "Protected Users - Members length: $($members.Length), Count property: $($members.Count)" -lvl Debug
                        }
                        
                        $summary["$($group.Key)"] = "(Enabled) $([string]$enabled), (Disabled) $([string]$disabled)"
                        
                        # AD Administrators totals
                        if ($group.Key -in @('Administrators', 'Domain Admins', 'Enterprise Admins', 'Schema Admins')) {
                            $adminGroupTotals[$group.Key] = @{
                                Enabled = $enabled
                                Disabled = $disabled
                            }
                        }
                    }
                    catch {
                        LogThis -m "Failed processing: $($group.Key), SID: $($group.Value)" -lvl Debug
                        $summary["$($group.Key)"] = "(Enabled) 0, (Disabled) 0"
                        if ($group.Key -in @('Administrators', 'Domain Admins', 'Enterprise Admins', 'Schema Admins')) {
                            $adminGroupTotals[$group.Key] = @{
                                Enabled = 0
                                Disabled = 0
                            }
                        }
                    }
                }
                
                $totalEnabled = ($adminGroupTotals.Values | ForEach-Object { $_.Enabled } | Measure-Object -Sum).Sum
                $totalDisabled = ($adminGroupTotals.Values | ForEach-Object { $_.Disabled } | Measure-Object -Sum).Sum
                $totalAdmins = $totalEnabled + $totalDisabled
                
                $orderedSummary = [ordered]@{}
                $orderedSummary['Total AD Admins (+) '] = "(Total) $([string]$totalAdmins), (Enabled) $([string]$totalEnabled), (Disabled) $([string]$totalDisabled)"
                
                foreach ($adminGroup in @('Administrators', 'Domain Admins', 'Enterprise Admins', 'Schema Admins')) {
                    if ($summary.ContainsKey($adminGroup)) {
                        $orderedSummary[$adminGroup] = $summary[$adminGroup]
                    }
                }
                
                foreach ($group in $summary.Keys) {
                    if ($group -notin @('Administrators', 'Domain Admins', 'Enterprise Admins', 'Schema Admins')) {
                        $orderedSummary[$group] = $summary[$group]
                    }
                }
                
                # Pre-Windows 2000
                try {
                    $pre2000 = Get-ADGroupMember -Identity "S-1-5-32-554" -Server $script:ADDomain.PDCEmulator
                    $enabledCount = ($pre2000 | Where-Object { $_.Enabled -eq $true } | Measure-Object).Count
                    $disabledCount = ($pre2000 | Where-Object { $_.Enabled -eq $false } | Measure-Object).Count
                    $orderedSummary['Pre-Windows 2000 (+) '] = "(Total) $(($pre2000 | Measure-Object).Count), (Enabled) $enabledCount, (Disabled) $disabledCount, (Everyone) is member: $(($pre2000.SID -contains 'S-1-1-0').ToString()), (AnonymousLogon) is member: $(($pre2000.SID -contains 'S-1-5-7').ToString()), (AuthenticatedUsers) is member: $(($pre2000.SID -contains 'S-1-5-11').ToString())"
                }
                catch {
                    $orderedSummary['Pre-Windows 2000 (+) '] = "(Total) Error, (Enabled) Error, (Disabled) Error, (Everyone) is member: Error, (AnonymousLogon) is member: Error, (AuthenticatedUsers) is member: Error"
                }
 
                try {
                    LogThis -m "Creating privileged matrix for $($accessPaths.Count) accounts" -lvl Debug
                    LogThis -m "AccessPaths keys: $($accessPaths.Keys -join ', ')" -lvl Debug
                    LogThis -m "PrivilegedGroups keys: $($script:PrivilegedGroups.Keys -join ', ')" -lvl Debug
                    if ($accessPaths.Count -eq 0) {
                        LogThis -m "WARNING: AccessPaths is empty - no users found in privileged groups!" -lvl Warn
                    }
                    
                    $allMembers = @{}
                    $privilegedGroupNames = $script:PrivilegedGroups.Keys | Sort-Object -Unique
                    
                    $domainAdmins = $groups | Where-Object { $_.Name -eq "Domain Admins" -or $_.SamAccountName -eq "Domain Admins" }
                    $enterpriseAdmins = $groups | Where-Object { $_.Name -eq "Enterprise Admins" -or $_.SamAccountName -eq "Enterprise Admins" }
                    
                    if ($domainAdmins) {
                        $daKey = "Domain Admins|Group"
                        $allMembers[$daKey] = @{
                            SamAccountName = "Domain Admins"
                            SID            = ""
                            ObjectType     = "Group"
                            Enabled        = $true
                            Name           = "Domain Admins"
                            LastLogonDate  = ""
                            PasswordLastSet = ""
                        }
                        
                        foreach ($grp in $privilegedGroupNames) {
                            $daMembership = $groups | Where-Object { $_.SamAccountName -eq "Domain Admins" -and $_.Group -eq $grp }
                            if ($daMembership) {
                                $path = $daMembership.NestedPath
                                if ($path -ne $grp) {
                                    $path = $path -replace "^$grp <- ", ""
                                } else {
                                    $path = "Direct member"
                                }
                                $allMembers[$daKey][$grp] = $path
                            }
                        }
                    }
                    
                    if ($enterpriseAdmins) {
                        $eaKey = "Enterprise Admins|Group"
                        $allMembers[$eaKey] = @{
                            SamAccountName = "Enterprise Admins"
                            SID            = ""
                            ObjectType     = "Group"
                            Enabled        = $true
                            Name           = "Enterprise Admins"
                            LastLogonDate  = ""
                            PasswordLastSet = ""
                        }
                        
                        foreach ($grp in $privilegedGroupNames) {
                            $eaMembership = $groups | Where-Object { $_.SamAccountName -eq "Enterprise Admins" -and $_.Group -eq $grp }
                            if ($eaMembership) {
                                $path = $eaMembership.NestedPath
                                if ($path -ne $grp) {
                                    $path = $path -replace "^$grp <- ", ""
                                } else {
                                    $path = "Direct member"
                                }
                                $allMembers[$eaKey][$grp] = $path
                            }
                        }
                    }
                    
                    foreach ($account in $accessPaths.Keys | Sort-Object) {
                        $member = $groups | Where-Object { $_.SamAccountName -eq $account } | Select-Object -First 1
                        
                        if ($member -and ($member.ObjectType -eq 'User' -or $member.ObjectType -eq 'Computer')) {
                            $key = "$($member.SamAccountName)|$($member.ObjectType)"
                            if (-not $allMembers.ContainsKey($key)) {
                                $allMembers[$key] = @{
                                    SamAccountName = $member.SamAccountName
                                    SID            = $member.SID
                                    ObjectType     = $member.ObjectType
                                    Enabled        = $member.Enabled
                                    Name           = $member.Name
                                    LastLogonDate  = if ($member.LastLogonDate) { $member.LastLogonDate.ToString('MM/dd/yyyy') } else { "" }
                                    PasswordLastSet = if ($member.PasswordLastSet) { $member.PasswordLastSet.ToString('MM/dd/yyyy') } else { "" }
                                }
                            }
                            
                            foreach ($grp in $privilegedGroupNames) {
                                if ($accessPaths[$account].ContainsKey($grp)) {
                                    $path = $accessPaths[$account][$grp]
 
                                    if ($path -ne "Direct member") {
                                        $path = $path -replace "^$grp <- ", ""
                                    }
                                    $allMembers[$key][$grp] = $path
                                }
                            }
                        }
                    }
                    
                    $matrix = @()
                    foreach ($entry in $allMembers.Values) {
                        $row = [ordered]@{
                            Name            = $entry.Name
                            SamAccountName  = $entry.SamAccountName
                            SID             = $entry.SID
                            Type            = $entry.ObjectType
                            Enabled         = if ($entry.ObjectType -eq "Group") { "" } else { $entry.Enabled }
                            LastLogonDate   = $entry.LastLogonDate
                            PasswordLastSet = $entry.PasswordLastSet
                            
                        }
                        foreach ($grp in $privilegedGroupNames) {
                            $row[$grp] = if ($entry.ContainsKey($grp)) { $entry[$grp] } else { '' }
                        }
                        $matrix += [PSCustomObject]$row
                    }
                    
                    $script:PrivilegedUsers = $matrix
                }
                catch {
                    LogThis -m "Privileged matrix failed" -lvl Warn -ex $_
                }
 
                if ($script:PrivilegedUsers) {
                    LogThis -m "Final PrivilegedUsers array has $($script:PrivilegedUsers.Count) objects" -lvl Debug
                    LogThis -m "First object properties: $($script:PrivilegedUsers[0].PSObject.Properties.Name -join ', ')" -lvl Debug
                    $script:PrivilegedUsers | & $script:Export -Name $section
                } else {
                    @() | & $script:Export -Name $section -NoResults
                }
 
                if ($groups -or $script:PrivilegedUsers) {
                    $orderedSummary | & $script:Export -Name $section -IsSummary
                } else {
                    [ordered]@{ 'Status' = "No privileged accounts found" } | & $script:Export -Name $section -IsSummary
                }
 
                # Search for groups whose names suggest MFA, VPN, remote access, admin or service use, and list their members
                try {
                    LogThis -m "Searching groups for MFA, VPN, SSL, Remote" -lvl Info
                    $mfaKeywords = @('Duo', 'MFA', 'VPN', 'SSL', 'Remote', 'Admins', 'Service', 'svc', 'sync')
                    $mfaGroups = @()
                    $mfaGroupMembers = @()
                    
                    foreach ($keyword in $mfaKeywords) {
                        try {
                            $foundGroups = Get-ADGroup -Filter "Name -like '*$keyword*'" -Properties Description, GroupScope, GroupType -Server $script:ADDomain.PDCEmulator
                            if ($foundGroups) {
                                $mfaGroups += $foundGroups
                            }
                        } catch {
                            LogThis -m "Error searching '$keyword': $_" -lvl Debug
                        }
                    }
                    
                    # Remove dupes
                    $mfaGroups = $mfaGroups | Sort-Object Name -Unique
                    LogThis -m "Total unique groups: $($mfaGroups.Count)" -lvl Info
                    
                    if ($mfaGroups.Count -gt 0) {
                        foreach ($group in $mfaGroups) {
                            try {
                                $members = Get-ADGroupMember -Identity $group.SID -Recursive -Server $script:ADDomain.PDCEmulator
                                
                                foreach ($member in $members) {
                                    $memberDetails = $null
                                    
                                    if ($member.objectClass -eq 'user') {
                                        $memberDetails = Get-ADUser -Identity $member.SID -Properties LastLogonDate, PasswordLastSet, Enabled -Server $script:ADDomain.PDCEmulator
                                    } elseif ($member.objectClass -eq 'computer') {
                                        $memberDetails = Get-ADComputer -Identity $member.SID -Properties LastLogonDate, Enabled -Server $script:ADDomain.PDCEmulator
                                    } elseif ($member.objectClass -eq 'group') {
                                        $memberDetails = Get-ADGroup -Identity $member.SID -Server $script:ADDomain.PDCEmulator
                                    }
                                    
                                    if ($memberDetails) {
                                        $mfaGroupMembers += [PSCustomObject]@{
                                            GroupName = $group.Name
                                            GroupSID = $group.SID
                                            GroupDescription = $group.Description
                                            MemberName = $memberDetails.Name
                                            MemberSamAccountName = $memberDetails.SamAccountName
                                            MemberSID = $memberDetails.SID
                                            MemberType = $member.objectClass
                                            MemberEnabled = if ($null -ne $memberDetails.Enabled) { $memberDetails.Enabled } else { "" }
                                            LastLogonDate = if ($memberDetails.LastLogonDate) { $memberDetails.LastLogonDate.ToString('MM/dd/yyyy') } else { "" }
                                            PasswordLastSet = if ($memberDetails.PasswordLastSet) { $memberDetails.PasswordLastSet.ToString('MM/dd/yyyy') } else { "" }
                                        }
                                    }
                                }
                            } catch {
                                LogThis -m "Error processing group $($group.Name): $_" -lvl Warn
                            }
                        }
                        
                        if ($mfaGroupMembers.Count -gt 0) {
                            LogThis -m "Exporting $($mfaGroupMembers.Count) Group Search" -lvl Info
                            $mfaGroupMembers | & $script:Export -Name "$section-GROUP-SEARCH"
                            
                            [ordered]@{
                                'Group Search' = "(Total Groups) $($mfaGroups.Count), (Total Members) $($mfaGroupMembers.Count), (Unique Users) $(($mfaGroupMembers | Where-Object { $_.MemberType -eq 'user' } | Sort-Object MemberSamAccountName -Unique).Count), (Unique Computers) $(($mfaGroupMembers | Where-Object { $_.MemberType -eq 'computer' } | Sort-Object MemberSamAccountName -Unique).Count), (Nested Groups) $(($mfaGroupMembers | Where-Object { $_.MemberType -eq 'group' } | Sort-Object MemberSamAccountName -Unique).Count)"
                            } | & $script:Export -Name "$section-GROUP-SEARCH" -IsSummary
                        } else {
                            LogThis -m "No Groups Found" -lvl Info
                            @() | & $script:Export -Name "$section-GROUP-SEARCH" -NoResults
                        }
                    } else {
                        LogThis -m "No Groups Found" -lvl Info
                        @() | & $script:Export -Name "$section-GROUP-SEARCH" -NoResults
                    }
                } catch {
                    LogThis -m "Group Search Error: $_" -lvl Error
                    @() | & $script:Export -Name "$section-GROUP-SEARCH" -IsError
                }
            }
 
            # USERS - exports all user accounts with security-relevant attributes and summarizes risky settings
            'USERS' = {
                try {
                    $users = Get-ADUser -Filter * -Properties $script:UserProperties -Server $script:ADDomain.PDCEmulator
                    
                    if ($users) {
                        $users | ForEach-Object {
                            [PSCustomObject][ordered]@{
                                'AdminCount' = $_.AdminCount
                                'Created' = $_.Created
                                'Modified' = $_.Modified
                                'Name' = $_.Name
                                'DisplayName' = $_.DisplayName
                                'Description' = $_.Description
                                'SamAccountName' = $_.SamAccountName
                                'Enabled' = $_.Enabled
                                'LastLogonDate' = $_.LastLogonDate
                                'PasswordLastSet' = $_.PasswordLastSet
                                'CannotChangePassword' = $_.CannotChangePassword
                                'DoesNotRequirePreAuth' = $_.DoesNotRequirePreAuth
                                'PasswordNeverExpires' = $_.PasswordNeverExpires
                                'PasswordNotRequired' = $_.PasswordNotRequired
                                'SID' = $_.SID
                                'logonWorkStations' = $_.logonWorkStations
                                'UserAccountControl' = $_.UserAccountControl
                                'msDS-SupportedEncryptionTypes' = $_.'msDS-SupportedEncryptionTypes'
                                'CanonicalName' = $_.CanonicalName
                                'DistinguishedName' = $_.DistinguishedName
                                'AccountExpirationDate' = $_.AccountExpirationDate
                                'LastBadPasswordAttempt' = $_.LastBadPasswordAttempt
                                'badpwdcount' = $_.badpwdcount
                                'PasswordExpired' = $_.PasswordExpired
                            }
                        } | & $script:Export -Name $section
                    } else {
                        @() | & $script:Export -Name $section -NoResults
                    }
                    
                    # Summary counts. The hex values are userAccountControl flags (for example 0x10000 means password never expires).
                    [ordered]@{
                        'Counts (*)' = if ($users) { "(Total) $(($users | Measure-Object).Count), (Enabled) $(($users | Where-Object {$_.Enabled} | Measure-Object).Count), (Disabled) $(($users | Where-Object {-not $_.Enabled} | Measure-Object).Count), (Stale) $(($users | Where-Object { $_.LastLogonDate -and $_.PasswordLastSet -and ((New-TimeSpan -Start $_.LastLogonDate -End $script:StartTime).TotalDays -ge $script:LogonAge) -and ((New-TimeSpan -Start $_.PasswordLastSet -End $script:StartTime).TotalDays -ge $script:PasswordAge) } | Measure-Object).Count), (NOTREQD) $(($users | Where-Object {$_.UserAccountControl -band 0x0020} | Measure-Object).Count), (CANT_CHANGE) $(($users | Where-Object {$_.UserAccountControl -band 0x0040} | Measure-Object).Count), (DONT_EXPIRE) $(($users | Where-Object {$_.UserAccountControl -band 0x10000} | Measure-Object).Count), (InterdomainTrust) $(($users | Where-Object {$_.UserAccountControl -band 0x0800} | Measure-Object).Count)" } else { "(Total) $notFound, (Enabled) $notFound, (Disabled) $notFound, (Stale) $notFound, (NOTREQD) $notFound, (CANT_CHANGE) $notFound, (DONT_EXPIRE) $notFound, (InterdomainTrust) $notFound" }
                        'Passwords - Enabled Accts Only (*)' = if ($users) { "(DesKeyOnly) $(($users | Where-Object {$_.Enabled -and ($_.UserAccountControl -band 0x200000)} | Measure-Object).Count), (NoPreAuth) $(($users | Where-Object {$_.Enabled -and ($_.UserAccountControl -band 0x400000)} | Measure-Object).Count), (ReversibleEncryption) $(($users | Where-Object {$_.Enabled -and ($_.UserAccountControl -band 0x0080)} | Measure-Object).Count)" } else { "(DesKeyOnly) $notFound, (NoPreAuth) $notFound, (ReversibleEncryption) $notFound" }
                        'Delegation (*)' = if ($users) { "(TRUSTED) $(($users | Where-Object {$_.UserAccountControl -band 0x80000} | Measure-Object).Count), (NOT_DELEGATED) $(($users | Where-Object {$_.UserAccountControl -band 0x100000} | Measure-Object).Count)" } else { "(TRUSTED_FOR) $notFound, (NOT_DELEGATED) $notFound" }
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    LogThis -m "Failed checking users: $_" -lvl Error
                    @() | & $script:Export -Name $section -IsError
                    [ordered]@{
                        'Counts (*)' = $errorValue
                        'Passwords - Enabled Accts Only (*)' = $errorValue
                        'Delegation (*)' = $errorValue
                    } | & $script:Export -Name $section -IsSummary
                }
            }
 
            # KRBTGT - age of the krbtgt account password (the account that signs Kerberos tickets)
            'KRBTGT' = {
                try {
                    $krbtgt = Get-ADUser 'krbtgt' -Properties PasswordLastSet -Server $script:ADDomain.PDCEmulator
                    
                    $passwordAge = New-TimeSpan -Start $krbtgt.PasswordLastSet -End $script:StartTime
 
                    [ordered]@{
                        'PasswordLastSet' = "LastSet $(& $script:Format $krbtgt.PasswordLastSet -Format Display) [$([math]::Floor($passwordAge.TotalDays / 365))y:$([math]::Floor(($passwordAge.TotalDays % 365) / 30))m:$([math]::Floor($passwordAge.TotalDays % 30))d]"
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    LogThis -m "Failed checking KRBTGT: $_" -lvl Error
                    @() | & $script:Export -Name $section -IsError
                    [ordered]@{
                        'PasswordLastSet' = $notFound
                    } | & $script:Export -Name $section -IsSummary
                }
            }
 
            # DELEGATION - finds accounts trusted for Kerberos delegation (unconstrained, constrained, protocol transition and resource-based)
            'DELEGATION' = {
                try {
                    $delegatedAccounts = Get-ADObject -Filter {
                        ((UserAccountControl -BAND 0x0080000) -OR 
                        (UserAccountControl -BAND 0x1000000) -OR 
                        (msDS-AllowedToDelegateTo -like '*') -OR 
                        (msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'))
                    } -Properties @(
                        "Name", "SamAccountName", "ObjectClass", "UserAccountControl", 
                        "msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity", "CanonicalName"
                    ) -Server $script:ADDomain.PDCEmulator
 
                    if ($delegatedAccounts) {
                        $delegatedAccounts | ForEach-Object {
                            $delegationType = 'Constrained'  # Default
                            
                            if ($_.UserAccountControl -BAND 0x0080000) {
                                $delegationType = 'Unconstrained'
                            }
                            
                            if ($_.UserAccountControl -BAND 0x1000000) {
                                $delegationType = 'Constrained with Protocol Transition'
                            }
                            
                            if ($_.'msDS-AllowedToActOnBehalfOfOtherIdentity' -and $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' -ne '') {
                                $delegationType = 'Resource-Based Constrained Delegation'
                            }
 
                            [PSCustomObject][ordered]@{
                                'Name' = $_.Name
                                'SamAccountName' = $_.SamAccountName
                                'ObjectClass' = $_.ObjectClass
                                'DelegationType' = $delegationType
                                'msDS-AllowedToDelegateTo' = $_.'msDS-AllowedToDelegateTo' -join ', '
                                'msDS-AllowedToActOnBehalfOfOtherIdentity' = $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' -join ', '
                                'UserAccountControl' = $_.UserAccountControl
                                'CanonicalName' = $_.CanonicalName
                                'DistinguishedName' = $_.DistinguishedName
                            }
                        } | & $script:Export -Name $section
 
                        [ordered]@{
                            'Summary (+)' = "(Total) $($delegatedAccounts.Count), (Unconstrained) $(($delegatedAccounts | Where-Object { $_.UserAccountControl -BAND 0x0080000 }).Count), (Constrained) $(($delegatedAccounts | Where-Object { $_.'msDS-AllowedToDelegateTo' }).Count), (Resource) $(($delegatedAccounts | Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' }).Count)"
                        } | & $script:Export -Name $section -IsSummary
                    } else {
                        @() | & $script:Export -Name $section -NoResults
                        [ordered]@{
                            'Summary (+)' = "(Total) $notFound, (Unconstrained) $notFound, (Constrained) $notFound, (Resource) $notFound"
                        } | & $script:Export -Name $section -IsSummary
                    }
                } catch {
                    LogThis -m "Failed checking delegation: $_" -lvl Error
                    @() | & $script:Export -Name $section -IsError
                    [ordered]@{
                        'Summary (+)' = "(Total) $errorValue, (Unconstrained) $errorValue, (Constrained) $errorValue, (Resource) $errorValue"
                    } | & $script:Export -Name $section -IsSummary
                }
            }
 
            # MSA - managed service accounts (sMSA and gMSA) and who is allowed to retrieve gMSA passwords, including nested group members
            'MSA' = {
                try {
                    $props = @(
                        'PrincipalsAllowedToRetrieveManagedPassword',
                        'DNSHostName','Enabled','CanonicalName','Description','DisplayName',
                        'DistinguishedName','Created','Modified','msDS-ManagedPasswordInterval',
                        'msDS-SupportedEncryptionTypes','Name','SamAccountName','userAccountControl'
                    )
                    $msaList = Get-ADServiceAccount -Filter * -Properties $props -Server $script:ADDomain.PDCEmulator
 
                    $msaList | ForEach-Object {
                        [PSCustomObject][ordered]@{
                            Type                  = if ($_.ObjectClass -eq 'msDS-GroupManagedServiceAccount') { 'gMSA' } else { 'sMSA' }
                            Created               = $_.Created
                            Modified              = $_.Modified
                            Name                  = $_.Name
                            SamAccountName        = $_.SamAccountName
                            Enabled               = $_.Enabled
                            DNSHostName           = $_.DNSHostName
                            Description           = $_.Description
                            msDS_ManagedPasswordInterval  = $_.'msDS-ManagedPasswordInterval'
                            msDS_SupportedEncryptionTypes = $_.'msDS-SupportedEncryptionTypes'
                            userAccountControl    = $_.userAccountControl
                            CanonicalName         = $_.CanonicalName
                            DistinguishedName     = $_.DistinguishedName
                        }
                    } | & $script:Export -Name $section
 
                    $allMembers = @{}
                    $gmsaGroupNames = $msaList | Where-Object ObjectClass -eq 'msDS-GroupManagedServiceAccount' | Select-Object -ExpandProperty Name | Sort-Object -Unique
                    $msaList | Where-Object ObjectClass -eq 'msDS-GroupManagedServiceAccount' | ForEach-Object {
                        $msa = $_
                        foreach ($principal in $msa.PrincipalsAllowedToRetrieveManagedPassword) {
                            $dn = if ($principal -is [string]) { $principal } else { $principal.DistinguishedName }
                            $visited = @{}
                            $stack = @(@{DN=$dn;Path=@()})
                            $results = @()
                            while ($stack.Count -gt 0) {
                                $current = $stack[0]
                                if ($stack.Count -gt 1) {
                                    $stack = $stack[1..($stack.Count-1)]
                                } else {
                                    $stack = @()
                                }
                                if ($visited.ContainsKey($current.DN)) { continue }
                                $visited[$current.DN] = $true
                                $members = Get-ADGroupMember -Identity $current.DN
                                foreach ($m in $members) {
                                    if ($m.objectClass -eq 'user' -or $m.objectClass -eq 'computer') {
 
                                        $fullObject = if ($m.objectClass -eq 'user') {
                                            Get-ADUser -Identity $m.DistinguishedName -Properties Enabled -Server $script:ADDomain.PDCEmulator
                                        } else {
                                            Get-ADComputer -Identity $m.DistinguishedName -Properties Enabled -Server $script:ADDomain.PDCEmulator
                                        }
                                        $results += [PSCustomObject]@{
                                            Member = $fullObject
                                            Path = @($current.Path + $m.Name)
                                        }
                                    } elseif ($m.objectClass -eq 'group') {
                                        if (-not $visited.ContainsKey($m.DistinguishedName)) {
                                            $stack += @{DN=$m.DistinguishedName;Path=@($current.Path + $m.Name)}
                                        }
                                    }
                                }
                            }
                            LogThis -m "Found $($results.Count) members for $($msa.Name)" -lvl Debug
                            foreach ($entry in $results) {
                                $member = $entry.Member
                                $pathArr = $entry.Path
                                $key = "$($member.SamAccountName)|$($member.objectClass)"
                                if (-not $allMembers.ContainsKey($key)) {
                                    $allMembers[$key] = @{
                                        SamAccountName = $member.SamAccountName
                                        ObjectType     = $member.objectClass
                                        Enabled        = $member.Enabled
                                    }
                                }
                                $pathStr = if ($pathArr.Count -eq 0) { 'Direct member' } else { ($pathArr -join ' <- ') }
                                $allMembers[$key][$msa.Name] = $pathStr
                            }
                        }
                    }
                    $matrix = @()
                    foreach ($entry in $allMembers.Values) {
                        $row = [ordered]@{
                            SamAccountName = $entry.SamAccountName
                            ObjectType     = $entry.ObjectType
                            Enabled        = $entry.Enabled
                        }
                        foreach ($gmsaGroup in $gmsaGroupNames) {
                            $row["MSA=$gmsaGroup"] = if ($entry.ContainsKey($gmsaGroup)) { $entry[$gmsaGroup] } else { '' }
                        }
                        $matrix += [PSCustomObject]$row
                    }
                    if ($matrix.Count) {
                        $matrix | & $script:Export -Name "$section-GROUPS"
                    } else {
                        @() | & $script:Export -Name "$section-GROUPS" -NoResults
                    }
                    $count_s = ($msaList | Where-Object ObjectClass -eq 'msDS-ManagedServiceAccount').Count
                    $count_g = ($msaList | Where-Object ObjectClass -eq 'msDS-GroupManagedServiceAccount').Count
                    [ordered]@{
                        'Summary (+)' = "(Total) $($msaList.Count), (sMSA) $count_s, (gMSA) $count_g, (GroupMembers) $($matrix.Count)"
                    } | & $script:Export -Name $section -IsSummary
                }
                catch {
                    LogThis -m "Failed checking MSAs: $_" -lvl Error
                    [ordered]@{
                        'Summary (+)' = "(Total) $errorValue, (sMSA) $errorValue, (gMSA) $errorValue"
                    } | & $script:Export -Name $section -IsSummary
                }
            }
 
            # SPN - user accounts that have service principal names set. Flags privileged accounts and duplicate SPNs.
            'SPN' = {
                try {
                    $spnObjects = Get-ADObject -Filter { ServicePrincipalName -like "*" } `
                        -Properties ServicePrincipalName, ObjectClass, Name, DistinguishedName, SamAccountName, UserAccountControl, CanonicalName, Enabled `
                        -Server $script:ADDomain.PDCEmulator | Where-Object { $_.ObjectClass -eq "user" }
                    
                    if ($spnObjects) {
                        $userSPNs = $spnObjects | Where-Object { $_.ObjectClass -eq 'user' }
                        $totalUsers = ($userSPNs | Measure-Object).Count
 
                        $privilegedSPNs = $spnObjects | Where-Object {
                            $_.ObjectClass -eq 'user' -and
                            $_.SamAccountName -in $script:PrivilegedUsers.SamAccountName
                        }
                        $totalPrivileged = ($privilegedSPNs | Measure-Object).Count
 
                        $allSPNs = @()
                        foreach ($obj in $spnObjects) {
                            foreach ($spn in $obj.ServicePrincipalName) {
                                $allSPNs += $spn
                            }
                        }
                        
                        $duplicateSPNs = $allSPNs | Group-Object | Where-Object { $_.Count -gt 1 } | Select-Object -ExpandProperty Name
                        $combinedSPNData = $spnObjects | ForEach-Object {
                            $isPrivileged = $_.SamAccountName -in $script:PrivilegedUsers.SamAccountName
                            $hasDuplicates = $false
                            foreach ($spn in $_.ServicePrincipalName) {
                                if ($spn -in $duplicateSPNs) {
                                    $hasDuplicates = $true
                                    break
                                }
                            }
                            $user = Get-ADUser -Identity $_.SamAccountName -Properties Enabled -Server $script:ADDomain.PDCEmulator
                            [PSCustomObject][ordered]@{
                                'Name' = $_.Name
                                'SamAccountName' = $_.SamAccountName
                                'ObjectType' = $_.ObjectClass
                                'Enabled' = $user.Enabled
                                'Privileged' = if ($isPrivileged) { 'TRUE' } else { 'FALSE' }
                                'ServicePrincipalName' = $_.ServicePrincipalName -join ', '
                                'Duplicate' = if ($hasDuplicates) { 'TRUE' } else { 'FALSE' }
                                'UserAccountControl' = $_.UserAccountControl
                                'CanonicalName' = $_.CanonicalName
                                'DistinguishedName' = $_.DistinguishedName
                            }
                        }
                        $combinedSPNData | & $script:Export -Name $section
                        
                        $totalSPNs = ($spnObjects | ForEach-Object { $_.ServicePrincipalName.Count } | Measure-Object -Sum).Sum
                        $totalObjects = ($spnObjects | Measure-Object).Count
                        $totalDuplicates = ($duplicateSPNs | Measure-Object).Count
                    } else {
                        @() | & $script:Export -Name $section -NoResults
                        $totalSPNs = 0
                        $totalObjects = 0
                        $totalUsers = 0
                        $totalPrivileged = 0
                        $totalDuplicates = 0
                    }
 
                    [ordered]@{
                        'Summary (+)' = "(Total) $totalSPNs, (Objects) $totalObjects, (Users) $totalUsers, (Privileged) $totalPrivileged, (Duplicates) $totalDuplicates"
                    } | & $script:Export -Name $section -IsSummary
 
                } catch {
                    LogThis -m "Failed checking SPNs: $_" -lvl Error
                    @() | & $script:Export -Name $section -IsError
                    [ordered]@{
                        'Summary (+)' = "(Total) $errorValue, (Objects) $errorValue, (Users) $errorValue, (Privileged) $errorValue, (Duplicates) $errorValue"
                    } | & $script:Export -Name $section -IsSummary
                }
            }
 
            # FGPP - fine-grained password policies and the users and groups each one applies to
            'FGPP' = {
                try {
                    $fgpps = Get-ADFineGrainedPasswordPolicy -Filter * -Server $script:ADDomain.PDCEmulator
                    
                    if ($fgpps) {
                        $fgpps | ForEach-Object {
                            $appliedTo = (Get-ADFineGrainedPasswordPolicySubject -Identity $_.Name -Server $script:ADDomain.PDCEmulator)
                            $users = @($appliedTo | Where-Object { $_.objectClass -eq 'user' })
                            $groups = @($appliedTo | Where-Object { $_.objectClass -eq 'group' })
                            [PSCustomObject][ordered]@{
                                'Name'                     = $_.Name
                                'Precedence'               = $_.Precedence
                                'MinPasswordLength'        = $_.MinPasswordLength
                                'PasswordHistoryCount'     = $_.PasswordHistoryCount
                                'ComplexityEnabled'        = $_.ComplexityEnabled
                                'ReversibleEncryptionEnabled' = $_.ReversibleEncryptionEnabled
                                'MinPasswordAge'           = $_.MinPasswordAge
                                'MaxPasswordAge'           = $_.MaxPasswordAge
                                'LockoutThreshold'         = $_.LockoutThreshold
                                'LockoutDuration'          = $_.LockoutDuration
                                'LockoutObservationWindow' = $_.LockoutObservationWindow
                                'AppliedTo'                = ($appliedTo.Name -join ', ')
                                'AffectedUsers'            = ($users.Name -join ', ')
                                'AffectedGroups'           = ($groups.Name -join ', ')
                            }
                        } | & $script:Export -Name $section
                    } else {
                        @() | & $script:Export -Name $section -NoResults
                    }
 
                    $allMembers = @{}
                    $fgppNames = $fgpps | Select-Object -ExpandProperty Name | Sort-Object -Unique
                    
                    foreach ($fgpp in $fgpps) {
                        $appliedTo = (Get-ADFineGrainedPasswordPolicySubject -Identity $fgpp.Name -Server $script:ADDomain.PDCEmulator)
                        $groups = @($appliedTo | Where-Object { $_.objectClass -eq 'group' })
                        $users = @($appliedTo | Where-Object { $_.objectClass -eq 'user' })
 
                        foreach ($user in $users) {
                            $fullObject = Get-ADUser -Identity $user.DistinguishedName -Properties Enabled -Server $script:ADDomain.PDCEmulator
                            $key = "$($fullObject.SamAccountName)|$($fullObject.objectClass)"
                            if (-not $allMembers.ContainsKey($key)) {
                                $allMembers[$key] = @{
                                    SamAccountName = $fullObject.SamAccountName
                                    ObjectType     = $fullObject.objectClass
                                    Enabled        = $fullObject.Enabled
                                }
                            }
                            $allMembers[$key][$fgpp.Name] = 'Direct member'
                        }
 
                        foreach ($group in $groups) {
                            $visited = @{}
                            $stack = @(@{DN=$group.DistinguishedName;Path=@($group.Name)})
                            $results = @()
                            while ($stack.Count -gt 0) {
                                $current = $stack[0]
                                if ($stack.Count -gt 1) {
                                    $stack = $stack[1..($stack.Count-1)]
                                } else {
                                    $stack = @()
                                }
                                if ($visited.ContainsKey($current.DN)) { continue }
                                $visited[$current.DN] = $true
                                $members = Get-ADGroupMember -Identity $current.DN
                                foreach ($m in $members) {
                                    if ($m.objectClass -eq 'user' -or $m.objectClass -eq 'computer') {
                                        $fullObject = if ($m.objectClass -eq 'user') {
                                            Get-ADUser -Identity $m.DistinguishedName -Properties Enabled -Server $script:ADDomain.PDCEmulator
                                        } else {
                                            Get-ADComputer -Identity $m.DistinguishedName -Properties Enabled -Server $script:ADDomain.PDCEmulator
                                        }
                                        $results += [PSCustomObject]@{
                                            Member = $fullObject
                                            Path = @($current.Path + $m.Name)
                                        }
                                    } elseif ($m.objectClass -eq 'group') {
                                        if (-not $visited.ContainsKey($m.DistinguishedName)) {
                                            $stack += @{DN=$m.DistinguishedName;Path=@($current.Path + $m.Name)}
                                        }
                                    }
                                }
                            }
                            LogThis -m "Found $($results.Count) members for FGPP $($fgpp.Name) group $($group.Name)" -lvl Debug
                            foreach ($entry in $results) {
                                $member = $entry.Member
                                $pathArr = $entry.Path
                                $key = "$($member.SamAccountName)|$($member.objectClass)"
                                if (-not $allMembers.ContainsKey($key)) {
                                    $allMembers[$key] = @{
                                        SamAccountName = $member.SamAccountName
                                        ObjectType     = $member.objectClass
                                        Enabled        = $member.Enabled
                                    }
                                }
                                $pathStr = if ($pathArr.Count -eq 1) { 'Direct member' } else { ($pathArr -join ' <- ') }
                                if (-not $allMembers[$key][$fgpp.Name] -or $allMembers[$key][$fgpp.Name] -ne 'Direct member') {
                                    $allMembers[$key][$fgpp.Name] = $pathStr
                                }
                            }
                        }
                    }
                    
                    $matrix = @()
                    foreach ($entry in $allMembers.Values) {
                        $row = [ordered]@{
                            SamAccountName = $entry.SamAccountName
                            ObjectType     = $entry.ObjectType
                            Enabled        = $entry.Enabled
                            Privileged     = if ($entry.SamAccountName -in $script:PrivilegedUsers.SamAccountName) { 'TRUE' } else { 'FALSE' }
                        }
                        foreach ($fgppName in $fgppNames) {
                            $row["FGPP=$fgppName"] = if ($entry.ContainsKey($fgppName)) { $entry[$fgppName] } else { '' }
                        }
                        $matrix += [PSCustomObject]$row
                    }
                    
                    if ($matrix.Count) {
                        $matrix | & $script:Export -Name "$section-GROUPS"
                    } else {
                        @() | & $script:Export -Name "$section-GROUPS" -NoResults
                    }
                    
                    [ordered]@{
                        'Summary (+)' = "(Total) $(if ($fgpps) { $fgpps.Count } else { 0 }), (GroupMembers) $($matrix.Count)"
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    LogThis -m "Failed checking FGPP: $_" -lvl Error
                    @() | & $script:Export -Name $section -IsError
                    [ordered]@{
                        'Summary (+)' = "(Total) $errorValue, (GroupMembers) $errorValue"
                    } | & $script:Export -Name $section -IsSummary
                }
            }
 
            # SYSVOL - checks folder permissions on each DC's SYSVOL share and reports entries beyond the standard system and read-only ones
            'SYSVOL' = {
                try {
                    $results = foreach ($dc in $script:DCs) {
                        LogThis -m "Processing SYSVOL on $($dc.Name)"
                        try {
                            $allFolders = Get-ChildItem -Path "\\$($dc.Name)\SYSVOL" -Directory -Recurse -Depth 2
                            foreach ($folder in $allFolders) {
                                $acl = Get-Acl -Path $folder.FullName
                                $acl.Access | Where-Object { 
                                    $_.IdentityReference -notlike "NT AUTHORITY*" -and
                                    $_.IdentityReference -notlike "BUILTIN*" -and
                                    $_.IdentityReference -notlike "CREATOR*" -and
                                    $_.IdentityReference -notmatch "^S-1-" -and
                                    $_.FileSystemRights -ne "ReadAndExecute, Synchronize"
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
                        $results | & $script:Export -Name $section
                        [PSCustomObject]                    [ordered]@{
                        'Summary (+)' = "(DCs Processed) $(($script:DCs | Measure-Object).Count), (Custom Permissions) $(($results | Measure-Object).Count)"
                    } | & $script:Export -Name $section -IsSummary
                    } else {
                        @() | & $script:Export -Name $section -NoResults
                        [PSCustomObject]                    [ordered]@{
                        'Summary (+)' = "(DCs Processed) $(($script:DCs).Count), (Custom Permissions) 0"
                    } | & $script:Export -Name $section -IsSummary
                    }
                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }
 
            # LOGGING - reads the advanced audit policy (success and failure auditing) from the local machine
            # using the Windows audit API, then compares it to a list of expected audit subcategories.
            'LOGGING' = {
                # Pass 1 - call the audit API directly and export the raw subcategory settings
                & {
                    $dll = [string]::Join("`r`n", '[DllImport("advapi32.dll")]', 'public static extern bool') 
                    $auditpol = Add-Type -Name 'AuditPolRaw' -Namespace 'Win32' -PassThru -MemberDefinition "
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
 
                    $ms = [System.Runtime.InteropServices.Marshal]
                    $count = [uint32]0
                    $buffer = [IntPtr]::Zero
                    $size = $ms::SizeOf([type][guid])
                    $null = $auditpol::AuditEnumerateSubCategories([guid]::Empty, $true, [ref]$buffer, [ref]$count)
                    $ptr = [int64]$buffer
                    $results = @()
 
                    foreach ($id in 1..$count) {
                        $guid = $ms::PtrToStructure([IntPtr]$ptr,[type][guid])
                        $ptr += $size
 
                        $pol = New-Object AUDIT_POLICY_INFORMATION
                        $pSize = $ms::SizeOf($pol)
                        $pPtr = $ms::AllocHGlobal($pSize)
                        $null = $ms::StructureToPtr($pol, $pPtr, $false)
                        $null = $auditpol::AuditQuerySystemPolicy($guid, 1, [ref]$pPtr)
                        $pol = $ms::PtrToStructure($pPtr, [type][AUDIT_POLICY_INFORMATION])
                        $null = $ms::FreeHGlobal($pPtr)
 
                        $results += $pol
                    }
 
                    $null = $auditpol::AuditFree($buffer)
                    $results | & $script:Export -Name $section
 
                }
                
                # Pre-Windows 2000 Compatible Access group check. This repeats the same check from the PRIVILEGED section.
                try { # Pre-Windows 2000
                    $pre2000 = Get-ADGroupMember -Identity "S-1-5-32-554" -Server $script:ADDomain.PDCEmulator
                    $enabledCount = ($pre2000 | Where-Object { $_.Enabled -eq $true } | Measure-Object).Count
                    $disabledCount = ($pre2000 | Where-Object { $_.Enabled -eq $false } | Measure-Object).Count
                    $orderedSummary['Pre-Windows 2000 (+) '] = "(Total) $(($pre2000 | Measure-Object).Count), (Enabled) $enabledCount, (Disabled) $disabledCount, (Everyone) is member: $(($pre2000.SID -contains 'S-1-1-0').ToString()), (AnonymousLogon) is member: $(($pre2000.SID -contains 'S-1-5-7').ToString()), (AuthenticatedUsers) is member: $(($pre2000.SID -contains 'S-1-5-11').ToString())"
                }
                catch {
                    $orderedSummary['Pre-Windows 2000 (+) '] = "(Total) Error, (Enabled) Error, (Disabled) Error, (Everyone) is member: Error, (AnonymousLogon) is member: Error, (AuthenticatedUsers) is member: Error"
                }
 
                # Pass 2 - query the audit API again, this time looking up readable category and subcategory names
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
                        try {
                            $pol = new-object AUDIT_POLICY_INFORMATION
                            $size = $ms::SizeOf($pol)
                            $ptr = $ms::AllocHGlobal($size)
                            $null = $ms::StructureToPtr($pol, $ptr, $false)
                            $result = $auditpol::AuditQuerySystemPolicy($sub, 1, [ref]$ptr)
                            if (-not $result) {
                                LogThis -m "AuditQuerySystemPolicy failed for GUID: $sub" -lvl Debug
                                $null = $ms::FreeHGlobal($ptr)
                                return $null
                            }
                            $pol = $ms::PtrToStructure($ptr, [type][AUDIT_POLICY_INFORMATION])
                            $null = $ms::FreeHGlobal($ptr)
                            @{
                                category = $pol.AuditCategoryGuid
                                success = [bool]($pol.AuditingInformation -band 1)
                                failure = [bool]($pol.AuditingInformation -band 2)
                            }
                        } catch {
                            LogThis -m "Get-PolicyInfo failed for GUID: $sub - $($_.Exception.Message)" -lvl Debug
                            return $null
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
                        try {
                            $guid = $ms::PtrToStructure([IntPtr]$ptr,[type][guid])
                            $nameResult = $auditpol::AuditLookupSubCategoryName($guid,[ref]$name)
                            if (-not $nameResult) {
                                LogThis -m "AuditLookupSubCategoryName failed for GUID: $guid" -lvl Debug
                                $ptr += $size
                                continue
                            }
                            
                            $pol = Get-PolicyInfo $guid
                            if ($null -eq $pol) {
                                LogThis -m "Get-PolicyInfo returned null for GUID: $guid" -lvl Debug
                                $ptr += $size
                                continue
                            }
                            
                            if (-not $catList.ContainsKey($pol.category)) {
                                LogThis -m "Category not found in catList for GUID: $guid" -lvl Debug
                                $ptr += $size
                                continue
                            }
                            
                            $results += @{
                                Category = $catList[$pol.category]
                                CategoryGUID = $pol.category
                                Subcategory = $name.ToString()
                                SubcategoryGUID = $guid
                                Success = $pol.success
                                Failure = $pol.failure
                            }
                        } catch {
                            LogThis -m "Error processing audit policy item ${id}: $($_.Exception.Message)" -lvl Debug
                        }
                        $ptr += $size
                    }
 
                    if ($results) {
                        # Maps each audit subcategory to a control ID number used in the report
                        $controlMap = @{
                            "Account Logon|Credential Validation" = 100
                            "Account Logon|Kerberos Authentication Service" = 101
                            "Account Logon|Kerberos Service Ticket Operations" = 102
                            "Account Logon|Other Account Logon Events" = 103
                            "Account Management|Computer Account Management" = 104
                            "Account Management|Other Account Management Events" = 105
                            "Account Management|Security Group Management" = 106
                            "Account Management|User Account Management" = 107
                            "Detailed Tracking|DPAPI Activity" = 108
                            "Detailed Tracking|Process Creation" = 109
                            "DS Access|Directory Service Access" = 110
                            "DS Access|Directory Service Changes" = 111
                            "Logon/Logoff|Account Lockout" = 112
                            "Logon/Logoff|Logoff" = 113
                            "Logon/Logoff|Logon" = 114
                            "Logon/Logoff|Other Logon/Logoff Events" = 115
                            "Logon/Logoff|Special Logon" = 116
                            "Policy Change|Audit Policy Change" = 117
                            "Policy Change|Authentication Policy Change" = 118
                            "Policy Change|MPSSVC Rule-Level Policy Change" = 119
                            "System|IPsec Driver" = 120
                            "System|Security State Change" = 121
                            "System|Security System Extension" = 122
                            "System|System Integrity" = 123
                        }
 
                        # Keep only the mapped subcategories and put them in control ID order
                        $filteredResults = $results | Where-Object {
                            $key = "$($_.Category)|$($_.Subcategory)"
                            $controlMap.ContainsKey($key)
                        }
 
                        if ($filteredResults) {
                            $orderedKeys = $controlMap.Keys
                            $orderedResults = foreach ($key in $orderedKeys) {
                                $filteredResults | Where-Object { "$($_.Category)|$($_.Subcategory)" -eq $key }
                            }
                        } else {
                            $orderedResults = @()
                        }
 
                        $policyOutput = $orderedResults | ForEach-Object {
                            $controlKey = "$($_.Category)|$($_.Subcategory)"
                            $controlValue = $controlMap[$controlKey]
                            $success = $_.Success
                            $failure = $_.Failure
                            # Label each row as Success, Failure, Both or None
                            $comment = if ($success -and $failure) {
                                "Both"
                            } elseif ($success) {
                                "Success"
                            } elseif ($failure) {
                                "Failure"
                            } else {
                                "None"
                            }
                            [PSCustomObject][ordered]@{
                                'Category' = $_.Category
                                'Subcategory' = $_.Subcategory
                                'Control' = $controlValue
                                'Success' = $success
                                'Failure' = $failure
                                'Comments' = $comment
                            }
                        }
                        $policyOutput | & $script:Export -Name "$section"
 
                        [ordered]@{
                            'Status' = "Evidence Collected"
                        } | & $script:Export -Name $section -IsSummary
                    } else {
                        [ordered]@{
                            'Status' = "Evidence Collection Failed"
                        } | & $script:Export -Name $section -IsSummary
                    }
 
                    $null = $auditpol::AuditFree($buffer)
                } catch {
                    LogThis -m "Failed checking audit policies: $_" -lvl Error
                    [ordered]@{
                        'Status' = $errorValue
                    } | & $script:Export -Name $section -IsSummary
                }
            }
 
            # COMPUTERS - exports all computer accounts and counts servers, workstations and unknown systems
            'COMPUTERS' = {
                try {
                    $computers = Get-ADComputer -Filter * -Properties @(
                        'Name', 'DistinguishedName', 'OperatingSystem', 
                        'OperatingSystemVersion', 'LastLogonDate', 'Enabled',
                        'TrustedForDelegation', 'SamAccountName', 'CanonicalName', 'Created'
                    ) -Server $script:ADDomain.PDCEmulator
 
                    if ($computers) {
                        $computers | ForEach-Object {
                            [PSCustomObject][ordered]@{
                                'Name' = $_.Name
                                'SamAccountName' = $_.SamAccountName
                                'Enabled' = $_.Enabled
                                'LastLogonDate' = $_.LastLogonDate
                                'OperatingSystem' = $_.OperatingSystem
                                'OperatingSystemVersion' = $_.OperatingSystemVersion
                                'TrustedForDelegation' = $_.TrustedForDelegation
                                'CreatedDate' = $_.Created
                                'CanonicalName' = $_.CanonicalName
                                'DistinguishedName' = $_.DistinguishedName
                            }
                        } | & $script:Export -Name $section
 
                        $serverCount = ($computers | Where-Object { $_.OperatingSystem -like "*Server*" } | Measure-Object).Count
                        $workstationCount = ($computers | Where-Object { $_.OperatingSystem -like "*Windows*" -and $_.OperatingSystem -notlike "*Server*" } | Measure-Object).Count
                        $unknownCount = ($computers | Where-Object { $_.OperatingSystem -notlike "*Windows*" -or -not $_.OperatingSystem } | Measure-Object).Count
 
                        [ordered]@{
                            'Summary (+)' = "(Servers) $serverCount, (Workstations) $workstationCount, (Unknown) $unknownCount"
                        } | & $script:Export -Name $section -IsSummary
                    } else {
                        @() | & $script:Export -Name $section -NoResults
                        [ordered]@{
                            'Summary (+)' = "(None) 0"
                        } | & $script:Export -Name $section -IsSummary
                    }
                } catch {
                    LogThis -m "Failed gathering computers: $_" -lvl Error
                    @() | & $script:Export -Name $section -IsError
                    [ordered]@{
                        'Summary (+)' = $errorValue
                    } | & $script:Export -Name $section -IsSummary
                }
            }
 
            # SPOOLER - checks whether the Print Spooler service is running on each domain controller
            'SPOOLER' = {
                try {
                    $spoolerInfo = @()
                    $script:DCs | ForEach-Object {
                        try {
                            $spoolerService = Get-Service -ComputerName $_.Name -Name Spooler
                            $startupConfig = (Get-WmiObject -Class Win32_Service -Filter "Name='Spooler'" -ComputerName $_.Name).StartMode
                            
                            $spoolerObj = [PSCustomObject][ordered]@{
                                'DC' = $_.Name
                                'Site' = $_.Site
                                'Status' = $spoolerService.Status
                                'Startup' = $startupConfig
                            }
                            $spoolerInfo += $spoolerObj
                            $spoolerObj | & $script:Export -Name $section
                        } catch {
                            LogThis -m "Spooler check failed: $($_.Name): $_" -lvl Warn
                            $spoolerObj = [PSCustomObject][ordered]@{
                                'DC' = $_.Name
                                'Site' = $_.Site
                                'Status' = $notFound
                                'Startup' = $notFound
                            }
                            $spoolerInfo += $spoolerObj
                            $spoolerObj | & $script:Export -Name $section
                        }
                    }
 
                    [ordered]@{
                        'Summary (+)' = "(Total DCs) $($spoolerInfo.Count), (Running) $(($spoolerInfo | Where-Object { $_.Status -eq 'Running' } | Measure-Object).Count), (Stopped) $(($spoolerInfo | Where-Object { $_.Status -eq 'Stopped' } | Measure-Object).Count), (Disabled) $(($spoolerInfo | Where-Object { $_.Startup -eq 'Disabled' } | Measure-Object).Count)"
                    } | & $script:Export -Name $section -IsSummary
 
                } catch {
                    LogThis -m "Failed checking spooler: $_" -lvl Error
                    @() | & $script:Export -Name $section -IsError
                    [ordered]@{
                        'Summary (+)' = "(Total DCs) $errorValue, (Running) $errorValue, (Stopped) $errorValue, (Disabled) $errorValue"
                    } | & $script:Export -Name $section -IsSummary
                }
            }
 
            # NETWORK - checks anonymous access and null session settings in each DC's registry (read remotely),
            # plus the LSAAnonymousNameLookup setting via a temporary secedit export.
            'NETWORK' = {
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
                                            if ($null -eq $val.$key) { return $nullValue }
                                            return $val.$key
                                        } catch {
                                            return $notFound
                                        }
                                    } -ArgumentList $reg.Path, $key
 
                                    $results += [PSCustomObject]@{
                                        Server = $dc.Name
                                        Key = $key
                                        Value = $value
                                    }
 
                                } catch {
                                    LogThis -m "Failed checking registry on $($dc.Name) for $key : $_" -lvl Warn
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
                                        $value = if ($lookup) { $lookup.ToString().Split('=')[1].Trim() } else { $notFound }
                                        Remove-Item -Path $tempPath -Force
                                        return $value
                                    }
                                    return "Export Failed"
                                } catch {
                                    if (Test-Path $tempPath) { Remove-Item -Path $tempPath -Force }
                                    return "Error: $_"
                                }
                            } -ErrorAction SilentlyContinue
 
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
 
                    if ($results) {
                        $results | Select-Object Server, Key, Value | & $script:Export -Name $section
                    } else {
                        @() | & $script:Export -Name $section -NoResults
                    }
 
                    $complianceSummary = @{}
                    $totalDCs = $script:DCs.Count
                    
                    # Compliance
                    # Expected secure values. A DC is counted as compliant when its value matches.
                    $expectedValues = @{
                        'RestrictNullSessAccess' = 1
                        'NullSessionShares' = 0
                        'RestrictAnonymousSAM' = 1
                        'RestrictAnonymous' = 1
                        'EveryoneIncludesAnonymous' = 0
                        'allownullsessionfallback' = 0
                        'LSAAnonymousNameLookup' = 0
                    }
                    
                    # Count compliant DCs for each
                    foreach ($setting in $expectedValues.Keys) {
                        $compliantDCs = ($results | Where-Object { 
                            $_.Key -eq $setting -and 
                            $_.Value -eq $expectedValues[$setting] 
                        } | Measure-Object).Count
                        
                        $complianceSummary[$setting] = "$($expectedValues[$setting]) ($compliantDCs of $totalDCs)"
                    }
                    
                    [ordered]@{
                        'RestrictNullSessAccess' = $complianceSummary['RestrictNullSessAccess']
                        'NullSessionShares' = $complianceSummary['NullSessionShares']
                        'RestrictAnonymousSAM' = $complianceSummary['RestrictAnonymousSAM']
                        'RestrictAnonymous' = $complianceSummary['RestrictAnonymous']
                        'EveryoneIncludesAnonymous' = $complianceSummary['EveryoneIncludesAnonymous']
                        'allownullsessionfallback' = $complianceSummary['allownullsessionfallback']
                        'LSAAnonymousNameLookup' = $complianceSummary['LSAAnonymousNameLookup']
                    } | & $script:Export -Name $section -IsSummary
 
                } catch {
                    LogThis -m "Failed checking network registry settings: $_" -lvl Error
                    [ordered]@{
                        'Status' = "Evidence Collection Failed"
                    } | & $script:Export -Name $section -IsSummary
                }
            }
 
            # ADCS - Active Directory Certificate Services.
            # Looks at certification authorities, certificate templates (with a risk rating), the NTAuth store
            # and CA audit logging. If no CA is found, it records that and moves on.
            'ADCS' = {
                # Hard-coded exception. Skip this section when running on a host named TRUST.
                if ($env:COMPUTERNAME -eq 'TRUST') {
                    LogThis -m "Skipping CERTIFICATES section on TRUST host" -lvl Info
                    return
                }
                try {
                    # certutil only succeeds if a certification authority is present
                    $caCheck = certutil -CA
                    if ($LASTEXITCODE -eq 0) {
                        LogThis -m "ADCS found: $($caCheck[0])"
 
                        LogThis -m "Verifying PSPKI module" -show "Verifying PSPKI module"
                        GetPrerequisites -Verify $script:CertModule
                        
                        LogThis -m "Processing CAs" -show "CERTIFICATES"
                        $cas = Get-CertificationAuthority
                        if ($cas) {
                            LogThis -m "CAs found: $($cas.Count)"
                            # Collect details about each certification authority
                            $authorities = @(foreach ($ca in $cas) {
                                LogThis -m "Processing: $($ca.Name), $i of $($cas.Count)"
                                
                                $endpointDetails = if ($ca.EnrollmentEndpoints) {
                                    $ca.EnrollmentEndpoints | ForEach-Object {
                                        $isHttps = $_.Uri -like "https://*"
                                        $usesNTLM = $_.Authentication -like "*NTLM*"
                                        
                                        "EndpointUri=$($_.Uri); IsHttps=$isHttps; Auth=$($_.Authentication); UsesNTLM=$usesNTLM"
                                    }
                                }
                                $enrollmentEndpoints = if ($endpointDetails) { $endpointDetails -join " | " } else { $notFound }
                                
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
                                
                                # Read the template's permissions to see who can enroll
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
                                    [bool]($TemplateProps.'pKIExtendedKeyUsage' | Where-Object { # Has authentication EKUs
                                        $_ -in @(
                                            "1.3.6.1.5.5.7.3.2",    # Client Authentication
                                            "1.3.6.1.5.2.3.4",      # PKINIT Client Authentication
                                            "1.3.6.1.4.1.311.20.2.2" # Smart Card Logon
                                        )
                                    }),
                                    
                                    [bool]($TemplateProps.'pKIExtendedKeyUsage' -contains "2.5.29.37.0" -or # Has dangerous EKUs
                                        $null -eq $TemplateProps.'pKIExtendedKeyUsage'),
                                    [bool]($TemplateProps.'msPKI-Certificate-Name-Flag' -band 0x00000001) # Allows SAN specification
                                ) -contains $true
                                
                                $CAManagerApproval = [bool]($TemplateProps.'msPKI-Enrollment-Flag' -band 0x02) # Check for CA Manager Approval requirement
 
                                $riskLevel = if ($SensitiveKeyUsage -and $LowPrivilegedEnrollment -and !$CAManagerApproval) { # Determine risk level
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
                        try {
                            $domain = (Get-ADDomain).DNSRoot
                            if ($domain) {
                                $ntAuthPath = "CN=NtAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$($domain -replace '\.',',DC=')"
                                LogThis -m "NTAuth path: $ntAuthPath" -lvl Debug
                                
                                $ntAuthCertificates = @(Get-ADObject -Filter * -SearchBase $ntAuthPath -Properties * -ErrorAction SilentlyContinue | 
                                    Select-Object CanonicalName, CN, Created, Description, DisplayName, objectClass)
                                
                                if ($ntAuthCertificates) {
                                    $ntAuthCertificates | & $script:Export -Name "$section-NTAUTH"
                                    LogThis -m "Exported '$section-NTAUTH'"
                                    [ordered]@{
                                        'Total' = ($ntAuthCertificates).Count
                                    } | & $script:Export -Name "$section-NTAUTH" -IsSummary
                                    LogThis -m "Exported '$section-NTAUTH'-IsSummary"
                                } else {
                                    LogThis -m "No NTAuth certificates found in path" -lvl Warn
                                    [ordered]@{
                                        'Status' = "No NTAuth Certificates found in path"
                                    } | & $script:Export -Name "$section-NTAUTH-NONE-FOUND"
                                    [ordered]@{ 
                                        'Status' = "No NTAuth Certificates found in path" 
                                    } | & $script:Export -Name "$section-NTAUTH" -IsSummary
                                }
                            } else {
                                LogThis -m "Could not determine domain DNS root" -lvl Warn
                                [ordered]@{
                                    'Status' = "Could not determine domain DNS root"
                                } | & $script:Export -Name "$section-NTAUTH-ERROR"
                                [ordered]@{ 
                                    'Status' = "Could not determine domain DNS root" 
                                } | & $script:Export -Name "$section-NTAUTH" -IsSummary
                            }
                        } catch {
                            LogThis -m "Error processing NTAuth certificates: $_" -lvl Error -ex $_
                            [ordered]@{
                                'Status' = "Error processing NTAuth certificates: $($_.Exception.Message)"
                            } | & $script:Export -Name "$section-NTAUTH-ERROR"
                            [ordered]@{ 
                                'Status' = "Error processing NTAuth certificates: $($_.Exception.Message)" 
                            } | & $script:Export -Name "$section-NTAUTH" -IsSummary
                        }
 
                    # Logging
                        LogThis -m "Processing CA Logging Configuration" -show "CA Logging"
                        # For each CA, check whether certificate services auditing is turned on
                        $logging = @(foreach ($ca in $cas) {
                            LogThis -m "Auditing logging for: $($ca.ComputerName)" -lvl Debug
 
                            $auditPolicy = try { # Category Logging (Success & Failure)
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
                            
                            $auditConfig = try { # Subcategory Logging (127)
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
 
                            $scePolicy = try { # Subcategory supercedes category (1)
                                $value = Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy'
                                if ($null -eq $value) { "Not configured" } else { $value }
                            } catch {
                                if ($_.Exception.Message -match "Property SCENoApplyLegacyAuditPolicy does not exist") {
                                    "Not configured"
                                } else {
                                    "Error: $($_.Exception.Message)"
                                }
                            }
 
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
                        if ($logging) {
                            $logging | & $script:Export -Name "$section-LOGGING"
                            LogThis -m "Exported '$section-LOGGING'"
                        } else {
                            @() | & $script:Export -Name "$section-LOGGING" -NoResults
                        }
                        [ordered]@{
                            'CAs' = ($cas | Measure-Object).Count
                            'Compliant' = ($logging | Where-Object { 
                                $_.HasSCEPolicy -and $_.HasAuditPolicy -and $_.HasAuditConfig 
                            } | Measure-Object).Count
                            'Compliant SCE' = ($logging | Where-Object HasSCEPolicy | Measure-Object).Count
                            'Compliant Policy' = ($logging | Where-Object HasAuditPolicy | Measure-Object).Count
                            'Compliant Config' = ($logging | Where-Object HasAuditConfig | Measure-Object).Count
                        } | & $script:Export -Name "$section-LOGGING" -IsSummary
 
                        $auditLog = foreach ($ca in $logging) { # Generate detailed audit log
                            "CA: $($ca.Name)"
                            "SCE Policy: $($ca.SCEPolicy)"
                            "Audit Policy: $($ca.AuditPolicy)"
                            "Audit Configuration: $($ca.AuditConfiguration)"
                            "----------------------------------------"
                        }
 
                        if ($auditLog) { # Export audit log
                            $auditLog | Out-File -FilePath (Join-Path $script:Directory "$section-audit-$($script:Filename).txt") -Encoding UTF8
                        }
 
                    } else {
                        LogThis -m "ADCS not found (Exit Code: $LASTEXITCODE)" -lvl Info
                        @() | & $script:Export -Name "$section-LOGGING" -NoResults
                        [ordered]@{
                            'Status' = "ADCS not installed"
                        } | & $script:Export -Name "$section-NONE-FOUND" -IsSummary
                    }
                } catch {
                    LogThis -m "Certificate processing failed" -lvl Error -ex $_
                    @() | & $script:Export -Name "$section-LOGGING" -IsError
                    [ordered]@{
                        'Status' = "Error: $($_.Exception.Message)"
                    } | & $script:Export -Name "$section-ERROR" -IsSummary
                }
            }
 
            # RAS - members of the 'RAS and IAS Servers' group (RADIUS/NPS). Pulls the NPS config from the
            # first server that responds.
            'RAS' = {
                try {
                    LogThis -m "RAS: Using server $($script:ADDomain.PDCEmulator) for domain $($script:ADDomain.DNSRoot)" -lvl Debug
                    $group = Get-ADGroup -Filter { Name -eq 'RAS and IAS Servers' } -Properties CanonicalName -Server $script:ADDomain.PDCEmulator
                    if ($group) {
                        LogThis -m "RAS: Found group '$($group.Name)' at $($group.DistinguishedName)" -lvl Debug
                        $members = Get-ADGroupMember -Identity $group.DistinguishedName -Server $script:ADDomain.PDCEmulator
                        LogThis -m "RAS: Total members found: $($members.Count)" -lvl Debug
                        LogThis -m "RAS: All members: $members" -lvl Debug
                        
                        $realMembers = $members | Where-Object { 
                            $_.ObjectClass -eq 'user' -or $_.ObjectClass -eq 'computer' 
                        }
                        
                        if ($realMembers.Count -eq 0) {
                            LogThis -m "RAS group found but contains no registered RAS servers (only system objects)" -lvl Info
                            @() | & $script:Export -Name "$section-SERVERS" -NoResults
                            @() | & $script:Export -Name "$section-CONFIG" -NoResults
                            [ordered]@{
                                'Summary (+)' = "(Total) 0, (Servers) No registered RAS servers"
                            } | & $script:Export -Name $section -IsSummary
                            return
                        }
                        
                        $membersWithProps = $realMembers | ForEach-Object {
                            if ($_.ObjectClass -eq 'user') {
                                Get-ADUser -Identity $_.DistinguishedName -Properties CanonicalName -Server $script:ADDomain.PDCEmulator
                            } elseif ($_.ObjectClass -eq 'computer') {
                                Get-ADComputer -Identity $_.DistinguishedName -Properties CanonicalName -Server $script:ADDomain.PDCEmulator
                            }
                        }
                        
                        if ($realMembers) {
                            $rasData = $membersWithProps | ForEach-Object {
                                [PSCustomObject]@{
                                    Name = $_.Name
                                    SamAccountName = $_.SamAccountName
                                    ObjectClass = $_.ObjectClass
                                    CanonicalName = $_.CanonicalName
                                    DistinguishedName = $_.DistinguishedName
                                }
                            }
                            $rasData | & $script:Export -Name "$section-SERVERS"                   
                            $npsConfig = $null
                            $workingServer = $null
                            
                            foreach ($member in $membersWithProps) {
                                try {
																									  
                                    $npsConfig = Invoke-Command -ComputerName $member.Name -ScriptBlock {
                                        try {
                                            $output = netsh nps show config
                                            
                                            # Replace domain SIDs in the NPS output with readable account names
                                            function Resolve-SIDs {
                                                param([string]$text)
                                                $pattern = 'S-1-5-21-[0-9-]+'
                                                $regexMatches = [regex]::Matches($text, $pattern)
                                                
                                                foreach ($match in $regexMatches) {
                                                    $sid = $match.Value
                                                    try {
                                                        $obj = [System.Security.Principal.SecurityIdentifier]$sid
                                                        $ntAccount = $obj.Translate([System.Security.Principal.NTAccount])
                                                        $text = $text -replace [regex]::Escape($sid), $ntAccount.Value
                                                    } catch {
                                                    }
                                                }
                                                return $text
                                            }
                                            
                                            $resolvedOutput = @()
                                            foreach ($line in $output) {
                                                # Drop any line containing the RADIUS shared secret so it is never saved
                                                if ($line -notmatch "Shared secret") {
                                                    $resolvedOutput += Resolve-SIDs -text $line
                                                }
                                            }
                                            
                                            return $resolvedOutput
                                        } catch {
                                            return "Error: $($_.Exception.Message)"
                                        }
                                    } -ErrorAction SilentlyContinue
                                    
                                    if ($npsConfig -and $npsConfig -notlike "Error:*") {
                                        $workingServer = $member.Name
                                        break
                                    } else {
                                        LogThis -m "Failed to get NPS config from $($member.Name): $npsConfig" -lvl Warn
                                    }
                                } catch {
                                    LogThis -m "Failed to connect to $($member.Name): $_" -lvl Warn
                                }
                            }
                            
                            if ($npsConfig -and $workingServer) {
                                [PSCustomObject]@{
                                    Server = $workingServer
                                    Config = $npsConfig -join "`n"
                                } | & $script:Export -Name "$section-CONFIG"
                            } else {
                                @() | & $script:Export -Name "$section-CONFIG" -NoResults
                            }
					
                        } else {
                            @() | & $script:Export -Name "$section-MEMBERS" -NoResults
																				  
                            @() | & $script:Export -Name "$section-CONFIG" -NoResults
                        }
                        
                        [ordered]@{
                            'Summary (+)' = "(Total) $($membersWithProps.Count), (Servers) $($membersWithProps.Name -join ', ')"
                        } | & $script:Export -Name $section -IsSummary
                    } else {
                        [ordered]@{
                            'Summary (+)' = "(Total) 0, (Servers) None found"
                        } | & $script:Export -Name $section -IsSummary
                    }
                } catch {
                    LogThis -m "RAS section failed: $_" -lvl Error
                    @() | & $script:Export -Name "$section-MEMBERS" -IsError
                    @() | & $script:Export -Name "$section-CONFIG" -IsError
                    [ordered]@{ 'Status' = "Failure: $_" } | & $script:Export -Name $section -IsSummary
                }
            }
 
            # TASKS - finds scheduled tasks that run ntdsutil.exe (typically AD backup jobs), describes their triggers, and checks the password policy of the account used for DSRM-related tasks
            'TASKS' = {
                try {
                    LogThis -m "Starting Scheduled Tasks assessment for ntdsutil.exe" -lvl Info
                    
                    $ntdsutilTasks = Get-ScheduledTask | Where-Object { $_.Actions.Execute -like "*ntdsutil.exe*" }
                    
                    if ($ntdsutilTasks) {
                        $allTaskData = @()
                        
                        foreach ($task in $ntdsutilTasks) {
                            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath; 
                            $triggers = $task.Triggers | ForEach-Object { 
                                $trigger = $_; 
                                $triggerType = $trigger.CimClass.CimClassName; 
                                switch ($triggerType) { 
                                    "MSFT_TaskDailyTrigger" { 
                                        $startTime = [datetime]::Parse($trigger.StartBoundary); 
                                        "At $($startTime.ToString('HH:mm')) every day" 
                                    } 
                                    "MSFT_TaskWeeklyTrigger" { 
                                        $startTime = [datetime]::Parse($trigger.StartBoundary); 
                                        "At $($startTime.ToString('HH:mm')) every $($trigger.DaysOfWeek)" 
                                    } 
                                    "MSFT_TaskBootTrigger" { "At system startup" } 
                                    "MSFT_TaskLogonTrigger" { "At log on of $($trigger.UserId)" } 
                                    "MSFT_TaskEventTrigger" { "When a specific event is logged" } 
                                    "MSFT_TaskTimeTrigger" { 
                                        $startTime = [datetime]::Parse($trigger.StartBoundary); 
                                        "At $($startTime.ToString('M/d/yyyy HH:mm'))" 
                                    } 
                                    "MSFT_TaskIdleTrigger" { "When the computer is idle" } 
                                    "MSFT_TaskRegistrationTrigger" { "When the task is created or modified" } 
                                    "MSFT_TaskSessionStateChangeTrigger" { "At workstation lock/unlock" } 
                                    "MSFT_TaskCustomTrigger" { "Custom trigger" } 
                                    default { "$triggerType - $($trigger.StartBoundary)" } 
                                } 
                            }
                            
                            $allTaskData += [PSCustomObject]@{ 
                                Name = $task.TaskName; 
                                Status = $task.State; 
                                Triggers = $triggers -join '; '; 
                                NextRunTime = $taskInfo.NextRunTime; 
                                LastRunTime = $taskInfo.LastRunTime; 
                                Actions = "$($task.Actions.Execute) $($task.Actions.Arguments)" 
                            }
                            
                            $taskArgs = $task.Actions.Arguments
                            if ($taskArgs -match 'dsrm' -and $taskArgs -match 'account (\w+)') {
                                $userAccount = $matches[1]
                                try {
                                    $passwordPolicy = Get-ADUserResultantPasswordPolicy -Identity $userAccount
                                    
                                    $allTaskData += [PSCustomObject]@{ 
                                        Name = ""; 
                                        Status = ""; 
                                        Triggers = ""; 
                                        NextRunTime = ""; 
                                        LastRunTime = ""; 
                                        Actions = "" 
                                    }
                                    
                                    $allTaskData += [PSCustomObject]@{ 
                                        Name = "Password Policy for $userAccount"; 
                                        Status = "MaxPasswordAge: $($passwordPolicy.MaxPasswordAge) days"; 
                                        Triggers = "MinPasswordLength: $($passwordPolicy.MinPasswordLength)"; 
                                        NextRunTime = "PasswordComplexity: $($passwordPolicy.ComplexityEnabled)"; 
                                        LastRunTime = "PasswordHistoryCount: $($passwordPolicy.PasswordHistoryCount)"; 
                                        Actions = "LockoutThreshold: $($passwordPolicy.LockoutThreshold)" 
                                    }
                                } catch {
 
                                    $allTaskData += [PSCustomObject]@{ 
                                        Name = ""; 
                                        Status = ""; 
                                        Triggers = ""; 
                                        NextRunTime = ""; 
                                        LastRunTime = ""; 
                                        Actions = "" 
                                    }
                                    
                                    $allTaskData += [PSCustomObject]@{ 
                                        Name = "Password Policy for $userAccount"; 
                                        Status = "Error"; 
                                        Triggers = "Could not retrieve password policy"; 
                                        NextRunTime = ""; 
                                        LastRunTime = ""; 
                                        Actions = "" 
                                    }
                                }
                            }
                        }
                        
                        $allTaskData | & $script:Export -Name $section
                        LogThis -m "Found $($ntdsutilTasks.Count) scheduled tasks with ntdsutil.exe" -lvl Info
                        
                        [ordered]@{
                            'Summary' = "(ntdsutil Tasks) $($ntdsutilTasks.Count)"
                        } | & $script:Export -Name $section -IsSummary
                    } else {
                        @() | & $script:Export -Name $section -NoResults
                        LogThis -m "No scheduled tasks found with ntdsutil.exe" -lvl Info
                        
                        [ordered]@{
                            'Summary' = "(ntdsutil Tasks) 0"
                        } | & $script:Export -Name $section -IsSummary
                    }
                    
                } catch {
                    LogThis -m "Scheduled Tasks assessment failed: $_" -lvl Error
                    @() | & $script:Export -Name $section -IsError
                }
            }
        }
        
        # DNS - exports the A records in the domain's DNS zone. This is added to the list on every run (the -Dns switch is not checked here).
        $Controls['DNS'] = {
                try {
                    $domain = $script:ADDomain.DNSRoot
                    $dnsZone = $domain
                    $dnsRecords = Get-DnsServerResourceRecord -ZoneName $dnsZone -ComputerName $script:ADDomain.PDCEmulator -ErrorAction Stop | Where-Object { $_.RecordType -eq 'A' }
                    $results = $dnsRecords | ForEach-Object {
                        [PSCustomObject][ordered]@{
                            HostName = $_.HostName
                            IPAddress = $_.RecordData.IPv4Address.IPAddressToString
                        }
                    }
                    $results | & $script:Export -Name $section
                    [ordered]@{
                        'Summary (+)' = "(Total A Records) $($results.Count)"
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    LogThis -m "Failed getting DNS A records: $_" -lvl Error
                    [ordered]@{
                        'Summary (+)' = "(Error) Unable to enumerate DNS A records"
                    } | & $script:Export -Name $section -IsSummary
                }
            }
        
        # Optional check (-Proxy). Prompts for a Duo Authentication Proxy server and saves a copy of its authproxy.cfg with secrets masked.
        if ($Proxy) {
            $Controls['DUO_PROXY'] = {
                try {
                    Write-Host "PROVIDE DUO PROXY FQDN OR IP ADDRESS:" -ForegroundColor Yellow -NoNewline
                    $s = Read-Host
                    LogThis -m "User input Duo server: $s" -lvl Info
                    
                    if ([string]::IsNullOrWhiteSpace($s)) {
                        LogThis -m "No Duo proxy server provided" -lvl Error -show "No server provided"
                        [ordered]@{ 'Status' = "No server provided" } | & $script:Export -Name "DUO_PROXY" -IsSummary
                        return
                    }
                    
                    LogThis -m "Starting Duo Proxy Configuration assessment" -lvl Info -show "AUTHPROXY.CFG"
                    
                    if($s -eq "localhost" -or $s -eq "127.0.0.1") {
                        $s = [System.Net.Dns]::GetHostName()
                    }
 
                    $f = "\\$s\c$\Program Files\Duo Security Authentication Proxy\conf\authproxy.cfg"
 
                    try {
                        
                        if(Test-Path $f) {
                            LogThis -m "Found Duo proxy configuration: $s" -lvl Info
                            $c = Get-Content $f
                            
                            # Mask secrets and passwords before saving the file
                            $sanitizedContent = $c | ForEach-Object {
                                if($_ -match "^radius_secret_1=(.*)") { "radius_secret_1=**********" }
                                elseif($_ -match "^radius_secret_2=(.*)") { "radius_secret_2=**********" }
                                elseif($_ -match "^skey=(.*)") { "skey=**********" }
                                elseif($_ -match "^.*password.*=(.*)" -and $_ -notmatch "^#") { $_ -replace "=(.*)$", "=**********" }
                                else { $_ }
                            }
                            
                            $txtFilePath = Join-Path $script:Directory "DUO_PROXY-$($script:Filename).txt"
                            $sanitizedContent | Out-File -FilePath $txtFilePath -Encoding UTF8
                            LogThis -m "Saved sanitized authproxy.cfg to: $txtFilePath" -lvl Info
                            
                            [ordered]@{
                                'Status' = "Gathered"
                            } | & $script:Export -Name "DUO_PROXY" -IsSummary
                            
                            LogThis -m "Duo proxy configuration assessment completed successfully" -lvl Info
                            
                        } else {
                            LogThis -m "Duo proxy configuration file not found on $s" -lvl Warn
                            [ordered]@{ 'Status' = "File not found: $f" } | & $script:Export -Name "DUO_PROXY" -IsSummary
                        }
                    } catch {
                        LogThis -m "Failed to connect to Duo proxy server $s" -lvl Error
                        [ordered]@{ 'Status' = "Connection failed: $s" } | & $script:Export -Name "DUO_PROXY" -IsSummary
                    }
                    
                } catch {
                    LogThis -m "Duo proxy configuration assessment failed: $_" -lvl Error
                    [ordered]@{ 'Status' = "Assessment failed: $_" } | & $script:Export -Name "DUO_PROXY" -IsSummary
                }
            }
        }
        
        # Optional check (-Duo). Prompts for Duo Admin API credentials, finds VPN and Fortinet related integrations,
        # and lists which users or groups are allowed to use them.
        if ($Duo) {
            $Controls['DUO'] = {
                try {
                    try {
                        # Credentials are typed in at run time. Nothing is stored in the script.
                        Write-Host "PROVIDE DUO INTEGRATION KEY:" -ForegroundColor Yellow -NoNewline
                        $IntegrationKey = Read-Host
                        Write-Host "PROVIDE DUO SECRET KEY:" -ForegroundColor Yellow -NoNewline
                        $SecretKey = Read-Host -AsSecureString
                        $SecretKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecretKey))
                        Write-Host "PROVIDE DUO API HOST:" -ForegroundColor Yellow -NoNewline
                        $ApiHost = Read-Host
                        
                        if ([string]::IsNullOrWhiteSpace($IntegrationKey) -or [string]::IsNullOrWhiteSpace($SecretKey) -or [string]::IsNullOrWhiteSpace($ApiHost)) {
                            LogThis -m "Incomplete Duo credentials provided" -lvl Error -show "Incomplete credentials"
                            [ordered]@{ 'Status' = "Incomplete credentials" } | & $script:Export -Name "DUO" -IsSummary
                            return
                        }
                        
                        LogThis -m "Starting Duo Admin API assessment" -lvl Info -show "DUO"
                        
                        LogThis -m "Setting up Duo authentication"
                        
                        try {
                            LogThis -m "Duo authentication configured"
                        } catch {
                            LogThis -m "Failed to configure Duo authentication: $_" -lvl Error
                            throw
                        }
                        
                        LogThis -m "Querying Duo integrations" -show "APPLICATIONS"
                        
                        try {
                            $duoApps = Get-DuoIntegration
                            LogThis -m "Total integrations found: $($duoApps.Count)"
                            LogThis -m "Integration names: $($duoApps.name -join ', ')"
                            
                            foreach ($app in $duoApps) {
                                LogThis -m "Integration: $($app.name) - Type: $($app.type)" -lvl Debug
                            }
                            
                            $duoTargetApps = $duoApps | Where-Object { $_.name -match "(Fortinet|FortiGate|SSL|VPN)" }
                            
                            if ($duoTargetApps) {
                                LogThis -m "Found target applications"
                                LogThis -m "Target app names: $($duoTargetApps.name -join ', ')"
                                
                                foreach ($app in $duoTargetApps) {
                                    LogThis -m "Target app: $($app.name) - ID: $($app.integration_key)" -lvl Debug
                                }
                            } else {
                                LogThis -m "No Fortinet/FortiGate/SSL/VPN applications found" -lvl Warn
                                @() | & $script:Export -Name "DUO" -NoResults
                                LogThis -m "Duo assessment completed" -lvl Done -show "`nCOMPLETED"
                                return
                            }
                        } catch {
                            LogThis -m "Failed querying Duo integrations: $_" -lvl Error
                            throw
                        }
                        
                        LogThis -m "Querying Duo users"
                        
                        try {
                            $duoUsers = Get-DuoUser
                            LogThis -m "Total users found: $($duoUsers.Count)"
                            LogThis -m "User names: $($duoUsers.username -join ', ')"
                            
                            foreach ($user in $duoUsers) {
                                LogThis -m "User: $($user.username) - ID: $($user.user_id) - Groups: $($user.groups.Count)" -lvl Debug
                            }
                        } catch {
                            LogThis -m "Failed querying Duo users: $_" -lvl Error
                            throw
                        }
                        
                        LogThis -m "Querying Duo groups" -show "MEMBERS"
                        
                        try {
                            $duoGroups = Get-DuoGroup
                            LogThis -m "Total groups found: $($duoGroups.Count)"
                            LogThis -m "Group names: $($duoGroups.name -join ', ')"
                            
                            foreach ($group in $duoGroups) {
                                LogThis -m "Group: $($group.name) - ID: $($group.group_id)" -lvl Debug
                            }
                        } catch {
                            LogThis -m "Failed querying Duo groups: $_" -lvl Error
                            throw
                        }
                        
                        LogThis -m "Processing user access settings"
                        
                        $duoData = @()
                        
                        foreach ($duoTargetApp in $duoTargetApps) {
                            try {
                                LogThis -m "Raw groups_allowed value: '$($duoTargetApp.groups_allowed)'" -lvl Debug
                                LogThis -m "Groups_allowed type: $($duoTargetApp.groups_allowed.GetType().Name)" -lvl Debug
                                
                                if ($duoTargetApp.groups_allowed -eq 'deny') {
                                    $userAccessSetting = "Disabled for all users"
                                } elseif ($duoTargetApp.groups_allowed -and $duoTargetApp.groups_allowed.Count -gt 0) {
                                    $userAccessSetting = "Enable only for permitted groups"
                                } else {
                                    $userAccessSetting = "Enable for all users"
                                }
                                
                                LogThis -m "Application: $($duoTargetApp.name) - User Access: $userAccessSetting" -lvl Info
                                LogThis -m "Groups allowed: $($duoTargetApp.groups_allowed)" -lvl Debug
                                
                                if ($userAccessSetting -eq "Enable only for permitted groups") {
                                    LogThis -m "Processing group-based access for $($duoTargetApp.name)"
                                    
                                    foreach ($duoUser in $duoUsers) {
                                        if ($duoUser.groups) {
                                            foreach ($duoUserGroup in $duoUser.groups) {
                                                $duoData += [PSCustomObject]@{
                                                    ObjectType = "User"
                                                    Username = $duoUser.username
                                                    RealName = $duoUser.realname
                                                    Email = $duoUser.email
                                                    UserId = $duoUser.user_id
                                                    Application = $duoTargetApp.name
                                                    UserAccess = $userAccessSetting
                                                    GroupName = $duoUserGroup.name
                                                    GroupId = $duoUserGroup.group_id
                                                }
                                            }
                                        }
                                    }
                                    
                                    foreach ($duoGroup in $duoGroups) {
                                        $duoData += [PSCustomObject]@{
                                            ObjectType = "Group"
                                            Username = ""
                                            RealName = ""
                                            Email = ""
                                            UserId = ""
                                            Application = $duoTargetApp.name
                                            UserAccess = $userAccessSetting
                                            GroupName = $duoGroup.name
                                            GroupId = $duoGroup.group_id
                                        }
                                    }
                                } elseif ($userAccessSetting -eq "Enable for all users") {
                                    LogThis -m "Processing all-users access for $($duoTargetApp.name)"
                                    
                                    foreach ($duoUser in $duoUsers) {
                                        $duoData += [PSCustomObject]@{
                                            ObjectType = "User"
                                            Username = $duoUser.username
                                            RealName = $duoUser.realname
                                            Email = $duoUser.email
                                            UserId = $duoUser.user_id
                                            Application = $duoTargetApp.name
                                            UserAccess = $userAccessSetting
                                            GroupName = "All Users"
                                            GroupId = ""
                                        }
                                    }
                                } else {
                                    LogThis -m "Application is disabled for all users: $($duoTargetApp.name)"
                                    $duoData += [PSCustomObject]@{
                                        ObjectType = "Application"
                                        Username = ""
                                        RealName = ""
                                        Email = ""
                                        UserId = ""
                                        Application = $duoTargetApp.name
                                        UserAccess = $userAccessSetting
                                        GroupName = "No Access"
                                        GroupId = ""
                                    }
                                }
                            } catch {
                                LogThis -m "Failed processing application $($duoTargetApp.name): $_" -lvl Error
                            }
                        }
                        
                        LogThis -m "Exporting $($duoData.Count) records"
                        
                        foreach ($item in $duoData) {
                            LogThis -m "Data item: $($item.ObjectType) - $($item.Username) - $($item.GroupName)" -lvl Debug
                        }
                        
                        if ($duoData.Count -gt 0) {
                            $duoData | & $script:Export -Name "DUO"
                        } else {
                            @() | & $script:Export -Name "DUO" -NoResults
                        }
                        
                        LogThis -m "Duo assessment completed" -lvl Done -show "`nCOMPLETED"
                        
                    } catch {
                        LogThis -m "Error processing: $section" -lvl warn -ex $_
                    }
                } catch {
                    LogThis -m "Duo assessment failed" -lvl Warn -ex $_
                }
            }
        }
        
        # Run every standard check in order (the optional Duo checks are run separately afterward)
        $adSections = $Controls.Keys | Where-Object { $_ -notin @('DUO_PROXY', 'DUO') }
        foreach ($section in $adSections) {
            $script:SectionCounter++  # Counter increment
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
 
        LogThis -m "Controls successfully completed" -lvl Done -show "`nCOMPLETED"
        
        # Conditional sections     
        if ($Proxy) {
            LogThis -m "Processing Duo Proxy assessment" -lvl Header -show "DUO PROXY"
            $script:SectionCounter++
            try {
                $scriptBlock = $Controls['DUO_PROXY']
                & $scriptBlock
                LogThis -m "Duo Proxy assessment completed" -lvl Done -show "`nCOMPLETED"
            } catch {
                LogThis -m "DUO_PROXY failed" -lvl Warn -ex $_
                LogThis -m "Duo Proxy assessment completed" -lvl Done -show "`nCOMPLETED"
            }
        }
        
        if ($Duo) {
            LogThis -m "Processing Duo Admin API assessment" -lvl Header -show "DUO ADMIN API"
            $script:SectionCounter++
            try {
                $scriptBlock = $Controls['DUO']
                & $scriptBlock
                LogThis -m "Duo Admin API assessment completed" -lvl Done -show "`nCOMPLETED"
            } catch {
                LogThis -m "DUO failed" -lvl Warn -ex $_
                LogThis -m "Duo Admin API assessment completed" -lvl Done -show "`nCOMPLETED"
            }
        }
 
    } catch {
        LogThis -m "Get-ActiveDirectory" -lvl Warn -ex $_ - show "Error gathering Active Directory details"
    }
}
 
# Initialize - sets up the run. Resets variables, discovers the forest, domain and DCs, creates the log,
# clears the output folder, and verifies required modules.
function Initialize{
    [CmdletBinding()]
    param(
    )
 
    LogThis -m "Delcare core variables"
    # Clear any leftover script-scope variables, then set the starting values
    Get-Variable script:* | Remove-Variable -Force
    $script:SectionCounter = 0
    $script:ProcessedSections = [System.Collections.Generic.HashSet[string]]::new()
    $script:StartTime = [System.DateTime]::UtcNow
    $script:RequiredModules = $RequiredModules
    $script:CertModule = $CertModule   
    $script:Version = $Version
    $script:Directory = $Directory # from global script param
    $script:ExportedFiles = @()
    $script:SummarySections = @()
    try {
        # Name the output files after the domain (or the computer name if the domain lookup fails)
        $script:ADDomain = Get-ADDomain
        $script:Filename = "$($script:ADDomain.DNSRoot)" # Get-ADDomain succeeded
    } catch {
        $script:Filename = "$($env:COMPUTERNAME)"        # Get-ADDomain failed
    }
    $script:Log = Join-Path $script:Directory "$($script:Filename).log"
    $script:Archive = Join-Path (Split-Path $script:Directory) "$($script:ADDomain.DNSRoot)_$(& $script:Format (Get-Date) -Format File).zip"
 
    try { # Initalize log file
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
            # NOTE - this deletes everything in the output folder (except the current log) before the run starts
            Get-ChildItem -Path $script:Directory -Exclude "$($script:Filename).log" | 
                Remove-Item -Recurse -Force -Confirm:$false
            LogThis -m "Cleaned up previous run"
        }
        
        New-Item -Path $script:Directory -ItemType Directory -Force | Out-Null
        LogThis -m "Created $($script:Directory)"
    } catch {
        LogThis -m "Failed creating $($script:Directory)" -lvl Error -ex $_ -show "Failed creating BRAVE directory"
    }
 
    
    
    LogThis -m "Initializing AD varaibles"
    
    $script:LogonAge = 90 # Stale age thresholds
    $script:PasswordAge = 90 # Stale age thresholds
    try { # Inialize Active Directory
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
            "Administrators"    = "S-1-5-32-544"                 # Built-in
            "Server Operators"   = "S-1-5-32-549"                # Built-in
            "Hyper-V Administrators" = "S-1-5-32-578"            # Built-in
            "Remote Desktop Users" = "S-1-5-32-555"              # Built-in alias
            # Code added below for special case handling  "Pre-Windows 2000 Compatible Access" = "S-1-5-32-554" # Built-in
            }
        } catch {
            LogThis -m "Privileged groups" -lvl Error -ex $_
        }
    } catch {
        LogThis -m "Failed AD initalization" -lvl Error -ex $_ -show "Failed initalizing Active Directory"
        return $false
    }
    
    $script:UserProperties = @( # Initalize user & computer property lists
        'SAMAccountname', 'Enabled', 'Name','DisplayName', 'Description', 'LastLogonDate', 'Created',
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
 
     $summary = @(  # Broadcast Status
        "`nSCRIPT: v$script:Version"
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
 
    LogThis -m "Checking prerequisites" -show "CHECKING PREREQUISITES" -lvl Header
    GetPrerequisites -Verify $script:RequiredModules
    
}
# BRAVE - the main driver. Runs each Get-* function in this script (currently Get-Controls),
# zips the results, validates the zip and removes the working folder.
function BRAVE {
    [CmdletBinding()]
    param (
        [string[]]$Functions
    )
 
    LogThis -m "BRAVE running"
    
    try {
        
        LogThis -m "Discovering Get-* functions"
        LogThis -m "Script Path: $($PSCommandPath)" -lvl Debug
 
        # Find the functions to run. Any function in this file whose name starts with Get-
        $getFunctions = Get-Command -CommandType Function | # Discover functions to turn into scriptblocks
            Where-Object {
                $_.ScriptBlock.File -eq $PSCommandPath -and 
                $_.Name -like 'Get-*'
            }
                    
        $scriptblocks = @($getFunctions | ForEach-Object { [scriptblock]::Create($_.Name) })
        $functionNames = $scriptblocks | ForEach-Object { $_.ToString() }
        LogThis -m "Executing: $($functionNames -join ', ')" -lvl Debug
 
        $total = $scriptblocks.Count
        
        foreach ($i in 0..($total-1)) { 
            $command = $scriptblocks[$i]
 
 
            LogThis -m "Running: $($command.ToString())" -lvl Debug
 
            try {
                & $command
            }
            catch {
                LogThis -m "Failed: $($command.ToString())" -lvl Warn -ex $_
            }
        }
 
        # Package the output into one zip file, placed next to the output folder
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
            ) -join "`n"
 
            LogThis -m "Creating archive file" -show "CREATED: $script:Archive" -lvl Info
            
            LogThis -m "Creating archive file" -show "`nCOMPLETED" -lvl Done
            
            LogThis -m "Summary" -show "SUMMARY" -lvl Header
            LogThis -m "Summary details" -show $summary -lvl Info
            LogThis -m "=== BRAVE Assessment Complete ===" -lvl Done -show "`nBRAVE SCRIPT COMPLETED"
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
}
 
# Entry point - set up the run, then run the assessment
try {
    LogThis -m "Main script block executing"
    Initialize
    BRAVE
} 
catch {
    LogThis -m "Main script block failed" -lvl Error -ex $_ -show "BRAVE failed executing"
}