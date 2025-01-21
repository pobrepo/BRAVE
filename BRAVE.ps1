<#
.SYNOPSIS
    BRAVE Assessment Script
.DESCRIPTION
    Active Directory queries for the purpose of a BRAVE assessments.
    Includes automated evidence collection for Veeam Backup & Replication, as an alternative to screenshots.
.NOTES
    Author:         Patrick O'Brien
    Date:           January 8, 2024
    Purpose:        Consolidation of 'Trimarc' and 'Composite' scripts with standardized output, naming, time format, error handling, message handling.
    Requirements:   PowerShell v5 (Run as Administrator), GroupPolicy PowerShell module, Remote Server Administration Tools (RSAT)
.EXAMPLE
    PS> C:\temp\BRAVE.ps1
#>

[CmdletBinding()]
param(
    [ValidateScript({
        if(-not (Test-Path $_) ) {
            try {
                New-Item -Path $_ -ItemType Directory -Force | Out-Null
            } catch {
                Write-Warning "Cannot create directory $_"
                return $false
            }
        }
        return $true
    })]
    [string]$Version = "2.1.0",
    [string[]]$RequiredModules = @('GroupPolicy'),
    [string]$CertModule = "PSPKI",
    [string]$Directory = "c:\temp\BRAVE\",
    [string]$GPODirectory = (Join-Path $Directory "GPO")
    
)
$ErrorActionPreference = "SilentlyContinue" # Fail-forward


#region Handlers
function FormatValue {
    param(
        [Parameter(ValueFromPipeline)]
        [nullable[DateTime]]$DateTime = [DateTime]::UtcNow,
        [ValidateSet('Write', 'File')]
        [string]$Format = 'Write'
    )

    if ($null -eq $DateTime) { return "Never" }
    
    $utcTime = $DateTime.ToUniversalTime()
    
    switch($Format) {
        'Write'   { $utcTime.ToString('MMM dd, yyyy HH:mm (UTC)') }
        'File'    { $utcTime.ToString('MMM-dd-yyyy_HHmmss') }
    }
}

# Format handler
$script:FormatValue = {
    param(
        [Parameter(ValueFromPipeline)]
        $Value
    )
    
    if ($null -eq $Value) { return '' }
    
    switch ($Value) {
        { $_ -is [DateTime] } { return FormatValue -DateTime $_ -Format Write }
        { $_ -is [TimeSpan] } { return $_.TotalDays }
        default { return $_ }
    }
}

# Recursive lookup handler
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
        
        # Set current path
        $currentPath = if ($ParentPath) {
            "$ParentPath -> $GroupName"
        } else {
            $GroupName
        }
        
        foreach ($member in $members) {
            if ($member.objectClass -eq 'group') {
                $nestedGroup = Get-ADGroup $member -Properties Enabled -Server $script:ADDomain.PDCEmulator
                
                # Add group to results
                $results += [PSCustomObject]@{
                    Name = $nestedGroup.Name
                    SamAccountName = $nestedGroup.SamAccountName
                    Group = $GroupName
                    Enabled = $true
                    LastLogonDate = $null
                    PasswordLastSet = $null
                    SPNs = ""
                    ObjectType = "Group"
                    NestedPath = $currentPath
                    DistinguishedName = $nestedGroup.DistinguishedName
                }
                
                # Process nested members
                $nestedMembers = & $script:Recursive -GroupSID $nestedGroup.SID `
                                                        -GroupName $nestedGroup.Name `
                                                        -SecurityGroup $SecurityGroup `
                                                        -ParentPath $currentPath `
                                                        -AccessPaths $AccessPaths
                
                if ($nestedMembers) {
                    $results += $nestedMembers
                }
            }
            else {
                $user = Get-ADUser $member -Properties LastLogonDate, PasswordLastSet, ServicePrincipalName, 
                                        Enabled, DistinguishedName -Server $script:ADDomain.PDCEmulator
                
                # Add user to results
                $results += [PSCustomObject]@{
                    Name = $user.Name
                    SamAccountName = $user.SamAccountName
                    Group = $GroupName
                    Enabled = $user.Enabled
                    LastLogonDate = & $script:FormatValue $user.LastLogonDate
                    PasswordLastSet = & $script:FormatValue $user.PasswordLastSet
                    SPNs = $user.ServicePrincipalName -join ';'
                    ObjectType = "User"
                    NestedPath = $currentPath
                    DistinguishedName = $user.DistinguishedName
                }
                
                # Track user access path
                if ($AccessPaths) {
                    if (-not $AccessPaths.ContainsKey($user.SamAccountName)) {
                        $AccessPaths[$user.SamAccountName] = @{}
                    }

                    $isDirect = $currentPath -eq $SecurityGroup

                    if (-not ($AccessPaths[$user.SamAccountName].ContainsKey($SecurityGroup) -and 
                        $AccessPaths[$user.SamAccountName][$SecurityGroup] -eq "Direct member")) {
                        $AccessPaths[$user.SamAccountName][$SecurityGroup] = if ($isDirect) {
                            "Direct member"
                        } else {
                            $currentPath
                        }
                    }
                }
            }
        }
        
        return $results
    }
    catch {
        Write-Log -Message "Error processing group '$GroupName': $_" -Level WARN
        
    }
}

# CSV export handler
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
        $summaryData = [ordered]@{}  # Ordered hashtable
        $detailedData = [System.Collections.ArrayList]@()
    }

    process {
        foreach ($item in $InputObject) {
            if ($item -is [hashtable] -or $item -is [System.Collections.Specialized.OrderedDictionary]) {
                foreach ($key in $item.Keys) {
                    $summaryData[$key] = & $script:FormatValue $item[$key]
                }
            } 
            elseif ($item -is [PSCustomObject] -and $IsSummary) {
                $item.PSObject.Properties | ForEach-Object {
                    $summaryData[$_.Name] = & $script:FormatValue $_.Value
                }
            }
            else {
                if ($item -is [PSObject]) {
                    $clonedItem = $item.PSObject.Copy()
                    foreach ($prop in $clonedItem.PSObject.Properties) {
                        $prop.Value = & $script:FormatValue $prop.Value
                    }
                    [void]$detailedData.Add($clonedItem)
                } else {
                    [void]$detailedData.Add($item)
                }
            }
        }
    }

    end {
        if ($summaryData.Count -gt 0 -or $IsSummary) {
            $summaryPath = Join-Path $script:Directory "$($script:filename)-summary.csv"
            $summaryObjects = foreach ($key in $summaryData.Keys) {
                [PSCustomObject]@{
                    'Section' = $Name
                    'Property' = $key
                    'Value' = $summaryData[$key]
                }
            }
            
            if (Test-Path $summaryPath) {
                # Append without headers
                $summaryObjects | ConvertTo-Csv -NoTypeInformation | Select-Object -Skip 1 | Add-Content -Path $summaryPath
            } else {
                # First time running, also include headers
                $summaryObjects | ConvertTo-Csv -NoTypeInformation | Set-Content -Path $summaryPath
            }
        }
    
        if ($detailedData.Count -gt 0 -and -not $IsSummary) {
            $detailedPath = Join-Path $script:Directory "$($script:filename)-$Name.csv"
            $detailedData | Export-Csv -Path $detailedPath -NoTypeInformation
        }
    }
}

# Error handler
$script:Error = {
    param($Section, $Msg)
    Write-Log -Message "$Section failed: $Msg" -Level ERROR
    @{ "$Section" = "Failed: $Msg" } | & $script:Export -Name $Section -IsSummary
}

# Archive handler
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
        Write-Log -Message "Archive validation failed: $_" -Level ERROR
        return $false
    }
    finally {
        if ($zip) { $zip.Dispose() }
    }
}
#endregion Handlers

#region Write

function Write-Info {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$m,                                                         # Required: -m          Message to write

        [ValidateSet('Info', 'Warn', 'Error', 'Debug', 'Header', 'Status')]
        [string]$lvl = 'Info',                                              # Optional: -lvl        Logging level

        [System.Management.Automation.ErrorRecord]$ex,                      # Optional: -ex $_      Include exception details
        [string]$show,                                                      # Optional: -show       User-facing message (regardless if -m is empty)
        [switch]$NoLog,                                                     # Optional: -NoLog      Skip log write
        [string]$section                                                    # Optional: -section    Replacement for $script:Error
    )
    <#
    .EXAMPLE
   
    Write-Info -m "This is a basic log entry."                              # Basic log entry
    
    Write-Info -m "<techincal output>" -show "Process complete"             # Log entry and user displayed text
    
    try {                                                                   ---- example code ----
        Get-ADDomain                                                        
            try {
                Get-ADDomain -SpecicDetails
            } catch {
                throw 
            }
    } catch {                                                              
        Write-Info -m "" -lvl Error -ex $_                                  # Show thrown error with exception details
        Write-Info -m "ADDomain failed" -lvl Error -ex $_                   # Include addtional text
    }                                                                       ---- example code ----
    #>

    $ts = Get-Date -Format 'MMM dd yyyy HH:mm:ss'                           # Timestamp
    $msg = "[$ts] [$lvl] $m"                                                # Base message {[timestamp] [loglevel] message}

    
    if (($lvl -eq 'Warn' -or $lvl -eq 'Error') -and $ex) {                  # Exception handling for {-ex $_ }
        $exceptionDetails = @(
            "   EXCEPTION:",
            "   Type:", 
            "   $($ex.Exception.GetType().FullName)",
            "   Message:", 
            "   $($ex.Exception.Message)",
            "   StackTrace:", 
            "   $($ex.Exception.StackTrace)",
            "   Line:", 
            "   $($ex.InvocationInfo.ScriptLineNumber)",
            "   Position:",
            "   $($ex.InvocationInfo.PositionMessage)"
        )
        $msg += "`n" + ($exceptionDetails -join "`n")
    }
                                                                            # Check log availability
    $ready = $script:Log -and (Test-Path $script:Log)
    if (-not $NoLog -and $ready) {                                          # Log is available and -NoLog parmater was not used 
        try {                                                               # Append to log
            $msg | Out-File -FilePath $script:Log -Append -Force -Encoding UTF8
        } catch {                                                           # Output failure to console
            Write-Warning "[!] Write-Info failed: $msg"
        }
    } else {                                                                # Emergency output for warnings and errors when log is unavailable
        if ($lvl -eq 'Warn') { Write-Warning $m }
        elseif ($lvl -eq 'Error') { Write-Error $m }
    }

    if ($show) {                                                            # User-friendly message {-show ""}
        switch ($lvl) {
            'Info'   { Write-Host $show -ForegroundColor Cyan }
            'Debug'  { Write-Host $show -ForegroundColor Cyan }
            'Warn'   { Write-Host "[*] $show" -ForegroundColor Yellow }
            'Error'  { Write-Host "[!] $show" -ForegroundColor Red }
            'Header' {
                Write-Host "`n=================================" -ForegroundColor Green
                Write-Host $show -ForegroundColor Green
                Write-Host "=================================" -ForegroundColor Green
            }
            'Status' {
                Write-Host "`n$show" -ForegroundColor White
            }
        }
    }

    if ($section) {                                                          # Replacement for $script:Error
        @{ "$section" = "Failed: $m" } | & $script:Export -Name $section -IsSummary
    }
}

function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO',
        [System.Management.Automation.ErrorRecord]$Exception,
        [switch]$PassThru
    )

    # Create timestamp
    $logMessage = "[$(FormatValue -Format Write)] [$Level] $Message"
    
    # Exception handling
    if ($Exception) {
        $logMessage += "`nEXCEPTION DETAILS:"
        $logMessage += "`n  Type: $($Exception.Exception.GetType().FullName)"
        $logMessage += "`n  Message: $($Exception.Exception.Message)"
        $logMessage += "`n  StackTrace: $($Exception.ScriptStackTrace)"
        if ($Exception.InvocationInfo) {
            $logMessage += "`n  Line: $($Exception.InvocationInfo.ScriptLineNumber)"
            $logMessage += "`n  Position: $($Exception.InvocationInfo.PositionMessage)"
        }
    }

    try {
        if ([string]::IsNullOrEmpty($script:Log)) {
            throw "Logfile null or empty $($script:Log)"
        }
        
        # Write to log file
        $logMessage | Out-File -FilePath $script:Log -Append -Force -Encoding UTF8

    }
    catch {
        Write-Warning "Write-Log failed: $_"
        Write-Warning "Message: $logMessage"
        Write-Warning "Logfile: $script:Log"
    }
}

function Write-Console {
   [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet("header", "info", "status", "done", "warn", "err")]
        [string]$Type = "info",
        [System.Management.Automation.ErrorRecord]$Exception
    )

    # Skip if message is empty or whitespace
    if ([string]::IsNullOrWhiteSpace($Message)) {
        Write-Log -Message "Empty message passed to Write-Console" -Level WARN
        return
    }

    # Map message types to log levels
    $logLevel = switch ($Type) {
        "header" { "INFO" }
        "info"   { "INFO" }
        "done"   { "INFO" }
        "warn"   { "WARN" }
        "err"   { "ERROR" }
    }

    # Always write to log first
    Write-Log -Message "Write-Console: $Message" -Level $logLevel -Exception $Exception

    # Console output with formatting
    switch ($Type) {
        "header" {
            Write-Host "`n------------------------------"
            Write-Host $Message
            Write-Host "------------------------------"
        }
        "info"   { Write-Host "$Message" -ForegroundColor Cyan }
        "done"   { Write-Host "$Message" -ForegroundColor Green }
        "warn"   { Write-Host "[*] $Message" -ForegroundColor Yellow }
        "err"  { 
            $consoleMessage = if ($Exception) {
                "[!] Error: $Message. See log file."
            } else {
                "[!] $Message"
            }
            Write-Host $consoleMessage -ForegroundColor Red
        }
    }
}
#endregion Write

#region Requirements
# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Info "PowerShell 5 or higher required. Current version: $($PSVersionTable.PSVersion)"
    throw
}

# Check Run as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Info "Script requires elevation. Run PowerShell with 'Run As Administrator'."
    throw
}
#endregion Requirements

function Get-ActiveDirectory {
    [CmdletBinding()]
    param()
    
    Write-Console -Message "QUERYING ACTIVE DIRECTORY" -Type header

    try {
        $controls = [Ordered]@{
                        
            'RUNTIME' = {
                try {
                    $system = Get-CimInstance -ClassName Win32_ComputerSystem
                    $networkKey = if ($system.PartOfDomain) {'Domain-joined'} else {'Workgroup-joined'}
                    $networkValue = if ($system.PartOfDomain) {$system.Domain} else {$system.Workgroup}

                    [Ordered]@{
                        'Time ' = FormatValue $script:StartTime -Format Write
                        'Computer' = $env:COMPUTERNAME
                        $networkKey = $networkValue
                        'User' = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                        'OS' = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
                        'PowerShell Application' = $Host.Name
                        'PowerShell Version' = $PSVersionTable.PSVersion
                        'PowerShell Path' = $PSCommandPath
                        'PowerShell Command' = $MyInvocation.MyCommand.Name
                        'Path ($PSCommandPath)' = $PSCommandPath
                        'Path ($MyInvocation)' = $MyInvocation.MyCommand.Path
                        'Line' = $MyInvocation.Line
                        'Working Directory' = (Get-Location).Path
                        'Context' = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                        'Policy' = Get-ExecutionPolicy
                        'Host Name' = $Host.Name
                        'Host Version' = $Host.Version
                        'OS Version' = [System.Environment]::OSVersion.VersionString
                        'CLR Version' = [System.Runtime.InteropServices.RuntimeInformation]::FrameworkDescription
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }

            'FOREST' = {
                Write-Console -Message "$section" -Type info
                try {
                    [Ordered]@{
                        'Name' = $script:ADForest.Name
                        'Mode' = $script:ADForest.ForestMode
                        'RootDomain' = $script:ADForest.RootDomain
                        'Domains' = $script:ADForest.Domains.Count
                        'Sites' = $script:ADForest.Sites.Count
                        'GCs' = $script:ADForest.GlobalCatalogs.Count
                    } | & $script:Export -Name $section -IsSummary # Pipe to supress console output
                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }
    
            'DOMAIN' = {
                Write-Console -Message "$section" -Type info        
                try {
                     @{ 
                        'DNSRoot' = $script:ADDomain.DNSRoot
                        'NetBIOS' = $script:ADDomain.NetBIOSName
                        'Mode' = $script:ADDomain.DomainMode
                        'SID' = $script:ADDomain.DomainSID.Value
                        'DCs' = $script:ADDomain.ReplicaDirectoryServers.Count
                        'RODCs' = $script:ADDomain.ReadOnlyReplicaDirectoryServers.Count
                    } | & $script:Export -Name $section -IsSummary # Pipe to supress console output
                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }

            'DCs' = {
                Write-Console -Message "$section" -Type info        
                try {
                    $DCs = Get-ADDomainController -Filter * | 
                        Select-Object HostName, Name, Enabled, OperationMasterRoles, OperatingSystem, OperatingSystemVersion, 
                                    ComputerObjectDN, IsGlobalCatalog, IsReadOnly, IPv4Address
                
                    $DCs | & $script:Export -Name $section # Export details
                
                    foreach ($dc in $DCs) { # Export summary
                        [ordered]@{
                            'Host' = $dc.HostName
                            'OS' = $dc.OperatingSystem
                        } | & $script:Export -Name $section -IsSummary
                    }
                
                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }

            'BACKUP' = { 
                Write-Console -Message "$section" -Type info
                
                try {
                    # Get partitions
                    $rootDSE = Get-ADRootDSE -Server $script:ADDomain.PDCEmulator
                    $partitions = $rootDSE.namingContexts
                    $detailedData = [System.Collections.ArrayList]@()
                    $summaryData = [System.Collections.ArrayList]@()

                    foreach ($partition in $partitions) {
                        # Get backup timestamp
                        $metadata = Get-ADReplicationAttributeMetadata -Object $partition `
                            -Properties dSASignature -Server $script:ADDomain.PDCEmulator
                        $backup = $metadata.LastOriginatingChangeTime
                        
                        # Determine partition type
                        $partitionContext = switch -Regex ($partition) {
                            "CN=Schema," { "Schema" }
                            "CN=Configuration," { "Configuration" }
                            "DC=DomainDnsZones," { "DomainDNSZones" }
                            "DC=ForestDnsZones," { "ForestDNSZones" }
                            "DC=.*" { "Domain" }
                        }

                        Write-Log -Message "Processing $partitionContext : $backup" -Level DEBUG

                        # Collect detailed data
                        $detailedData.Add([ordered]@{
                            'Type' = $partitionContext
                            'DN' = $partition
                            'LastBackup' = & $script:FormatValue $backup
                            'Age (day)' = if ($backup) {
                                [math]::Round((New-TimeSpan -Start $backup).TotalDays)
                            } else { "Never" }
                        }) > $null

                        # Collect summary data
                        $summaryData.Add([ordered]@{
                            'Partition' = $partitionContext
                            'Last Backup' = & $script:FormatValue $backup
                            'Age (day)' = if ($backup) {
                                [math]::Round((New-TimeSpan -Start $backup).TotalDays)
                            } else { "Never" }
                        }) > $null
                    }

                    # Export all data
                    $detailedData | & $script:Export -Name $section
                    $summaryData | & $script:Export -Name $section -IsSummary

                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }
    
            'FSMO' = {
                Write-Console -Message "$section" -Type info
                try {
                    @{
                        'Schema' = $script:ADForest.SchemaMaster
                        'Naming' = $script:ADForest.DomainNamingMaster
                        'PDC' = $script:ADDomain.PDCEmulator
                        'RID' = $script:ADDomain.RIDMaster
                        'Infra' = $script:ADDomain.InfrastructureMaster
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }

            'TRUSTS' = {
                Write-Console -Message "$section" -Type info
                
                try {
                    $trusts = Get-ADTrust -Filter * -Server $script:ADDomain.PDCEmulator | 
                        Select-Object Source, Target, Direction, IntraForest, SelectiveAuth, 
                            SIDFilteringForestAware, SIDFilteringQuarantinedDirection

                    if ($trusts) {
                        @{
                            'Total' = ($trusts| Measure-Object).Count
                            'Inbound' = ($trusts | Where-Object { $_.Direction -in 'Inbound','Bidirectional' } | Measure-Object).Count
                            'Outbound' = ($trusts | Where-Object { $_.Direction -in 'Outbound','Bidirectional' } | Measure-Object).Count
                            'BiDirectional' = ($trusts | Where-Object { $_.Direction -eq 'Bidirectional' } | Measure-Object).Count
                            'TrustedDomains' = ($trusts.Target | Sort-Object) -join '; '
                        } | & $script:Export -Name $section -IsSummary 

                        $trusts | & $script:Export -Name $section
                    } else {
                        [PSCustomObject]@{
                            Status = "No trusts found"
                        } | & $script:Export -Name "$section-NONE-FOUND" # Pipe to supress console output
                    }
                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }

            'SID500' = {
                Write-Console -Message "$section" -Type info
                
                try {
                    $administrator = Get-ADUser -Identity "$($script:ADDomain.DomainSID.Value)-500" -Properties $script:UserProperties -Server $script:ADDomain.PDCEmulator                
                    [ordered]@{
                        'SamAccountName' = $administrator.SamAccountName
                        'Name' = $administrator.Name
                        'DistinguishedName' = $administrator.DistinguishedName
                        'Enabled' = $administrator.Enabled
                        'LastLogonDate ' = & $script:FormatValue $administrator.LastLogonDate 
                        'LogonAge (days)' = [math]::Round((New-TimeSpan -Start $administrator.LastLogonDate -End (Get-Date)).TotalDays)
                        'PasswordLastSet ' = & $script:FormatValue $administrator.PasswordLastSet
                        'PasswordAge (days)' = [math]::Round((New-TimeSpan -Start $administrator.PasswordLastSet -End (Get-Date)).TotalDays)
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }

            'PRIVILEGED' = {
                Write-Console -Message "$section" -Type info
                
                try {
                    # Initialize tracking
                    $groups = @()
                    $accessPaths = @{}
            
                    foreach ($group in $script:PrivilegedGroups.GetEnumerator()) {
                        Write-Log -Message "Processing: $($group.Key), SID: $($group.Value)" -Level DEBUG
                        
                        $members = & $script:Recursive -GroupSID $group.Value `
                                                          -GroupName $group.Key `
                                                          -SecurityGroup $group.Key `
                                                          -AccessPaths $accessPaths
                        Write-Log -Message "Got members for group $($group.Key): $($members.Count) members" -Level DEBUG

                        if ($members) {
                            $groups += $members
                            
                            # Store statistics in a format usable for $script:Export 
                            @{
                                "$($group.Key) Total" = ($members | Where-Object ObjectType -eq 'User' | Sort-Object -Unique SamAccountName).Count
                               } | & $script:Export -Name $section -IsSummary
            
                            @{
                                "$($group.Key) Disabled" = ($members | Where-Object { $_.ObjectType -eq 'User' -and -not $_.Enabled } | Sort-Object -Unique SamAccountName).Count
                            } | & $script:Export -Name $section -IsSummary
                        }
                    }
                    
                    $pre2000SID = "S-1-5-32-554" # Pre-Windows 2000 Compatible Access group (direct members only)
                    try {
                        $pre2000Group = Get-ADGroup -Identity $pre2000SID -Properties Members -Server $script:ADDomain.PDCEmulator
                        $pre2000Members = Get-ADGroupMember -Identity $pre2000SID -Server $script:ADDomain.PDCEmulator
                        
                        if ($pre2000Members) {
                            foreach ($member in $pre2000Members) {
                                if ($member.objectClass -eq 'user') {
                                    $userDetails = Get-ADUser $member -Properties Enabled,LastLogonDate,PasswordLastSet
                                    $groups += [PSCustomObject]@{
                                        SamAccountName = $member.SamAccountName
                                        ObjectType = "User"
                                        Enabled = $userDetails.Enabled
                                        LastLogonDate = $userDetails.LastLogonDate
                                        PasswordLastSet = $userDetails.PasswordLastSet
                                        SecurityGroup = "Pre-Windows 2000 Compatible Access"
                                        Path = "Direct Member"
                                    }
                                    $accessPaths[$member.SamAccountName] = @{
                                        "Pre-Windows 2000 Compatible Access" = "Direct Member"
                                    }
                                }
                            }
                            
                            @{
                                "Pre-Windows 2000 Compatible Access Total" = ($pre2000Members | Where-Object objectClass -eq 'user').Count
                            } | & $script:Export -Name $section -IsSummary

                            @{
                                "Pre-Windows 2000 Compatible Access Disabled" = ($pre2000Members | 
                                    Where-Object objectClass -eq 'user' | 
                                    ForEach-Object { Get-ADUser $_ -Properties Enabled } | 
                                    Where-Object { -not $_.Enabled }).Count
                            } | & $script:Export -Name $section -IsSummary
                        }
                    } catch {
                        Write-Info -m "Pre-Windows 2000 group" -lvl warn -ex $_
                    }

                    Write-Info -m "Creating matrix for $($accessPaths.Count) accounts"
                    
                    # Privileged user matrix
                    $script:PrivilegedUsers = @()
                    foreach ($account in $accessPaths.Keys | Sort-Object) {
                        Write-Log -Message "Processing account: $account" -Level DEBUG
                        $member = $groups | Where-Object SamAccountName -eq $account | Select-Object -First 1
                        
                        if ($null -eq $member) {
                            continue
                        }
                        
                        if ($member.ObjectType -eq 'User') {
                            $obj = [PSCustomObject]@{
                                SamAccountName = $account
                                ObjectType = "User"
                                Enabled = $member.Enabled
                                LastLogonDate = & $script:FormatValue $member.LastLogonDate
                                PasswordLastSet = & $script:FormatValue $member.PasswordLastSet
                            }
                            
                            foreach ($group in $script:PrivilegedGroups.Keys) {
                                $value = if ($accessPaths[$account].ContainsKey($group)) { 
                                    $accessPaths[$account][$group] 
                                } else { 
                                    "" 
                                }
                                $obj | Add-Member -NotePropertyName $group -NotePropertyValue $value
                            }
                            
                            $script:PrivilegedUsers += $obj
                        }
                    }
            
                    # Export summary data through Export
                    foreach ($key in $summary.Keys) {
                        [PSCustomObject]@{
                            'Category' = $section
                            'Setting' = $key
                            'Value' = $summary[$key]
                        } | & $script:Export -Name $section -IsSummary
                    }

                    # Export hierarchicy directly (Export can't handle nested objects)
                    try {
                        $groupPath = Join-Path $script:Directory "$($script:filename)-$section-GROUPS.csv"
                        $groups | Export-Csv -Path $groupPath -NoTypeInformation

                    } catch {
                        Write-Log -Message "Failed exporting: '$groupPath': $_" -Level ERROR
                        throw  # Throw to outer catch
                    }

                    try {
                        $userPath = Join-Path $script:Directory "$($script:filename)-$section-USER_MATRIX.csv"
                        $script:PrivilegedUsers | Export-Csv -Path $userPath -NoTypeInformation

                    } catch {
                        Write-Log -Message "Failed exporting: '$path': $_" -Level ERROR
                        throw  # Throw to outer catch
                    }
                    
                } catch {
                    Write-Log -Message "Error in '$section': $_ " -Level ERROR
                    & $script:Error $section "Failed to gather $section"
                }
            }

            'USERS' = {
                Write-Console -Message "USERS" -Type info
                
                try {
                    $users = Get-ADUser -Filter * -Properties $script:UserProperties -Server $script:ADDomain.PDCEmulator

                    if ($users) {
                        $users | & $script:Export -Name $section # Export details

                        [ordered]@{ # Export summary
                            'Total' = ($users | Measure-Object).Count
                            'Enabled' = ($users | Where-Object {$_.Enabled}).Count
                            'Disabled' = ($users | Where-Object {-not $_.Enabled}).Count
                            'Locked' = ($users | Where-Object {$_.lockoutTime -gt 0}).Count
                            'PasswordExpired' = ($users | Where-Object {$_.PasswordExpired}).Count
                            'Stale' = ($users | Where-Object {
                                $_.LastLogonDate -and $_.PasswordLastSet -and 
                                ((New-TimeSpan -Start $_.LastLogonDate -End (Get-Date)).TotalDays -ge $script:LogonAge) -and
                                ((New-TimeSpan -Start $_.PasswordLastSet -End (Get-Date)).TotalDays -ge $script:PasswordAge)
                            } ).Count
                            'INTERDOMAIN_TRUST_ACCOUNT' = ($users | Where-Object {$_.UserAccountControl -band 0x0800}).Count
                            'PASSWD_NOTREQD' = ($users | Where-Object {$_.UserAccountControl -band 0x0020}).Count
                            'PASSWD_CANT_CHANGE' = ($users | Where-Object {$_.UserAccountControl -band 0x0040}).Count
                            'ENCRYPTED_TEXT_PWD_ALLOWED' = ($users | Where-Object {$_.UserAccountControl -band 0x0080}).Count
                            'DONT_EXPIRE_PASSWORD' = ($users | Where-Object {$_.UserAccountControl -band 0x10000}).Count
                            'TRUSTED_FOR_DELEGATION' = ($users | Where-Object {$_.UserAccountControl -band 0x80000}).Count
                            'NOT_DELEGATED' = ($users | Where-Object {$_.UserAccountControl -band 0x10000}).Count
                            'USE_DES_KEY_ONLY' = ($users | Where-Object {$_.UserAccountControl -band 0x200000}).Count
                            'DONT_REQ_PREAUTH' = ($users | Where-Object {$_.UserAccountControl -band 0x400000}).Count
                            'PASSWORD_EXPIRED' = ($users | Where-Object {$_.UserAccountControl -band 0x800000}).Count
                        } | & $script:Export -Name $section -IsSummary
                    } else {
                        @{
                            'Total' = 'No user objects found'
                        } | & $script:Export -Name $section-NONE-FOUND -IsSummary
                    }
                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }
            
            'TOMBSTONE' = {
                Write-Console -Message "$section" -Type info
                
                try {
                    $tombstone = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" `
                        -Properties tombstoneLifetime -Server $script:ADDomain.PDCEmulator
                    
                    @{
                        'TombstoneLifetime (day)' = [int]$tombstone.tombstoneLifetime
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }
    
            'DSHEURISTICS' = {
                Write-Console -Message "$section" -Type info
                
                try {
                    $configuration = (Get-ADRootDSE).configurationNamingContext
                    $ds = Get-ADObject -Filter 'objectClass -eq "nTDSService"' `
                        -SearchBase $configuration -Properties dSHeuristics -Server $script:ADDomain.PDCEmulator
                    
                    @{
                        'Attribute' = if ($ds.dSHeuristics) { $ds.dSHeuristics } else { "<null>" }
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }

            'PASSWORDPOLICY' = {
                Write-Console -Message "$section" -Type info
                
                try {
                    $policy = Get-ADDefaultDomainPasswordPolicy -Server $script:ADDomain.PDCEmulator
                    
                    @{
                        'ComplexityEnabled' = $policy.ComplexityEnabled
                        'MinPasswordLength' = $policy.MinPasswordLength
                        'MaxPasswordAge (day)' = $policy.MaxPasswordAge.TotalDays
                        'MinPasswordAge (day)' = $policy.MinPasswordAge.TotalDays
                        'LockoutThreshold' = $policy.LockoutThreshold
                        'LockoutDuration (min)' = $policy.LockoutDuration.TotalMinutes
                        'PasswordHistoryCount' = $policy.PasswordHistoryCount
                        'ReversibleEncryptionEnabled' = $policy.ReversibleEncryptionEnabled
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }

            'GROUPPOLICY' = {
                Write-Console -Message "$section" -Type info
    
                try {
                    
                    # Create subfolder
                    try {
                        New-Item -Path $script:GPODirectory -ItemType Directory -Force > $null
                    } catch {
                        Write-Log -Message "Failed creating $($script:GPODirectory)" -Level WARN
                    }
                    
                    # Get GPOs
                    try {
                        $Gpos = Get-GPO -All -Server $script:ADDomain.PDCEmulator
                        Write-Log -Message "GPOs: $($Gpos.Count)" -Level INFO
                    } catch {
                        Write-Log -Message "Failed gahtering GPOs" -Level WARN
                    }
                    
                    if ($Gpos) {
                        foreach ($gpo in $Gpos) {
                            # Export GPOs
                            try {
                                [xml]$reports = Get-GPOReport -ReportType Xml -Guid $gpo.Id -Server $script:ADDomain.PDCEmulator
                                if ($null -ne $reports.GPO.Name) {
                                    Get-GPOReport -Name $reports.GPO.Name -ReportType Html -Path (Join-Path $script:GPODirectory "$($reports.GPO.Name).html") -Server $script:ADDomain.PDCEmulator
                                    Get-GPOReport -Name $reports.GPO.Name -ReportType Xml -Path (Join-Path $script:GPODirectory "$($reports.GPO.Name).xml") -Server $script:ADDomain.PDCEmulator
                                    Write-Log -Message "Exported $($reports.GPO.Name)" -Level INFO
                                }
                            } catch {
                                Write-Log -Message "Failed exporting $($gpo.DisplayName)" -Level WARN
                            }
                            
                            try { # Security groups applied to
                                $security = $gpo.GetSecurityInfo($true)  # $true includes inherited permissions
                                $permissions = @($security | ForEach-Object {
                                    $source = if ($_.Inherited) { 
                                        "Inherited" 
                                    } else { 
                                        "Direct"
                                    }
                                    "$($_.Trustee) ($($_.TrusteeType)) [$source] - $($_.Permission)"
                                } | Sort-Object)
                            } catch {
                                $permissions = @("Error getting permissions")
                                Write-Log -Message "Failed gathering permissions: $($gpo.DisplayName)" -Level WARN
                            }
                            
                            try { # OUs linked to
                                $links = $gpo.GetReport().LinksTo | ForEach-Object { $_.SOMPath }
                            } catch {
                                $links = @("Error getting links")
                                Write-Log -Message "Error getting linked OUs: $($gpo.DisplayName)" -Level WARN
                            }

                            # Export details
                            try {
                                [ordered]@{
                                    'Name' = $gpo.DisplayName
                                    'Owner' = $gpo.Owner
                                    'Status' = $gpo.GpoStatus
                                    'Linked OUs' = $links -join '; '
                                    'Security Filtering' = $permissions -join '; '
                                    'Description' = $gpo.Description
                                    'CreationTime' = & $script:FormatValue $gpo.CreationTime
                                    'ModificationTime' = & $script:FormatValue $gpo.ModificationTime
                                    'UserVersion' = $gpo.User.DSVersion
                                    'ComputerVersion' = $gpo.Computer.DSVersion
                                    'WmiFilter' = if ($gpo.WmiFilter) { $gpo.WmiFilter.Name } else { "None" }
                                    'ID' = $gpo.Id
                                } | & $script:Export -Name $section
                            } catch {
                                Write-Log -Message "Failed exporting: $($gpo.DisplayName) $_" -Level ERROR
                            }
                            
                            # Export summary
                            [ordered]@{
                                'Total' = $Gpos.Count
                                'Disabled' = ($Gpos | Where-Object { $_.GpoStatus -eq 'AllSettingsDisabled' }).Count
                                'Orphaned' = ($Gpos | Where-Object { 
                                    try { 
                                        -not $_.GetReport().LinksTo 
                                    } catch { 
                                        $true 
                                    }
                                }).Count
                            } | & $script:Export -Name $section -IsSummary

                        } 
                    } else {
                        [PSCustomObject]@{
                        } | & $script:Export -Name "$section-NONE-FOUND"
                    }
                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }

            'KRBTGT' = {
                Write-Console -Message "$section" -Type info

                try {
                    $krbtgt = Get-ADUser 'krbtgt' -Properties PasswordLastSet -Server $script:ADDomain.PDCEmulator
                    @{
                        'PasswordLastSet' = FormatValue $krbtgt.PasswordLastSet -Format Write
                        'Age (day)' = [math]::Round(((Get-Date) - (Get-ADUser 'krbtgt' -Properties PasswordLastSet -Server $script:ADDomain.PDCEmulator).PasswordLastSet).TotalDays)
                    } | & $script:Export -Name $section -IsSummary
                } catch {
                    & $script:Error $section "Failed to check KRBTGT account"
                }
            }
    
            'DELAGATION' = {
                Write-Console -Message "$section" -Type info
                
                try {
                    $delegatedAccounts = Get-ADObject -Filter {
                        ((UserAccountControl -BAND 0x0080000) -OR 
                        (UserAccountControl -BAND 0x1000000) -OR 
                        (msDS-AllowedToDelegateTo -like '*') -OR 
                        (msDS-AllowedToActOnBehalfOfOtherIdentity -like '*')) -AND 
                        (PrimaryGroupID -ne '516') -AND 
                        (PrimaryGroupID -ne '521')
                    } -Properties @(
                        "sAMAccountName", "Name", "ObjectClass", "PrimaryGroupID", 
                        "UserAccountControl", "ServicePrincipalName", 
                        "msDS-AllowedToDelegateTo", 
                        "msDS-AllowedToActOnBehalfOfOtherIdentity",
                        "DistinguishedName", "CanonicalName"
                    ) -Server $script:ADDomain.PDCEmulator

                    if ($delegatedAccounts) {
                        $delegatedAccounts | ForEach-Object {
                            [PSCustomObject]@{
                                'Name' = $_.Name
                                'DistinguishedName' = $_.DistinguishedName
                                'Type' = $(switch ($true) {
                                    { $_.UserAccountControl -BAND 0x0080000 } { 'Unconstrained' }
                                    { $_.UserAccountControl -BAND 0x1000000 } { 'Constrained with Protocol Transition' }
                                    { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' } { 'Resource-Based Constrained' }
                                    { $_.'msDS-AllowedToDelegateTo' } { 'Constrained' }
                                    default { 'Unknown' }
                                })
                                'Scope' = if ($_.UserAccountControl -BAND 0x0080000) { 
                                    'All Services' 
                                } else { 
                                    'Specific Services' 
                                }
                                'Protocol' = if ($_.UserAccountControl -BAND 0x1000000) {
                                    'Any (Protocol Transition)'
                                } else {
                                    'Kerberos'
                                }
                                'ServicePrincipalName' = $_.ServicePrincipalName -join '; '
                                'DelegatedServices' = if ($_.'msDS-AllowedToDelegateTo') {
                                    $_.'msDS-AllowedToDelegateTo' -join '; '
                                } else {
                                    'N/A'
                                }
                            } | & $script:Export -Name $section
                        }

                        # Add summary
                        [ordered]@{
                            'Total' = $delegatedAccounts.Count
                            'Unconstrained' = ($delegatedAccounts | Where-Object { $_.UserAccountControl -BAND 0x0080000 }).Count
                            'Constrained' = ($delegatedAccounts | Where-Object { $_.'msDS-AllowedToDelegateTo' }).Count
                            'Resource-Based' = ($delegatedAccounts | Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' }).Count
                        } | & $script:Export -Name $section -IsSummary
                    } else {
                        [PSCustomObject]@{
                            'Status' = "No Kerberos Delegation Found"
                        } | & $script:Export -Name "$section-NONE-FOUND"
                    }
                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }
 
            'MSA' = {
                Write-Log -Message "Standalone and group managed service accounts" -Level INFO
                
                try {
                    # Get both types
                    $sMSA = Get-ADObject -Filter 'ObjectClass -eq "msDS-ManagedServiceAccount"' `
                        -Properties @(
                            "Name", "ObjectClass", "SamAccountName", "Created",
                            "Modified", "Description", "DNSHostName", "Enabled",
                            "MemberOf", "msDS-HostServiceAccount"
                        )

                    $gMSA = Get-ADObject -Filter 'ObjectClass -eq "msDS-GroupManagedServiceAccount"' `
                        -Properties @(
                            "Name", "ObjectClass", "SamAccountName", "Created",
                            "Modified", "Description", "DNSHostName", "Enabled",
                            "MemberOf", "msDS-GroupMSAMembership"
                        )

                    if ($sMSA -or $gMSA) {
                        $sMSA | ForEach-Object {
                            $hostComputers = $_.'msDS-HostServiceAccount' | ForEach-Object {
                                (Get-ADComputer $_).Name
                            }

                            [PSCustomObject]@{
                                Name = $_.Name
                                Type = "sMSA"
                                'Created ' = FormatValue $_.Created -Format Write
                                'Modified ' = FormatValue $_.Modified -Format Write
                                HostName = $_.DNSHostName
                                Enabled = $_.Enabled
                                Computers = $hostComputers -join '; '
                                Members = ($_.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }) -join '; '
                            } | & $script:Export -Name $section
                        }

                        $gMSA | ForEach-Object {
                            $principals = $_.'msDS-GroupMSAMembership' | ForEach-Object {
                                (Get-ADObject $_).Name
                            }

                            [PSCustomObject]@{
                                Name = $_.Name
                                Type = "gMSA"
                                Created = FormatValue $_.Created -Format Write
                                Modified = FormatValue $_.Modified -Format Write
                                HostName = $_.DNSHostName
                                Enabled = $_.Enabled
                                Principals = $principals -join '; '
                                Members = ($_.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }) -join '; '
                            } | & $script:Export -Name $section
                        }
                    } else { # No MSAs found
                        [PSCustomObject]@{
                        } | & $script:Export -Name "$section-NONE-FOUND"
                    }

                    # Generate summary statistics
                    @{
                        'SMA' = ($sMSA | Measure-Object).Count
                        'gMSA' = ($gMSA | Measure-Object).Count
                        'Total' = ($sMSA | Measure-Object).Count + ($gMSA | Measure-Object).Count
                    } | & $script:Export -Name $section -IsSummary

                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }
    
            'SPN' = {
                Write-Log -Message "Service Principal Names" -Level INFO
                
                try {
                    # Get all objects with SPNs
                    $spnObjects = Get-ADObject -Filter { ServicePrincipalName -like "*" } -Properties @(
                        'ServicePrincipalName', 'ObjectClass', 'Name', 'DistinguishedName',
                        'SamAccountName', 'UserAccountControl'
                    )

                    if ($spnObjects) {
                        # Cross-reference with privileged users
                        $privilegedSPNs = $spnObjects | Where-Object {
                            $_.ObjectClass -eq 'user' -and
                            $_.SamAccountName -in $script:PrivilegedUsers.SamAccountName
                        }

                        if ($privilegedSPNs) { # Export privileged accounts
                            try {
                                $privilegedSPNs | ForEach-Object {
                                    [PSCustomObject]@{
                                        Name = $_.Name
                                        SamAccountName = $_.SamAccountName
                                        SPNs = $_.ServicePrincipalName -join ';'
                                    }
                                } | & $script:Export -Name "$section-PRIVILEGED"
                            } catch {
                                & $script:Error $section "Failed exporting $section-PRIVILEGED"
                            }
                        }
                        else {
                            [PSCustomObject]@{
                            } | & $script:Export -Name "$section-PRIVILEGED-NONE-FOUND"
                        }

                        # Export duplicates
                        $spnCheck = SetSPN -X -F
                        if (-not ($spnCheck -like "*found 0 group of duplicate SPNs*")) {
                            $duplicates = $spnCheck | Where-Object { 
                                $_ -notlike "Checking forest*" -and 
                                $_ -notlike "Operation will be*" -and 
                                $_ -notlike "Processing entry*" -and
                                $_ -notlike "found * group of duplicate SPNs*"
                            }
                            
                            if ($duplicates) {
                                $duplicates | & $script:Export -Name "$section-DUPLICATE"
                            }
                        } else {
                            [PSCustomObject]@{
                            } | & $script:Export -Name "$section-DUPLICATE-NONE-FOUND"
                        }

                    } else {
                        [PSCustomObject]@{
                        } | & $script:Export -Name "$section-NONE-FOUND"
                    }

                    # Generate summary
                    @{
                        'Total' = ($spnObjects | ForEach-Object { $_.ServicePrincipalName.Count } | Measure-Object -Sum).Sum
                        'Objects' = ($spnObjects | Measure-Object).Count
                        'Privileged' = ($privilegedSPNs | Measure-Object).Count
                        'Duplicate' = ($duplicateSPNs | Measure-Object).Count
                    } | & $script:Export -Name $section -IsSummary

                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }

            'FGPP' = {
                Write-Log -Message "Fine-grained password policies" -Level INFO
                
                try {
                    # Get fine-grained policies 
                    $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * -Server $script:ADDomain.PDCEmulator
                    
                    if ($fgpp) {
                        $fgpp | ForEach-Object {
                            $policy = $_
                            
                            # Get groups applied to
                            $appliesTo = Get-ADFineGrainedPasswordPolicySubject -Identity $policy
                            
                            # Get members of each group using recursive function
                            $fgppMembers = $appliesTo | ForEach-Object {
                                $fgppGroup = Get-ADGroup $_ -Properties Name -Server $script:ADDomain.PDCEmulator
                                
                                & $script:Recursive -GroupSID $fgppGroup.SID `
                                                    -GroupName $fgppGroup.Name `
                                                    -SecurityGroup $fgppGroup.Name `
                                                    -AccessPaths @{}
                            }

                            # Add the group membership properties to the policy object
                            $policy | Add-Member -NotePropertyName 'AffectedUsers' -NotePropertyValue (if ($fgppMembers) { ($fgppMembers | Where-Object ObjectType -eq 'User' | Select-Object -ExpandProperty Name -Unique | Sort-Object) -join '; ' } else { 'None' })
                            $policy | Add-Member -NotePropertyName 'AffectedGroups' -NotePropertyValue (if ($fgppMembers) { ($fgppMembers | Where-Object ObjectType -eq 'Group' | Select-Object -ExpandProperty Name -Unique | Sort-Object) -join '; ' } else { 'None' })
                            $policy | Add-Member -NotePropertyName 'TotalAffectedUsers' -NotePropertyValue (if ($fgppMembers) { ($fgppMembers | Where-Object ObjectType -eq 'User' | Select-Object -Unique).Count } else { 0 })
                            $policy | Add-Member -NotePropertyName 'TotalAffectedGroups' -NotePropertyValue (if ($fgppMembers) { ($fgppMembers | Where-Object ObjectType -eq 'Group' | Select-Object -Unique).Count } else { 0 })

                            # Output the enhanced policy object
                            $policy | & $script:Export -Name $section
                        }
                        
                        @{
                            'Policies' = ($fgpp).Count
                        } | & $script:Export -Name $section -IsSummary
                        
                    } else {
                        # Still output empty policy for detailed report
                        [PSCustomObject]@{
                            'Name' = 'No Fine-Grained Password Policies Found'
                            'AffectedUsers' = 'None'
                            'AffectedGroups' = 'None'
                            'TotalAffectedUsers' = 0
                            'TotalAffectedGroups' = 0
                        } | & $script:Export -Name $section

                        @{
                            'PolicyCount' = 0
                        } | & $script:Export -Name $section -IsSummary
                    }
                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }

            'SYSVOL' = {
                Write-Console -Message "SYSVOL"
                
                try {
                    $results = foreach ($dc in $script:DCs) {
                        Write-Log -Message "Processing SYSVOL on $($dc.Name)" -Level INFO
                        
                        try {
                            # Recursively enumerate SYSVOL folders with depth limit
                            $allFolders = Get-ChildItem -Path "\\$($dc.Name)\SYSVOL" -Directory -Recurse -Depth 2
                            
                            foreach ($folder in $allFolders) {
                                # Get ACL information for each folder
                                $acl = Get-Acl -Path $folder.FullName
                                
                                # Filter out standard/built-in permissions
                                $acl.Access | 
                                    Where-Object { 
                                        @("BUILTIN\Administrators", "NT AUTHORITY\SYSTEM", "CREATOR OWNER") -notcontains $_.IdentityReference -and 
                                        $_.FileSystemRights -notmatch "^-?[\d\.]+$" 
                                    } | 
                                    ForEach-Object {
                                        # Create custom permission entry
                                        [PSCustomObject]@{
                                            'DC' = $dc.Name
                                            'Folder' = $folder.FullName
                                            'Identity' = $_.IdentityReference
                                            'Permissions' = $_.FileSystemRights
                                            'Inherited' = $_.IsInherited
                                        }
                                    }
                            }
                        } catch {
                            Write-Log -Message "Failed to process DC: $($dc.Name): $_" -Level WARN
                            continue
                        }
                    }
                    
                    if ($results) {
                        # Detailed export
                        $results | & $script:Export -Name $section
                        
                        # Summary export
                        @{
                            'DCs Processed' = ($script:DCs | Measure-Object).Count
                            'Custom Permissions' = ($results | Measure-Object).Count
                        } | & $script:Export -Name $section -IsSummary
                    } else { # Mo custom permissions found
                        @{
                            'DCs Processed' = ($script:DCs).Count
                            'Custom Permissions' = 0
                        } | & $script:Export -Name $section -IsSummary
                    }
                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }

            'LOGGING' = {
                Write-Console -Message "LOGGING"
            
                try {
                    # Initialize Windows API
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

                    # Get policies
                    function Get-PolicyInfo($sub) {
                        $pol = new-object AUDIT_POLICY_INFORMATION
                        $size = $ms::SizeOf($pol)
                        $ptr = $ms::AllocHGlobal($size)
                        $null = $ms::StructureToPtr($pol, $ptr, $false)
                        $null = $auditpol::AuditQuerySystemPolicy($sub, 1, [ref]$ptr)
                        $pol = $ms::PtrToStructure($ptr, [type][AUDIT_POLICY_INFORMATION])
                        $null = $ms::FreeHGlobal($ptr)
                        [PsCustomObject]@{
                            category = $pol.AuditCategoryGuid
                            success = [bool]($pol.AuditingInformation -band 1)
                            failure = [bool]($pol.AuditingInformation -band 2)
                        }
                    }

                    # Get categories
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

                    # Get subcategories
                    $guid = [guid]::Empty
                    $null = $auditpol::AuditEnumerateSubCategories($guid, $true, [ref]$buffer, [ref]$count)
                    $ptr = [int64]$buffer
                    $results = @()
                    foreach($id in 1..$count) {
                        $guid = $ms::PtrToStructure([IntPtr]$ptr,[type][guid])
                        $null = $auditpol::AuditLookupSubCategoryName($guid,[ref]$name)
                        $pol = Get-PolicyInfo $guid
                        
                        $results += [PSCustomObject]@{
                            Category = $catList[$pol.category]
                            Subcategory = $name.ToString()
                            Success = $pol.success
                            Failure = $pol.failure
                        }
                        $ptr += $size
                    }

                    # Detailed export
                    $results | & $script:Export -Name $section
                    
                    # Summary export
                    @{
                        'Total' = ($results | Measure-Object).Count
                        'Success' = ($results | Where-Object Success | Measure-Object).Count
                        'Failure' = ($results | Where-Object Failure | Measure-Object).Count
                    } | & $script:Export -Name $section -IsSummary
                    
                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }

            'COMPUTERS' = {
                Write-Console -Message "COMPUTERS" -Type info
                
                try {
                    # Query all computer objects
                    $computers = Get-ADComputer -Filter * -Properties @(
                        'Name', 'DistinguishedName', 'OperatingSystem', 
                        'OperatingSystemVersion', 'LastLogonDate', 'Enabled',
                        'TrustedForDelegation', 'whenCreated'
                    ) -Server $script:ADDomain.PDCEmulator

                    if ($computers) {
                        # Process and format computer information
                        $computerInfo = $computers | Select-Object `
                            Name,
                            DistinguishedName,
                            @{ Name = 'OS'; Expression = {$_.OperatingSystem} },
                            @{ Name = 'OSVersion'; Expression = {$_.OperatingSystemVersion} },
                            @{ Name = 'LastLogonDate'; Expression = {FormatValue $_.LastLogonDate -Format Write} },
                            @{ Name = 'Status'; Expression = {if ($_.Enabled) {'Enabled'} else {'Disabled'}} },
                            TrustedForDelegation,
                            @{ Name = 'Created'; Expression = {FormatValue $_.whenCreated -Format Write} }

                        # Export detailed computer information
                        $computerInfo | & $script:Export -Name $section

                        # Calculate summary metrics
                        $total = ($computers | Measure-Object).Count
                        $disabled = ($computers | Where-Object {-not $_.Enabled} | Measure-Object).Count
                        $delegated = ($computers | Where-Object {$_.TrustedForDelegation} | Measure-Object).Count
                        $stale = ($computers | Where-Object {
                            $_.LastLogonDate -and 
                            $_.LastLogonDate -lt (Get-Date).AddDays(-90)
                        } | Measure-Object).Count

                        # Export summary information
                        @{
                            'Total' = $total
                            'Disabled' = $disabled
                            'Delegated' = $delegated
                            'Stale' = $stale
                        } | & $script:Export -Name $section -IsSummary
                    } else {
                        # Record when no computer objects are found
                        @{
                            'Total' = 'No computer objects found'
                        } | & $script:Export -Name $section -IsSummary
                    }
                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }

            'SPOOLER' = {
                Write-Log -Message "Checking print spooler status on DCs" -Level INFO
                
                try {
                    $script:DCs | ForEach-Object {
                        try {
                            $spoolerService = Get-Service -ComputerName $_.Name -Name Spooler
                            $startupConfig = (Get-WmiObject -Class Win32_Service -Filter "Name='Spooler'" -ComputerName $_.Name).StartMode
                            
                            [PSCustomObject]@{
                                DC = $_.Name
                                Host = $_.HostName
                                Site = $_.Site
                                Status = $spoolerService.Status
                                Startup = $startupConfig
                                Error = $null
                                IsSummary = $true
                            }
                        } catch {
                            Write-Log -Message "Spooler checked failed: $($_.Name): $_" -Level WARN
                            [PSCustomObject]@{
                                DC = $_.Name
                                Host = $_.HostName
                                Site = $_.Site
                                Status = "Error"
                                Startup = "Unknown"
                                Error = $_.Exception.Message
                                IsSummary = $true
                            } 
                        }
                    } | & $script:Export -Name $section -Description "Print Spooler"
                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }

            'NETWORK' = {
                Write-Console -Message "$section" -Type info
                
                try {
                    # Registry keys to fetch
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

                    $results = foreach ($dc in $script:DCs) {
                        Write-Log -Message "Gathering registry on $($dc.Name)" -Level INFO
                        
                        # Check registry values
                        foreach ($reg in $registryKeys) {
                            foreach ($key in $reg.Keys) {
                                try {
                                    $value = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                                        param($path, $key)
                                        try {
                                            $val = Get-ItemProperty -Path $path -Name $key -ErrorAction Stop
                                            if ($null -eq $val.$key) {
                                                return "<null>"
                                            }
                                            return $val.$key
                                        } catch {
                                            return "Not Found"
                                        }
                                    } -ArgumentList $reg.Path, $key -ErrorAction Stop

                                    # Store result for summary counting
                                    $result = [ordered]@{
                                        'Server' = $dc.Name
                                        'Setting' = "Registry"
                                        'Key' = $key
                                        'Path' = $reg.Path
                                        'Value' = $value
                                    }
                                    $result | & $script:Export -Name $section
                                    $result # Output for results collection
                                } catch {
                                    Write-Log -Message "Failed checking registry on $($dc.Name) for $key : $_" -Level WARN
                                    $result = [ordered]@{
                                        'Server' = $dc.Name
                                        'Setting' = "Registry"
                                        'Key' = $key
                                        'Path' = $reg.Path
                                        'Value' = "Error: Unable to connect"
                                    }
                                    $result | & $script:Export -Name $section
                                    $result # Output for results collection
                                }
                            }
                        }

                        # Check security policy
                        try {
                            $lsaValue = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                                $tempPath = Join-Path $env:TEMP "secexport.cfg"
                                try {
                                    $null = secedit /export /cfg $tempPath
                                    if (Test-Path $tempPath) {
                                        $content = Get-Content $tempPath
                                        $lookup = $content | Select-String "LSAAnonymousNameLookup"
                                        if ($lookup) {
                                            return $lookup.ToString().Split('=')[1].Trim()
                                        }
                                        return "Not Found"
                                    }
                                    return "Export Failed"
                                } catch {
                                    return "Error: $_"
                                } finally {
                                    if (Test-Path $tempPath) {
                                        Remove-Item -Path $tempPath -Force
                                    }
                                }
                            } 

                            $result = [ordered]@{
                                'Server' = $dc.Name
                                'Setting' = "Security Policy"
                                'Key' = "LSAAnonymousNameLookup"
                                'Path' = "secedit /export"
                                'Value' = $lsaValue
                            }
                            $result | & $script:Export -Name $section
                            $result # Output for results collection
                        } catch {
                            Write-Log -Message "Failed secedit export on $($dc.Name): $_" -Level WARN
                            $result = [ordered]@{
                                'Server' = $dc.Name
                                'Setting' = "Security Policy"
                                'Key' = "LSAAnonymousNameLookup"
                                'Path' = "secedit /export"
                                'Value' = "Error: Unable to connect"
                            }
                            $result | & $script:Export -Name $section
                            $result # Output for results collection
                        }
                    }

                    # Export summary
                    [ordered]@{
                        'Total Checks' = $results.Count
                        'Successful' = ($results | Where-Object { $_.Value -notlike "Error:*" }).Count
                        'Failed' = ($results | Where-Object { $_.Value -like "Error:*" }).Count
                    } | & $script:Export -Name $section -IsSummary

                } catch {
                    & $script:Error $section "Failed gathering $section"
                }
            }
        }    
        
        # Process each section
        $sectionsToProcess = $controls.Keys
        foreach ($section in $sectionsToProcess) {
            Write-Log -Message "Processing section: $section" -Level DEBUG
            
            try {
                $scriptBlock = $controls[$section]
                if ($scriptBlock -is [ScriptBlock]) {
                    & $scriptBlock
                } else {
                    Write-Log -Message "Invalid scriptblock for section: $section" -Level WARN
                    @{
                        'Section' = $section
                        'Error' = "Invalid scriptblock"
                    } | & $script:Export -Name $section
                }
            } catch {
                Write-Log -Message "Failed processing $($section): $_" -Level ERROR
                @{
                    'Section' = $section
                    'Error' = $_.Exception.Message
                } | & $script:Export -Name $section
            }
        }
    
        Write-Log -Message "Get-BRAVE successfully completed" -Level INFO
        Write-Console -Message "DONE" -Type done

    } catch {
        Write-Log -Message "Get-BRAVE Outtermost catch block failed $_" -Level ERROR
        Write-Console -Message "Error gathering Active Directory details" -Type warn
    }
}

function Get-CertificateServices {
    [CmdletBinding()]
    param()
    
    Write-Console -Message "GATHERING CERTIFICATE SERVICES" -Type header
    
    # Basic sanity check
    try {
        $caCheck = certutil -ping
        if ($LASTEXITCODE -ne 0) {
            Write-Log -Message "ADCS not found: $LASTEXITCODE" -Level DEBUG
            Write-Console -Message "No Certificate Services" -Type done
            
            @{
                'CAs' = 0
                'Status' = 'None found'
            } | & $script:Export -Name "ADCS" -IsSummary

            return
        }

        # Check PSPKI module
        $pspkiStatus = Test-ModuleAvailability -ModuleName $script:CertModule
        if ($pspkiStatus -ne "Ready") {
            Write-Console -Message "PSPKI module not available" -Type warn
            
            @{
                'CAs' = 0
                'Status' = 'PSPKI module not available'
            } | & $script:Export -Name "ADCS" -IsSummary
            
            return
        }
    } catch {
        Write-Log -Message "Error checking Certificate Services: $_" -Level WARN
        Write-Console -Message "Error checking Certificate Services" -Type warn
        
        @{
            'CAs_Found' = 0
            'Status' = 'Error checking Certificate Services'
        } | & $script:Export -Name "CertificateServices" -IsSummary
        
        return
    }

    # Define output paths
    $outputPaths = @{
        Templates    = Join-Path $script:Directory "$($script:filename)-ADCS-Templates.csv"
        Enrollment   = Join-Path $script:Directory "$($script:filename)-ADCS-Enrollment.csv"
        Permissions  = Join-Path $script:Directory "$($script:filename)-ADCS-EnrollmentPermissions.csv"
        NTAuth       = Join-Path $script:Directory "$($script:filename)-ADCS-NTAuth.csv"
        Logging      = Join-Path $script:Directory "$($script:filename)-ADCS-Logging.csv"
    }

    try { # Main CA assessment block
        Write-Log -Message "Initiating CA discovery"
        $cas = Get-CA -ErrorAction Stop
        
        if (-not $cas) {
            Write-Console -Message "No Certificate Authorities found, skipping" -Type info
            
            @{
                'CAs_Found' = 0
                'Status' = 'No CAs found in domain'
            } | & $script:Export -Name "CertificateServices" -IsSummary
            
            return
        }

        $caNames = $cas | Where-Object {$_.Name} | Select-Object -ExpandProperty ComputerName
        Write-Log -Message "Found CAs: $($caNames -join ', ')" -Level INFO
        Write-Console -Message "Found $($caNames.Count) Certificate Authorities" -Type info

        # Template enumeration
        Write-Log -Message "Beginning template enumeration using certutil"
        $templates = certutil -Template | Out-String
        
        Write-Log -Message "Processing templates"
        try {
            $templates | Export-Csv -Path $outputPaths.Templates -NoTypeInformation -Force
            Write-Log -Message "Template exported to: $($outputPaths.Templates)"
        } catch {
            Write-Log -Message "Failed exporting templates: $_" -Level ERROR
        }
    
        # Template permissions
        Write-Log -Message "Beginning detailed template permission analysis"
        $filter = @()
        $maxEnrollPermissions = 0

        $templates -split "(?=Template\[\d+\]:)" | ForEach-Object {
            $commonName = ""
            $friendlyName = ""
            $enrollPermissions = @()
            $otherPermissions = @()

            $_ -split "`r?`n" | ForEach-Object {
                if ($_ -match "TemplatePropCommonName") {
                    $commonName = ($_ -replace "TemplatePropCommonName\s+=\s+", "").Trim()
                } elseif ($_ -match "TemplatePropFriendlyName") {
                    $friendlyName = ($_ -replace "TemplatePropFriendlyName\s+=\s+", "").Trim()
                } elseif ($_ -match "Allow Enroll") {
                    $enrollPermissions += ($_ -replace "Allow Enroll\s+", "").Trim()
                } elseif ($_ -match "Allow FullControl|Allow Write") {
                    $otherPermissions += $_
                }
            }

            if ($enrollPermissions.Count -gt 0) {
                $maxEnrollPermissions = [math]::Max($maxEnrollPermissions, $enrollPermissions.Count)
                $row = [PSCustomObject]@{
                    TemplateCommonName = $commonName
                    TemplateFriendlyName = $friendlyName
                    FullControlCount = ($otherPermissions | Where-Object { $_ -match "Allow FullControl" }).Count
                    WriteCount = ($otherPermissions | Where-Object { $_ -match "Allow Write" }).Count
                }
                for ($i = 0; $i -lt $enrollPermissions.Count; $i++) {
                    $row | Add-Member -NotePropertyName ("EnrollPermission" + ($i + 1)) -NotePropertyValue $enrollPermissions[$i]
                }
                $filter += $row
            }
        }

        # Enrollment permissions
        try {
            $filter | Export-Csv -Path $outputPaths.Permissions -NoTypeInformation -Force
            Write-Log -Message "Enrollment permissions exported: $($outputPaths.Permissions)"
        } catch {
            Write-Log -Message "Failed exporting enrollment permissions: $_" -Level ERROR
        }

        # CA Templates
        Write-Log -Message "Processing CA template assignments"
        try {
            $caTemplatesOutput = certutil -CATemplates | Out-String
            $caTemplates = @()
            $caTemplatesOutput -split "`r?`n" | ForEach-Object {
                if ($_ -match ":\s+(.+?)\s+--") {
                    $caTemplates += $matches[1].Trim()
                }
            }
            
            # Export enrollments
            $caTemplates | Export-Csv -Path $outputPaths.Enrollment -NoTypeInformation -Force
            Write-Log -Message "CA template assignments exported to: $($outputPaths.Enrollment)"
        } catch {
            Write-Log -Message "Failed processing CA template assignments: $_" -Level ERROR
        }

        # NtAuth certificates
        Write-Log -Message "Querying NtAuth certificates from AD"
        try {
            $ntAuthPath = "CN=NtAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$($script:ADDomain.DNSRoot -replace '\.',',DC=')"
            $ntAuthCerts = Get-ADObject -Filter * -SearchBase $ntAuthPath -Properties *
            
            $ntAuthCerts | Select-Object CanonicalName, CN, Created, Description, DisplayName, objectClass |
                Export-Csv -Path $outputPaths.NTAuth -NoTypeInformation -Force
            Write-Log -Message "NtAuth certificates exported to: $($outputPaths.NTAuth)"
        } catch {
            Write-Log -Message "Failed processing NtAuth certificates: $_" -Level ERROR
        }

        # Audit logging configuration
        Write-Log -Message "Beginning audit configuration analysis"
        try {
            $auditResults = foreach ($ca in $cas) {
                $sceValue = try {
                    Get-ItemPropertyValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy'
                } catch {
                    "Not Configured"
                }

                $policyValue = try {
                    (auditpol /get /subcategory:"Certification Services" | Out-String) -replace '(?s).*Certification Services\s+(.+)$', '$1'
                } catch {
                    "Error retrieving policy"
                }

                $configValue = try {
                    (certutil -getreg CA\AuditFilter | Out-String) -replace '(?s).*AuditFilter REG_DWORD = ([\da-fA-F]+).*', '$1'
                } catch {
                    "Error retrieving config"
                }

                [PSCustomObject]@{
                    Name = $ca.ComputerName
                    SCE = $sceValue
                    Policy = $policyValue
                    Config = $configValue
                }
            }

            $auditResults | Export-Csv -Path $outputPaths.Logging -NoTypeInformation -Force
            Write-Log -Message "Audit configuration exported to: $($outputPaths.Logging)"

            # Templates security
            $templateAnalysis = $filter | ForEach-Object {
                $vulnerabilities = @()
                
                # Vulnerable enrollment permissions
                if ($_.PSObject.Properties.Name -match "EnrollPermission\d+" | 
                    Where-Object { $_.$_ -in @('Everyone', 'Authenticated Users', 'Domain Users') }) {
                    $vulnerabilities += "Overly permissive enrollment rights"
                }

                # Vulnerable administrative permissions
                if ($_.FullControlCount -gt 0) {
                    $vulnerabilities += "Full Control permissions present"
                }
                
                if ($vulnerabilities) {
                    [PSCustomObject]@{
                        TemplateName = $_.TemplateCommonName
                        Finding = $vulnerabilities -join '; '
                    }
                }
            } | & $script:Export -Name "CertificateServices-Vulnerabilities"

            # Audit logging compliance
            $auditAnalysis = $auditResults | ForEach-Object {
                $findings = @()
                
                if ($_.SCE -eq 'Not Configured') {
                    $findings += "Legacy audit policy not disabled"
                }
                if ($_.Policy -notmatch 'Success and Failure') {
                    $findings += "Insufficient audit policy"
                }
                if ($_.Config -eq '0' -or $_.Config -eq 'Error retrieving config') {
                    $findings += "Audit filtering not properly configured"
                }
                
                if ($findings) {
                    [PSCustomObject]@{
                        CAName = $_.Name
                        Finding = $findings -join '; '
                        RiskLevel = 'Medium'
                        Impact = 'Potential audit gaps'
                        Remediation = 'Configure comprehensive auditing'
                        IsSummary = $true
                    }
                }
            } | & $script:Export -Name "ADCS-AuditFindings"

            # Generate summary
            @{
                'CAs' = $cas.Count
                'Templates' = $filter.Count
                'Templates_With_Weak_Security' = ($templateAnalysis).Count
                'CAs_With_Audit_Issues' = ($auditAnalysis).Count
                'NTAuth_Certificates' = ($ntAuthCerts).Count
                'Status' = 'Assessment completed'
            } | & $script:Export -Name "ADCS" -IsSummary

            Write-Console -Message "DONE" -Type done

        } catch {
            Write-Log -Message "Failed to process audit configuration: $_" -Level ERROR
        }

    } catch {
        Write-Log -Message "Certificate Services failed: $_" -Level ERROR
    }
}

function Initialize-BRAVE {
    [CmdletBinding()]
    param( 
   )

    Write-Info -m "Delcare core"
    
    # 1. Declare core variables
    Get-Variable script:* | Remove-Variable -Force  # Clear previous run
    $script:StartTime = [System.DateTime]::UtcNow   # Get current time
    $script:RequiredModules = $RequiredModules                                              # {
    $script:Version = $Version                                                              #   from global script param
    $script:Directory = $Directory                                                          # }
    try {                                                                                   # Filename suffix
        $script:ADDomain = Get-ADDomain
        $script:filename = $script:ADDomain.DNSRoot                                         # Get-ADDomain succeeded
    } catch {
        $script:filename = $env:COMPUTERNAME                                                # Get-ADDomain failed
    }
    $script:Log = Join-Path $script:Directory "$($script:filename).log"                     # Establish log file
    $script:Archive = Join-Path (Split-Path $script:Directory) "$($script:filename).zip"    # Establish archive file
    
    # 2. Initialize log file
    Write-Info -m "Initalize log"
    try {
        # Create directory if not existing
        if (-not (Test-Path $script:Directory)) {
            New-Item -Path $script:Directory -ItemType Directory -Force | Out-Null
        }
        
        "[$(FormatValue -Format Write)] === BRAVE Assessment Started ===" | # Log header
            Set-Content -Path $script:Log -Force -Encoding UTF8
    } catch {
        Write-Info "Can't create output directory" -lvl Error -ex $_
    }

    # 3. Cleanup previous run
    try {
        if (Test-Path $script:Directory) {
            Get-ChildItem -Path $script:Directory -Exclude "$($script:filename).log" | 
                Remove-Item -Recurse -Force -Confirm:$false
            Write-Info -m "Cleaned up from previous run"
        } 
            New-Item -Path $script:Directory -ItemType Directory -Force | Out-Null
            Write-Info -m "Created $($script:Directory)"
    } catch {
        Write-Info -m "Cleanup of previous run failed" -lvl Error -ex $_
    }

    # 4. Initialize AD
    Write-Info -m "Initializing AD varaibles"
    
        # Age thresholds for account staleness
        $script:LogonAge = 90
        $script:PasswordAge = 90

    try {
        $script:ADForest = Get-ADForest #Forest
        $script:DCs = Get-ADDomainController -Server $script:ADDomain.PDCEmulator -Filter * | 
        Select-Object HostName, Name, Enabled, OperationMasterRoles, 
            OperatingSystem, OperatingSystemVersion, ComputerObjectDN, 
            IsGlobalCatalog, IsReadOnly, IPv4Address, Site

        $script:PrivilegedGroups = @{ # Privileged groups for recursive lookups
            "Enterprise Admins" = "$($script:ADDomain.DomainSID.Value)-519" # Universal scope
            "Domain Admins"     = "$($script:ADDomain.DomainSID.Value)-512" # Domain scope
            "Schema Admins"     = "$($script:ADDomain.DomainSID.Value)-518" # Forest scope
            "*Administrators"    = "S-1-5-32-544"                            # Built-in
            "Protected Users"   = "$($script:ADDomain.DomainSID.Value)-525" # Security group
            "Server Operators"   = "$($script:ADDomain.DomainSID.Value)-554" # Security group
        }

    } catch {
        Write-Log -Message "Failed initializing AD variables: $_" -Level ERROR
        Write-Console -Message "Failed to initialize Active Directory" -Type warn
        return $false
    }

    
    # 5. Standard user properties
    $script:UserProperties = @(
        'SAMAccountname',   'Enabled',        'Name',
        'DisplayName',      'LastLogonDate',  'Created',
        'Modified',         'AccountExpirationDate',
        'PasswordLastSet',  'PasswordNeverExpires',
        'PasswordNotRequired', 'PasswordExpired',
        'CannotChangePassword', 'LastBadPasswordAttempt',
        'badpwdcount',     'logonWorkStations',
        'AdminCount',      'UserAccountControl',
        'DoesNotRequirePreAuth',
        'msDS-SupportedEncryptionTypes',
        'DistinguishedName',
        'CanonicalName',   'ServicePrincipalName'
    )
    
    # 6. Prerequisites check
    Write-Console -Message "CHECKING PREREQUISITES" -Type header
    Write-Log -Message "ModuleList: $($ModuleList -join ', ')"
    function Test-RSATInstallation {
        param (
            [bool]$isServer
        )
        
        $rsatStatus = $false
        try {
            if ($isServer) {
                try {
                    $rsat = Get-WindowsFeature RSAT-AD-PowerShell -ErrorAction Stop
                    $isInstalled = $rsat.InstallState -eq 'Installed'
                    $installCommand = { Install-WindowsFeature -Name RSAT-AD-PowerShell -ErrorAction Stop }
                } catch {
                    Write-Log "Failed to check server RSAT status: $($_.Exception.Message)"
                    $isInstalled = $false
                    $installCommand = { Install-WindowsFeature -Name RSAT-AD-PowerShell -ErrorAction Stop }
                }
            } else {
                try {
                    $rsat = Get-WindowsCapability -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -Online -ErrorAction Stop
                    $isInstalled = $rsat.State -eq 'Installed'
                    $installCommand = { Add-WindowsCapability -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -Online -ErrorAction Stop }
                } catch {
                    Write-Log -Message "Failed to check client RSAT status: $_. Attempting to install" -Level ERROR
                    $isInstalled = $false
                    $installCommand = { Add-WindowsCapability -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0" -Online -ErrorAction Stop }
                }
            }
    
            if (-not $isInstalled) {
                Write-Console -Message "RSAT not installed. Installing..." -Type warn
                
                try {
                    & $installCommand
                    Write-Console -Message "RSAT installed successfully"
                    $rsatStatus = $true
                } catch {
                    Write-Log -Message "RSAT failed: $_" -Level ERROR
                    Write-Console -Message "RSAT failed - continuing with limited functionality" -Type warn
                }
            } else {
                Write-Console -Message "RSAT: READY"
                $rsatStatus = $true
            }
        } catch {
            Write-Log -Message "RSAT failed, attempting to continue" -Level ERROR
            Write-Console -Message "RSAT failed, attempting to continue"-Type warn
        }
        return $rsatStatus
    }
    
    function Test-ModuleAvailability {
        param (
            [string]$ModuleName
        )
    
        try {
            # Check if module is already loaded
            if (Get-Module -Name $ModuleName) {
                Write-Log -Message "Module already loaded: $ModuleName"
                return "Ready"
            }
        } catch {
            Write-Log -Message "Error checking loaded modules: $($_.Exception.Message)"
        }
            
        # Check if module is installed
        if (Get-Module -ListAvailable -Name $ModuleName) {
            try {
                Import-Module -Name $ModuleName -Force -Verbose:$false -ErrorAction Stop
                Write-Log -Message "Module imported: $ModuleName"
                return "Ready"
            } catch {
                Write-Log -Message "Import failed: $_. Attempting alternate method" -Level ERROR
                # Alternate import method
                try {
                    Import-Module -Name (Get-Module -ListAvailable -Name $ModuleName |
                        Select-Object -First 1).Path -Force -Verbose:$false
                    return "Ready"
                } catch {
                    Write-Log -Message "Alternate import failed: $_" -Level ERROR
                    return "ImportFailed"
                }
            }
        }

        # Module needs to be installed
        Write-Console -Message "Installing module: $ModuleName" -Type warn
        # Ensure NuGet is available
        try {
            if (-not (Get-PackageProvider -Name NuGet)) {
                Write-Log -Message "Installing NuGet" -Level INFO
                Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null
            }
        } catch {
                Write-Log -Message "NuGet provider installation failed: $_. Attempting to continue" -Level ERROR
        }

        try {
            if (Find-Module -Name $ModuleName -ErrorAction Stop) {
                try {
                    Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                    Import-Module -Name $ModuleName -Force -Verbose:$false -ErrorAction Stop
                    return "Ready"
                } catch {
                    Write-Log -Message "Module installation/import failed: $_" -Level ERROR
                    return "InstallFailed"
                }
            }
            return "NotFound"
        } catch {
            Write-Log -Message "Error finding $($ModuleName) $_" -Level ERROR
            return "NotFound"
        }
    }
        
    # Check OS and RSAT
    $rsatInstalled = $false
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $isServer = @(2,3) -contains $osInfo.ProductType
        Write-Log -Message "$($osInfo.Caption)" -Level DEBUG
        
        $rsatInstalled = Test-RSATInstallation -isServer $isServer
    } catch {
        Write-Log -Message "OS detection failed, assuming workstation" -Level WARN -Exception $_
        $rsatInstalled = Test-RSATInstallation -isServer $false
    }
    
    # Check modules
    $moduleResults = @{}
    foreach ($module in $ModuleList) {
        Write-Log -Message "Processing module: $module" -Level INFO
        try {
            $moduleResults[$module] = Test-ModuleAvailability -ModuleName $module
        } catch {
            Write-Log -Message "Module processing failed: $($_.Exception.Message)"
            $moduleResults[$module] = "Error"
        }
    }
    
    # Log results
    Write-Log -Message "Prerequisites check summary:" -Level INFO
    $moduleResults.GetEnumerator() | ForEach-Object {
        Write-Log -Message "  $($_.Key) : $($_.Value)" -Level INFO
        if ($_.Value -ne "Ready") {
            Write-Log -Message "$($_.Key) : $($_.Value)" -Type warn
        }
    }
    
    $moduleSuccess = ($moduleResults.Values | Where-Object { $_ -ne "Ready" } | Measure-Object).Count -eq 0 # All modules ready

    if (-not ($rsatInstalled -and $moduleSuccess)) { # One or more failed
        $failedComponents = @() # List of failed components
        
        if (-not $rsatInstalled) { # RSAT failed
            $failedComponents += "RSAT" 
        }
        
        if (-not $moduleSuccess) { # One or more modules failed
            $failedModules = $moduleResults.GetEnumerator() | 
                Where-Object { $_.Value -ne "Ready" } | 
                ForEach-Object { $_.Key }
            $failedComponents += "Modules: $($failedModules -join ', ')"
        }
        
        $errorMessage = "Prerequisite Checks Failed: $($failedComponents -join '; ')" # Error message
        
        Write-Console -Message $errorMessage -Type warn
        
        throw $errorMessage # Throw error to stop script
    }
    Write-Console -Message "POWERSHELL: READY"
    Write-Console -Message "DONE" -Type done
    return $true # All prerequisites met
}

function Start-BRAVE {
    [CmdletBinding()]
    param (
        [string[]]$Functions
    )

    Write-Info -m "Start-BRAVE running"

    try {
    # 1. Display status
    $summary = @("
        SCRIPT: v$script:Version"
        "START:  $(FormatValue $script:StartTime -Format Write)"
        "FILE:   $($script:Archive)"
    ) -join "`n"

    $details = @("
        HOST:   $env:COMPUTERNAME"
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

    Write-Info -m "$details" -lvl Summary -show "$summary"

    # 2. Discover functions to turn into scriptblocks
    Write-Log -Message 'Discovering Get-* functions' -Level INFO
    
    $getFunctions = Get-Command -CommandType Function | 
        Where-Object {
            $_.ScriptBlock.File -eq $PSCommandPath -and 
            $_.Name -like 'Get-*'
        }
            
        $scriptblocks = @($getFunctions | ForEach-Object { [scriptblock]::Create($_.Name) })
        $functionNames = $scriptblocks | ForEach-Object { $_.ToString() }
        Write-Log -Message "Executing script functions: $($functionNames -join ', ')" -Level INFO

        # 3. Progress bar
        $total = $scriptblocks.Count
        $current = 0
        Write-Progress -Activity "Executing BRAVE Script" -Completed
        
        # 4. Execute scriptblocks
        foreach ($command in $scriptblocks) {
            $current++
            $percentComplete = ($current / $total) * 100
            Write-Log "Running $($command.ToString())"
            Write-Progress -Activity "Executing BRAVE" -Status "Running $($command.ToString())" -PercentComplete $percentComplete

            try {
                & $command
            }
            catch {
                Write-Log -Message "Command failed: $($command.ToString()): $_" -Level ERROR
            }
        } 

        Write-Console -Message "CREATING ARCHIVE FILE" -Type header

       # 5. Create archive file
        $itemsToArchive = Get-ChildItem -Path $script:Directory -File # Get items to archive
        $itemsToArchive += Get-ChildItem -Path $script:Directory -Directory | # Get items to archive
            Where-Object { $_.FullName -ne $script:GPODirectory }

        Write-Log -Message "File Count: $($itemsToArchive.Count)" -Level INFO
        Write-Log -Message "Archiving: $($itemsToArchive.Name -join ', ')" -Level INFO

        try {
            if ($itemsToArchive) { # Create .zip
                try {
                    $nonLogFiles = $itemsToArchive | Where-Object { $_.FullName -ne $script:Log }
                    Compress-Archive -Path $nonLogFiles.FullName -DestinationPath $script:Archive -Force
                    Write-Log -Message "Added files to archive" -Level INFO
                    Start-Sleep -Seconds 1
                } catch {
                    Write-Log -Message "Failed addding files to archive: $_" -Level ERROR
                }
            }

            if (Test-Path $script:GPODirectory) { # Add GPO folder
                try {
                    Compress-Archive -Path $script:GPODirectory -DestinationPath $script:Archive -Update
                    Write-Log -Message "Added $($script:GPODirectory) to  $($script:Archive)" -Level INFO
                    Start-Sleep -Seconds 1
                } catch {
                    Write-Log -Message "Failed adding $($script:GPODirectory) to  $($script:Archive): $_" -Level ERROR
                }
            }

            # Add invoked script
            try {
                Compress-Archive -Path $PSCommandPath -DestinationPath $script:Archive -Update
                Write-Log -Message "Added $($PSCommandPath) to $($script:Archive): " -Level INFO
                Start-Sleep -Seconds 1
            } catch {
                Write-Log -Message "Failed adding $($PSCommandPath) to $($script:Archive): $_" -Level ERROR
            }

            Write-Console -Message 'DONE' -Type done

            # Write summary
            $duration = [datetime]::UtcNow - $script:StartTime
            $durationFormatted = if ($duration.TotalHours -ge 1) {
                $duration.ToString('hh\:mm\:ss')
            } else {
                $duration.ToString('mm\:ss')
            }

            $summary = @(
                "STARTED:  $(FormatValue $script:StartTime -Format Write)"
                "FINISHED: $(FormatValue ([datetime]::UtcNow) -Format Write)"
                "DURATION: $durationFormatted"
                "CREATED:  $script:Archive"
            ) -join "`n"

            Write-Info  "$summary"
            Write-Info -m "=== BRAVE Assessment Complete ==="
            Start-Sleep -Milliseconds 500

            # Add log file
            Compress-Archive -Path $script:Log -DestinationPath $script:Archive -Update
            Write-Log -Message "Added $($script:Log) to $($script:Archive)" -Level INFO
            Start-Sleep -Milliseconds 500

            # Verify archive and cleanup
            if (Test-Path $script:Archive) {
                if (& $script:Validate -Path $script:Archive) {
                    try { # Cleanup
                        Get-ChildItem -Path $script:Directory -Exclude (Split-Path $script:Log -Leaf) |
                            Remove-Item -Recurse -Force -Confirm:$false
                        Remove-Item -Path $script:Log -Force
                        Remove-Item -Path $script:Directory -Force
                    }
                    catch {
                        Write-Log -Message "Failed post clean up: $_" -Level ERROR
                    }
                }
                else {
                    Write-Log -Message "Archive validation failed - skipping cleanup" -Level WARN
                    Write-Console -Message "Archive failed" -Type warn
                }
            }
            else {
                Write-Log -Message "Archive not found - skipping cleanup" -Level WARN
                Write-Console -Message "Archive not found" -Type warn
            }
        } catch {
            Write-Warning "Error creating archive: $_"
            throw
        }
    }
    catch {
        throw
    }
    finally {
        Write-Progress -Activity "Executing BRAVE Script" -Completed
    }
}

# Main script execution block
Write-Info -m "Main script block"
try {
    Write-Info -m "Initalize-Brave "
    $initResult = Initialize-BRAVE # Run Initialize
    
    if ($null -eq $initResult -or $initResult -eq $false) { # Check return from Initialize
        Write-Log -Nessage "Initalize failed $_" -Level ERROR
        Write-Console -Message "Error initalizing BRAVE script" -Type err
        Write-Log -m "Initalize-BRAVE failed" -lvl Error -ex $_ -show "BRAVE failed initalizing"
        exit 1 # Exit script
    } else {
        Write-Log -Message "Initalize succcess, continuing with execution" -Level INFO
        Start-BRAVE # Continue on
    }
    Write-Log -Message "Script Execution complete" -Level INFO
} 
catch {
    Write-Log -Message "Script Execution failed: $_" -Level ERROR
    Write-Console -Message "$_" -Type err
    Write-Info -m "Main script block failed" -lvl Error -ex $_ -show "BRAVE script failed"
    exit 1
}