<#
.SYNOPSIS
    BRAVE Assessment Script
.DESCRIPTION
    Active Directory queries for the purpose of a BRAVE assessments.
    Includes automated evidence collection for Veeam Backup & Replication, as an alternative to screenshots.
.NOTES
    Version:        2.0.0
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
    [string]$OutputDirectory = "c:\temp\BRAVE\",
    [string[]]$ModuleList = @('GroupPolicy'),
    [string[]]$CertModule = @('PSPKI')
)
$ErrorActionPreference    = "SilentlyContinue"

function Format-DateTime {
    param(
        [Parameter(ValueFromPipeline)]
        [nullable[DateTime]]$DateTime = [DateTime]::UtcNow,
        [ValidateSet('Write', 'File', 'ISO')]
        [string]$Format = 'Write'
    )

    if ($null -eq $DateTime) { return "Never" }
    
    $utcTime = $DateTime.ToUniversalTime()
    
    switch($Format) {
        'Write'   { $utcTime.ToString('MMM dd, yyyy HH:mm (UTC)') }
        'File'    { $utcTime.ToString('MMM-dd-yyyy_HHmmss') }
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
    $logMessage = "[$(Format-DateTime -Format Write)] [$Level] $Message"
    
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
        if ([string]::IsNullOrEmpty($script:LogFile)) {
            throw "LogFile null or empty $($script:LogFile)"
        }
        
        # Write to log file
        $logMessage | Out-File -FilePath $script:LogFile -Append -Force -Encoding UTF8

    }
    catch {
        Write-Warning "Write-Log failed: $_"
        Write-Warning "Message: $logMessage"
        Write-Warning "LogFile: $script:LogFile"
    }
}

function Write-Console {
   [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet("header", "info", "done", "warn", "err")]
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

# Check PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Warning "PowerShell 5 or higher required. Current version: $($PSVersionTable.PSVersion)"
    throw
}

# Check Run as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Script requires elevation. Run PowerShell with 'Run As Administrator'."
    throw
}

# Helper: Validate archive file
function Test-Archive {
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

function Get-ActiveDirectory {
    [CmdletBinding()]
    param()
    
    Write-Console -Message "GATHERING ACTIVE DIRECTORY INFORMATION" -Type header

    # Format helper
    function Format-Value {
        param(
            [Parameter(ValueFromPipeline)]
            $Value
        )
        
        if ($null -eq $Value) { return '' }
        
        switch ($Value) {
            { $_ -is [DateTime] } { return Format-DateTime -DateTime $_ -Format Write }
            { $_ -is [TimeSpan] } { return $_.TotalDays }
            default { return $_ }
        }
    }

    # Export handler
    $script:ExportData = {
        param (
            [Parameter(Mandatory, ValueFromPipeline)]
            [object[]]$InputObject,
            [Parameter(Mandatory)]
            [string]$Name,
            [string]$Description = $Name,
            [switch]$IsSummary
        )
    
        begin {
            $summaryData = [ordered]@{}  # Change to ordered hashtable
            $detailedData = [System.Collections.ArrayList]@()
        }
    
        process {
            foreach ($item in $InputObject) {
                if ($item -is [hashtable] -or $item -is [System.Collections.Specialized.OrderedDictionary]) {
                    foreach ($key in $item.Keys) {
                        $summaryData[$key] = Format-Value $item[$key]
                    }
                } 
                elseif ($item -is [PSCustomObject] -and $IsSummary) {
                    $item.PSObject.Properties | ForEach-Object {
                        $summaryData[$_.Name] = Format-Value $_.Value
                    }
                }
                else {
                    if ($item -is [PSObject]) {
                        $clonedItem = $item.PSObject.Copy()
                        foreach ($prop in $clonedItem.PSObject.Properties) {
                            $prop.Value = Format-Value $prop.Value
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
                $summaryPath = Join-Path $script:OutputDirectory "$($script:filename)-Summary.csv"
                foreach ($key in $summaryData.Keys) {
                    "$Name,$key,$($summaryData[$key])" | Add-Content -Path $summaryPath
                }
            }
    
            if ($detailedData.Count -gt 0 -and -not $IsSummary) {
                $detailedPath = Join-Path $script:OutputDirectory "$($script:filename)-$Name.csv"
                $detailedData | Export-Csv -Path $detailedPath -NoTypeInformation
            }
        }
    }

    # Error handler
    $script:HandleError = {
        param($Section, $Msg)
        Write-Log -Message "$Section failed: $Msg" -Level ERROR
        @{ "$Section" = "Failed: $Msg" } | & $script:ExportData -Name $Section -IsSummary
    }

    try {
        $controls = [Ordered]@{
            
            'RUNTIME' = { # Runtime environment
                try {
                    @{
                        'Time ' = Format-DateTime $script:StartTime -Format Write
                        'Computer' = $env:COMPUTERNAME
                        'User' = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                    } | & $script:ExportData -Name $section -IsSummary
                } catch {
                    & $script:HandleError $section "Failed gathering $section"
                }
            }
    
            'FOREST' = { # Forest topology
                Write-Console -Message "$section" -Type info
                try {
                    @{
                        'Name' = $script:ADForest.Name
                        'Mode' = $script:ADForest.ForestMode
                        'RootDomain' = $script:ADForest.RootDomain
                        'Domains' = $script:ADForest.Domains.Count
                        'Sites' = $script:ADForest.Sites.Count
                        'GCs' = $script:ADForest.GlobalCatalogs.Count
                    } | & $script:ExportData -Name $section -IsSummary
                } catch {
                    & $script:HandleError $section "Failed gathering $section"
                }
            }
    
            'DOMAIN' = { # Domain topology
                Write-Console -Message "$section" -Type info        
                try {
                     @{ 
                        'DNSRoot' = $script:ADDomain.DNSRoot
                        'NetBIOS' = $script:ADDomain.NetBIOSName
                        'Mode' = $script:ADDomain.DomainMode
                        'SID' = $script:ADDomain.DomainSID.Value
                        'DCs' = $script:ADDomain.ReplicaDirectoryServers.Count
                        'RODCs' = $script:ADDomain.ReadOnlyReplicaDirectoryServers.Count
                    } | & $script:ExportData -Name $section -IsSummary
                } catch {
                    & $script:HandleError $section "Failed gathering $section"
                }
            }

            'DOMAIN CONTROLLERS' = { # Domain topology
                Write-Console -Message "$section" -Type info        
                try {
                    $DCs = Get-ADDomainController -Filter * | 
                        Select-Object HostName, Name, OperatingSystem, OperatingSystemVersion, 
                                    ComputerObjectDN, IsGlobalCatalog, IPv4Address |
                        & $script:ExportData -Name "$section"

                    $DCs | ForEach-Object {
                        [ordered]@{
                            'DC' = $_.HostName
                            'Operating System' = $_.OperatingSystemVersion
                        } | & $script:ExportData -Name $section -IsSummary
                    }

                } catch {
                    & $script:HandleError $section "Failed gathering $section"
                }
            }
    
            'FSMO ROLES' = {  # FSMO role holders
                Write-Console -Message "FSMO" -Type info
                try {
                    @{
                        'Schema' = $script:ADForest.SchemaMaster
                        'Naming' = $script:ADForest.DomainNamingMaster
                        'PDC' = $script:ADDomain.PDCEmulator
                        'RID' = $script:ADDomain.RIDMaster
                        'Infra' = $script:ADDomain.InfrastructureMaster
                    } | & $script:ExportData -Name $section -IsSummary
                } catch {
                    & $script:HandleError $section "Failed gathering $section"
                }
            }
            
            'TRUSTS' = { # Domain trusts
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
                        } | & $script:ExportData -Name $section -IsSummary # Pipe to supress console output

                        $trusts | & $script:ExportData -Name $section
                    } else {
                        [PSCustomObject]@{
                            Status = "No trusts found"
                        } | & $script:ExportData -Name "$section-NONE-FOUND" # Pipe to supress console output
                    }
                } catch {
                    & $script:HandleError $section "Failed gathering $section"
                }
            }
   
            'PASSPWORD POLICY' = { # Domain password policy
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
                    } | & $script:ExportData -Name $section -IsSummary
                } catch {
                    & $script:HandleError $section "Failed gathering $section"
                }
            }
    
            'TOMBSTONE' = { # Directory service tombstone
                Write-Console -Message "$section" -Type info
                
                try {
                    $tombstone = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" `
                        -Properties tombstoneLifetime -Server $script:ADDomain.PDCEmulator
                    
                    @{
                        'TombstoneLifetime (day)' = [int]$tombstone.tombstoneLifetime
                    } | & $script:ExportData -Name $section -IsSummary
                } catch {
                    & $script:HandleError $section "Failed gathering $section"
                }
            }
    
            'DSHEURISTICS' = { # Directory Service behavior
                Write-Console -Message "$section" -Type info
                
                try {
                    $configNC = (Get-ADRootDSE).configurationNamingContext
                    $dsService = Get-ADObject -Filter 'objectClass -eq "nTDSService"' `
                        -SearchBase $configNC -Properties dSHeuristics -Server $script:ADDomain.PDCEmulator
                    
                    @{
                        'Value' = if ($dsService.dSHeuristics) { $dsService.dSHeuristics } else { "Not Set" }
                    } | & $script:ExportData -Name $section -IsSummary
                } catch {
                    & $script:HandleError $section "Failed gathering $section"
                }
            }
    
            'PARTITION BACKUPS' = { 
                Write-Console -Message "$section" -Type info
                
                try {
                    $contexts = (Get-ADRootDSE -Server $script:ADDomain.PDCEmulator).namingContexts
                    
                    $contexts | ForEach-Object {
                            $partitionType = switch -Regex ($_) {
                                "CN=Schema," { "Schema" }
                                "CN=Configuration," { "Config" }
                                "DC=.*" { "Domain" }
                                default { "Unknown" }
                            }
        
                            $lastBackup = Get-ADReplicationAttributeMetadata -Object $_ `
                                -Properties dSASignature -Server $script:ADDomain.PDCEmulator |
                                Select-Object -ExpandProperty LastOriginatingChangeTime
                            
                                [PSCustomObject]@{
                                    Type = $partitionType
                                    DN = $_
                                    'LastBackup ' = Format-DateTime $lastBackup -Format Write
                                    BackupsDays = if ($lastBackup) {
                                        [math]::Round((New-TimeSpan -Start $lastBackup).TotalDays, 1)
                                    } else { "Never" }
                                    IsSummary = $true
                                }
                    } | & $script:ExportData -Name $section -IsSummary  
                } catch {
                    & $script:HandleError $section "Failed gathering $section"
                }
            }

            'DEFAULT_ADMINISTRATOR' = {
                Write-Console -Message "$section" -Type info
                
                try {
                    $administrator = Get-ADUser -Identity "$($script:ADDomain.DomainSID.Value)-500" -Properties $script:UserProperties -Server $script:ADDomain.PDCEmulator                
                    [ordered]@{
                        'SamAccountName' = $administrator.SamAccountName
                        'Name' = $administrator.Name
                        'DistinguishedName' = $administrator.DistinguishedName
                        'Enabled' = $administrator.Enabled
                        'LastLogonDate ' = Format-Value $administrator.LastLogonDate 
                        'LogonAge (days)' = [math]::Round((New-TimeSpan -Start $administrator.LastLogonDate -End (Get-Date)).TotalDays)
                        'PasswordLastSet ' = Format-Value $administrator.PasswordLastSet
                        'PasswordAge (days)' = [math]::Round((New-TimeSpan -Start $administrator.PasswordLastSet -End (Get-Date)).TotalDays)
                    } | & $script:ExportData -Name $section -IsSummary
                } catch {
                    & $script:HandleError $section "Failed gathering $section"
                }
            }

            'PRIVILEGED' = {
                Write-Console -Message "$section" -Type info
                
                function Get-RecursiveGroupMember {
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
                                $nestedMembers = Get-RecursiveGroupMember -GroupSID $nestedGroup.SID `
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
                                    LastLogonDate = Format-Value $user.LastLogonDate
                                    PasswordLastSet = Format-Value $user.PasswordLastSet
                                    SPNs = $user.ServicePrincipalName -join ';'
                                    ObjectType = "User"
                                    NestedPath = $currentPath
                                    DistinguishedName = $user.DistinguishedName
                                }
                                
                                # Track access path for user
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
                        Write-Log -Message "Error processing group $GroupName" -Level WARN -Exception $_
                        
                    }
                }

                try {
                    # Initialize tracking
                    $groups = @()
                    $accessPaths = @{}
            
                    foreach ($group in $script:PrivilegedGroups.GetEnumerator()) {
                        Write-Log -Message "Processing: $($group.Key), SID: $($group.Value)" -Level DEBUG
                        
                        $members = Get-RecursiveGroupMember -GroupSID $group.Value `
                                                          -GroupName $group.Key `
                                                          -SecurityGroup $group.Key `
                                                          -AccessPaths $accessPaths
                        Write-Log -Message "Got members for group $($group.Key): $($members.Count) members" -Level DEBUG

                        if ($members) {
                            $groups += $members
                            
                            # Store statistics in a format usable for $script:ExportData 
                            @{
                                "$($group.Key) Total" = ($members | Where-Object ObjectType -eq 'User' | Sort-Object -Unique SamAccountName).Count
                               } | & $script:ExportData -Name $section -IsSummary
            
                            @{
                                "$($group.Key) Disabled" = ($members | Where-Object { $_.ObjectType -eq 'User' -and -not $_.Enabled } | Sort-Object -Unique SamAccountName).Count
                            } | & $script:ExportData -Name $section -IsSummary
                        }
                    }
                    Write-Log -Message "Starting matrix with $($accessPaths.Count) accounts" -Level DEBUG
                    
                    # Privileged groups user matrix
                    $privilegedUsers = @()
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
                                LastLogonDate = Format-Value $member.LastLogonDate
                                PasswordLastSet = Format-Value $member.PasswordLastSet
                            }
                            
                            foreach ($group in $script:PrivilegedGroups.Keys) {
                                $value = if ($accessPaths[$account].ContainsKey($group)) { 
                                    $accessPaths[$account][$group] 
                                } else { 
                                    "" 
                                }
                                $obj | Add-Member -NotePropertyName $group -NotePropertyValue $value
                            }
                            
                            $privilegedUsers += $obj
                        }
                    }
            
                    # Export summary data through ExportData
                    foreach ($key in $summary.Keys) {
                        [PSCustomObject]@{
                            'Category' = $section
                            'Setting' = $key
                            'Value' = $summary[$key]
                        } | & $script:ExportData -Name $section -IsSummary
                    }

                    # Export hierarchical data directly manually (ExportData cannot handle nested objects)
                    try {
                        $groupPath = Join-Path $script:OutputDirectory "$($script:filename)-$section-GROUPS.csv"
                        $groups | Export-Csv -Path $groupPath -NoTypeInformation

                    } catch {
                        Write-Log -Message "Failed exporting: $groupPath : $_" -Level ERROR
                        throw  # Throw to outer catch
                    }

                    try {
                        $userPath = Join-Path $script:OutputDirectory "$($script:filename)-$section-USER_MATRIX.csv"
                        $privilegedUsers | Export-Csv -Path $userPath -NoTypeInformation

                    } catch {
                        Write-Log -Message "Failed exporting: $path : $_" -Level ERROR
                        throw  # Throw to outer catch
                    }
                    
                } catch {
                    Write-Log -Message "Error in '$section': $_" -Level ERROR -Exception $_
                    & $script:HandleError $section "Failed to gather $section"
                }
            }
       
            'USERS' = {
                Write-Console -Message "USERS" -Type info
                
                try {
                    $users = Get-ADUser -Filter * -Properties $script:UserProperties -Server $script:ADDomain.PDCEmulator

                    if ($users) {
                        # Export detailed user information
                        $users | & $script:ExportData -Name $section

                        # Calculate and export summary counts
                        [ordered]@{
                            'Total' = ($users | Measure-Object).Count
                            'Enabled' = ($users | Where-Object {$_.Enabled}).Count
                            'Disabled' = ($users | Where-Object {-not $_.Enabled}).Count
                            'Stale' = ($users | Where-Object {
                                $_.LastLogonDate -and $_.PasswordLastSet -and 
                                ((New-TimeSpan -Start $_.LastLogonDate -End (Get-Date)).TotalDays -ge $script:LogonAge) -and
                                ((New-TimeSpan -Start $_.PasswordLastSet -End (Get-Date)).TotalDays -ge $script:PasswordAge)
                            } ).Count
                            'PASSWD_NOTREQD' = ($users | Where-Object {$_.UserAccountControl -band 0x0020}).Count
                            'ENCRYPTED_TEXT_PWD_ALLOWED' = ($users | Where-Object {$_.UserAccountControl -band 0x0080}).Count
                            'PASSWD_CANT_CHANGE' = ($users | Where-Object {$_.UserAccountControl -band 0x0040}).Count
                            'DONT_REQUIRE_PREAUTH' = ($users | Where-Object {$_.UserAccountControl -band 0x400000}).Count
                            'USE_DES_KEY_ONLY' = ($users | Where-Object {$_.UserAccountControl -band 0x200000}).Count
                        } | & $script:ExportData -Name $section -IsSummary
                    } else {
                        @{
                            'Total' = 'No user objects found'
                        } | & $script:ExportData -Name $section -IsSummary
                    }
                } catch {
                    & $script:HandleError $section "Failed gathering $section"
                }
            }

            'KRBTGT_ACCOUNT' = { # Kerberos ticket-granting ticket account
                Write-Console -Message "$section" -Type info

                try {
                    $krbtgt = Get-ADUser 'krbtgt' -Properties PasswordLastSet -Server $script:ADDomain.PDCEmulator
                    @{
                        'PasswordLastSet' = Format-DateTime $krbtgt.PasswordLastSet -Format Write
                        'Age (day)' = [math]::Round(((Get-Date) - (Get-ADUser 'krbtgt' -Properties PasswordLastSet -Server $script:ADDomain.PDCEmulator).PasswordLastSet).TotalDays)
                    } | & $script:ExportData -Name $section -IsSummary
                } catch {
                    & $script:HandleError $section "Failed to check KRBTGT account"
                }
            }
    
            'KERBEROS_DELAGATION' = { # Kerberos delegation
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
                        "Name", "ObjectClass", "PrimaryGroupID", 
                        "UserAccountControl", "ServicePrincipalName", 
                        "msDS-AllowedToDelegateTo", 
                        "msDS-AllowedToActOnBehalfOfOtherIdentity"
                    ) -Server $script:ADDomain.PDCEmulator

                    if ($delegatedAccounts) {
                        $delegatedAccounts | ForEach-Object {
                            [PSCustomObject]@{
                                Name = $_.Name
                                Type = $(switch ($true) {
                                    { $_.UserAccountControl -BAND 0x0080000 } { 'Unconstrained' }
                                    { $_.UserAccountControl -BAND 0x1000000 } { 'Constrained with Protocol Transition' }
                                    { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' } { 'Resource-Based Constrained' }
                                    { $_.'msDS-AllowedToDelegateTo' } { 'Constrained' }
                                    default { 'Unknown' }
                                })
                                Scope = if ($_.UserAccountControl -BAND 0x0080000) { 
                                    'All Services' 
                                } else { 
                                    'Specific Services' 
                                }
                                IsSummary = $true
                            } | & $script:ExportData -Name $section
                        }
                    } else {
                        [PSCustomObject]@{
                            Name = "No Kerberos Delegation Found"
                            DelegationType = "N/A"
                            Scope = "N/A"
                            IsSummary = $true
                        } | & $script:ExportData -Name $section
                    }
                } catch {
                    & $script:HandleError $section "Failed gathering $section"
                }
            }

            'PASSWORDS' = { # Group Policy stored credential
                Write-Log -Message "Group Policy plain text passwords" -Level INFO
                
                try {
                    $gpoStoragePath = "\\$($script:Domain.DNSRoot)\SYSVOL\$($script:Domain.DNSRoot)\Policies"
                    $credentialFindings = findstr /S /I cpassword "$gpoStoragePath\*.xml"
                    
                    if ($credentialFindings) {
                        Write-Log -Message "Found GPP passwords" -Level WARN
                        
                        $credentialFindings | ForEach-Object {
                            [PSCustomObject]@{
                                PolicyFile = $_
                                Issue = "Contains encrypted password"
                                IsSummary = $true
                            } | & $script:ExportData -Name $section
                        }
                    } else {
                        @{
                            'Results' = "No plain text passwords found"
                        } | & $script:ExportData -Name $section -IsSummary
                    }
                } catch {
                    & $script:HandleError $section "Failed gathering $section"
                }
            }
    
            'SPOOLER' = { # Print spooler service status across domain controllers
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
                            Write-Log -Message "Failed to check spooler on $($_.Name)" -Level WARN -Exception $_
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
                    } | & $script:ExportData -Name $section -Description "Print Spooler"
                } catch {
                    & $script:HandleError $section "Failed gathering $section"
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
                                'Created ' = Format-DateTime $_.Created -Format Write
                                'Modified ' = Format-DateTime $_.Modified -Format Write
                                HostName = $_.DNSHostName
                                Enabled = $_.Enabled
                                Computers = $hostComputers -join '; '
                                Members = ($_.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }) -join '; '
                            } | & $script:ExportData -Name $section
                        }

                        $gMSA | ForEach-Object {
                            $principals = $_.'msDS-GroupMSAMembership' | ForEach-Object {
                                (Get-ADObject $_).Name
                            }

                            [PSCustomObject]@{
                                Name = $_.Name
                                Type = "gMSA"
                                Created = Format-DateTime $_.Created -Format Write
                                Modified = Format-DateTime $_.Modified -Format Write
                                HostName = $_.DNSHostName
                                Enabled = $_.Enabled
                                Principals = $principals -join '; '
                                Members = ($_.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }) -join '; '
                            } | & $script:ExportData -Name $section
                        }
                    } else { # No MSAs found
                        [PSCustomObject]@{
                            Name = "No Managed Service Accounts Found"

                        } | & $script:ExportData -Name "$section-None-Found"
                    }

                    # Generate summary statistics
                    @{
                        'SMA' = ($sMSA | Measure-Object).Count
                        'gMSA' = ($gMSA | Measure-Object).Count
                        'Total' = ($sMSA | Measure-Object).Count + ($gMSA | Measure-Object).Count
                    } | & $script:ExportData -Name $section -IsSummary

                } catch {
                    & $script:HandleError $section "Failed gathering $section"
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
                        # Check for duplicate SPNs
                        $duplicateSPNs = SetSPN -X -F | Where-Object { $_ -notlike "Processing entry*" }

                        # Cross-reference with privileged users
                        $privilegedSPNs = $spnObjects | Where-Object {
                            $_.ObjectClass -eq 'user' -and
                            $_.SamAccountName -in $script:PrivilegedUsers.Name
                        }

                        # Export privileged accounts with SPNs
                        if ($privilegedSPNs) {
                            $privilegedSPNs | ForEach-Object {
                                [PSCustomObject]@{
                                    Name = $_.Name
                                    SamAccountName = $_.SamAccountName
                                    SPNs = $_.ServicePrincipalName -join ';'
                                    IsSummary = $true
                                }
                            } | & $script:ExportData -Name "$section-PrivilegedSPNs"
                        }
                        else {
                            [PSCustomObject]@{
                            } | & $script:ExportData -Name "$section-None-Found"
                        }

                        # Export duplicate findings if any exist
                        if ($duplicateSPNs) {
                            $duplicateSPNs | ForEach-Object {
                                [PSCustomObject]@{
                                    DuplicateSPN = $_
                                    IsSummary = $true
                                }
                            } | & $script:ExportData -Name "$section-Duplicates"
                        }
                    }
                    else {
                        [PSCustomObject]@{
                            Name = "No Service Principal Names"
                            SamAccountName = "N/A"
                            SPNs = "N/A"
                            IsSummary = $true
                        } | & $script:ExportData -Name "$section-PrivilegedSPNs"
                    }

                    # Generate summary
                    @{
                        'Total' = ($spnObjects | ForEach-Object { $_.ServicePrincipalName.Count } | Measure-Object -Sum).Sum
                        'Objects' = ($spnObjects | Measure-Object).Count
                        'Privileged' = ($privilegedSPNs | Measure-Object).Count
                        'Duplicate' = ($duplicateSPNs | Measure-Object).Count
                    } | & $script:ExportData -Name $section -IsSummary

                } catch {
                    & $script:HandleError $section "Failed gathering $section"
                }
            }

            'FGPP' = {
                Write-Log -Message "Fine-grained password policies" -Level INFO
                
                try {
                    # Query all fine-grained policies 
                    $fineGrainedPwdPolicy = Get-ADFineGrainedPasswordPolicy -Filter * -Server $script:ADDomain.PDCEmulator
                    
                    if ($fineGrainedPwdPolicy) {
                        $fineGrainedPwdPolicy | ForEach-Object {
                            $policy = $_
                            
                            # Get groups this policy applies to
                            $appliesTo = Get-ADFineGrainedPasswordPolicySubject -Identity $policy
                            
                            # Get members of each group
                            $groupMembers = $appliesTo | ForEach-Object {
                                Get-ADGroupMember -Identity $_ -Recursive | Select-Object Name, SamAccountName, objectClass
                            }

                            [PSCustomObject]@{
                                Name = $policy.Name
                                ComplexityEnabled = $policy.ComplexityEnabled
                                LockoutDuration = $policy.LockoutDuration
                                LockoutObservationWindow = $policy.LockoutObservationWindow
                                LockoutThreshold = $policy.LockoutThreshold
                                MaxPasswordAge = $policy.MaxPasswordAge
                                MinPasswordAge = $policy.MinPasswordAge
                                MinPasswordLength = $policy.MinPasswordLength
                                PasswordHistoryCount = $policy.PasswordHistoryCount
                                ReversibleEncryptionEnabled = $policy.ReversibleEncryptionEnabled
                                AppliesTo = ($appliesTo | Select-Object -ExpandProperty Name) -join '; '
                                AffectedUsers = ($groupMembers | Where-Object objectClass -eq 'user' | Select-Object -ExpandProperty Name) -join '; '
                                AffectedGroups = ($groupMembers | Where-Object objectClass -eq 'group' | Select-Object -ExpandProperty Name) -join '; '
                                TotalAffectedUsers = ($groupMembers | Where-Object objectClass -eq 'user' | Measure-Object).Count
                                TotalAffectedGroups = ($groupMembers | Where-Object objectClass -eq 'group' | Measure-Object).Count
                            } | & $script:ExportData -Name $section
                        }
                        
                        @{
                            'Policies' = ($fineGrainedPwdPolicy | Measure-Object).Count
                        } | & $script:ExportData -Name $section -IsSummary
                        
                    } else {
                        @{
                            'PolicyCount' = 0
                        } | & $script:ExportData -Name $section -IsSummary
                    }
                } catch {
                    & $script:HandleError $section "Failed gathering $section"
                }
            }

            'SYSVOL' = { # SYSVOL share permissions
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
                            Write-Log -Message "Failed to process DC: $($dc.Name)" -Level WARN -Exception $_
                            continue
                        }
                    }
                    
                    if ($results) {
                        # Detailed export
                        $results | & $script:ExportData -Name $section
                        
                        # Summary export
                        @{
                            'DCsProcessed' = ($script:DCs | Measure-Object).Count
                            'CustomPermissions' = ($results | Measure-Object).Count
                            'Status' = 'Custom permissions found'
                        } | & $script:ExportData -Name $section -IsSummary
                    } else { # Mo custom permissions found
                        @{
                            'DCsProcessed' = ($script:DCs | Measure-Object).Count
                            'CustomPermissions' = 0
                            'Status' = 'No custom permissions found'
                        } | & $script:ExportData -Name $section -IsSummary
                    }
                } catch {
                    & $script:HandleError $section "Failed gathering $section"
                }
            }

            'COMPUTERS' = { # Active Directory computer accounts
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
                            @{ Name = 'LastLogonDate'; Expression = {Format-DateTime $_.LastLogonDate -Format Write} },
                            @{ Name = 'Status'; Expression = {if ($_.Enabled) {'Enabled'} else {'Disabled'}} },
                            TrustedForDelegation,
                            @{ Name = 'Created'; Expression = {Format-DateTime $_.whenCreated -Format Write} }

                        # Export detailed computer information
                        $computerInfo | & $script:ExportData -Name $section

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
                        } | & $script:ExportData -Name $section -IsSummary
                    } else {
                        # Record when no computer objects are found
                        @{
                            'Total' = 'No computer objects found'
                        } | & $script:ExportData -Name $section -IsSummary
                    }
                } catch {
                    & $script:HandleError $section "Failed gathering $section"
                }
            }

            'LOGGING' = { # Security audit policy settings
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
                    $results | & $script:ExportData -Name $section
                    
                    # Summary export
                    @{
                        'Total' = ($results | Measure-Object).Count
                        'Success' = ($results | Where-Object Success | Measure-Object).Count
                        'Failure' = ($results | Where-Object Failure | Measure-Object).Count
                    } | & $script:ExportData -Name $section -IsSummary
                    
                } catch {
                    & $script:HandleError $section "Failed gathering $section"
                }
            }
        }
        
        # Process each section
        $sectionsToProcess = $controls.Keys
        foreach ($section in $sectionsToProcess) {
            Write-Log -Message "Processing section: $section" -Level DEBUG
            
            try {
                if ($controls.Contains($section)) { 
                    $scriptBlock = $controls[$section]
                    if ($scriptBlock -is [ScriptBlock]) {
                        & $scriptBlock
                    }
                }
            } catch {
                Write-Log -Message "Error processing section: $section" -Level ERROR -Exception $_
                @{ 'Status' = "Error: Processing failed" } | 
                    & $script:ExportData -Name $section -IsSummary
            }
        }

        Write-Log -Message "AD General assessment completed" -Level INFO
        Write-Console -Message "FINISHED GATHERING ACTIVE DIRECTORY INFORMATION" -Type done

    } catch {
        Write-Log -Message "Critical error in AD Information gathering" -Level ERROR -Exception $_
        Write-Console -Message "Error gathering AD Information" -Type warn
    }
}

function Get-GroupPolicies {
    Write-Console -Message "GATHERING GROUP POLICIES" -Type header
    
    $results = @()
    $GpoFolder = Join-Path $script:OutputDirectory "$script:Name-GPO"
    
    # Folder management for HTML/XML reports
    try {
        New-Item -Path $GpoFolder -ItemType Directory -Force > $null
    } catch {
        Write-Log -Message "Unable to create GPO Folder" -Level WARN
    }
    
    # Get all GPOs
    Write-Log -Message "Retrieving GPO list" -Level INFO
    $Gpos = Get-GPO -All
    
    if (-not $Gpos) {
        Write-Console -Message "No Group Policies found" -Type warn
        return
    }
    
    # Add CSV headers
    $results += "GROUP POLICIES,"
    
    foreach ($gpo in $Gpos) {
        # Add GPO info to CSV
        $results += "$($gpo.DisplayName),$($gpo.Id)"
        $results += "Created,$(Format-DateTime $gpo.CreationTime -Format Write)"
        $results += "Modified,$(Format-DateTime $gpo.ModificationTime -Format Write)"
        
        # Get security info gracefully
        try {
            $links = ($gpo.GetSecurityInfo()).TrusteePermissions.Count
        } catch {
            $links = "Error getting permissions"
            Write-Log -Message "Error getting permissions for $($gpo.DisplayName)" -Level WARN
        }
        $results += "Links,$links"
        
        # Get WMI filter gracefully
        $wmiFilter = if ($gpo.WmiFilter) { $gpo.WmiFilter.Name } else { "None" }
        $results += "WMI Filter,$wmiFilter"
        $results += "Status,$($gpo.GpoStatus)"
        $results += ","  # Separator between GPOs
        
        # Export HTML/XML reports
        try {
            [xml]$reports = Get-GPOReport -ReportType Xml -Guid $gpo.Id
            if ($null -ne $reports.GPO.Name) {
                $html = Join-Path $GpoFolder "$($reports.GPO.Name).html"
                $xml = Join-Path $GpoFolder "$($reports.GPO.Name).xml"
                
                Get-GPOReport -Name $reports.GPO.Name -ReportType Html -Path $html
                Get-GPOReport -Name $reports.GPO.Name -ReportType Xml -Path $xml
                
                Write-Console -Message "$($reports.GPO.Name)"
            }
        } catch {
            Write-Console -Message "Failed to export: $($gpo.DisplayName)" -Type warn
            continue
        }
    }
    
    # Export CSV results
    $outputPath = Join-Path $script:OutputDirectory "$($script:filename)-GPO.csv"
    $results | Out-File -FilePath $outputPath -Force
	Write-Console -Message "FINISHED GATHERING GROUP POLICIES" -Type done
}

function Get-NetworkSettings {
    
    Write-Console -Message "GATHERING NETWORK SETTINGS" -type header
    
    $results = @()
    
    try {
		Write-Console -Message "REGISTRY"

        $RegistryKeys = @( # Registry keys to check
            @{
                Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
                Name = @("RestrictNullSessAccess", "NullSessionShares")
            },
            @{
                Path = "HKLM:\System\CurrentControlSet\Control\Lsa"
                Name = @("RestrictAnonymousSAM", "RestrictAnonymous", "EveryoneIncludesAnonymous")
            },
            @{
                Path = "HKLM:\System\CurrentControlSet\Control\LSA\MSV1_0"
                Name = @("allownullsessionfallback")
            }
        )
        
        
        # Add header
        $results += "REGISTRY SETTINGS,"
        
    
        # Add header
        $results += "REGISTRY SETTINGS,"
        
        foreach ($RegistryKey in $RegistryKeys) {
			foreach ($name in $RegistryKey.Values) {
				try {
					$value = Get-ItemProperty -Path $RegistryKey.Path -Name $name
					if ($null -eq $value) {
						$results += "$name,null"
					} else {
						$results += "$name,$($value.$name)"
					}
				} catch {
					$results += "$name,null"
					Write-Log -Message "Error checking registry value $name" -Level ERROR -Exception $_
				}
			}
		}
        
        $results += ","  # Section separator
        
        # Add secedit info
        $results += "SECURITY POLICY,"
        $seceditPath = Join-Path $env:TEMP "secexport.cfg"
        $null = secedit /export /cfg $seceditPath
        
        if (Test-Path -Path $seceditPath) {
            try {
                $secContent = Get-Content $seceditPath
                $lsaLookup = $secContent | Select-String "LSAAnonymousNameLookup"
                
                if ($lsaLookup) {
                    $lsaValue = $lsaLookup.ToString().Split('=')[1].Trim()
                    $results += "LSAAnonymousNameLookup,$lsaValue"
                } else {
                    $results += "LSAAnonymousNameLookup,Not Found"
                }
            } finally {
                Remove-Item -Path $seceditPath -Force
            }
        }
        
        # Export results directly
        $outputPath = Join-Path $script:OutputDirectory "$($script:filename)-NetworkSettings.csv"
        $results | Out-File -FilePath $outputPath -Force
        
        Write-Log -Message "Network settings exported to: $outputPath" -Level INFO
        Write-Console -Message "FINISHED GATHERING NETWORK SETTINGS" -Type done
        return # explicite return to stop execution
    } catch {
        Write-Log -Message "Error in network settings audit" -Level ERROR -Exception $_
        Write-Console -Message "Error during network settings audit" -Type warn
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
            Write-Console -Message "No Certificate Services found - skipping" -Type done
            
            @{
                'CAs_Found' = 0
                'Status' = 'No Certificate Services found'
            } | & $script:ExportData -Name "CertificateServices" -IsSummary
            
            return
        }

        # Check PSPKI module
        $pspkiStatus = Test-ModuleAvailability -ModuleName $script:CertModule
        if ($pspkiStatus -ne "Ready") {
            Write-Console -Message "PSPKI module not available - skipping Certificate Services assessment" -Type warn
            
            @{
                'CAs_Found' = 0
                'Status' = 'PSPKI module not available'
            } | & $script:ExportData -Name "CertificateServices" -IsSummary
            
            return
        }
    } catch {
        Write-Log -Message "Error checking Certificate Services: $($_.Exception.Message)" -Level WARN
        Write-Console -Message "Error checking Certificate Services" -Type warn
        
        @{
            'CAs_Found' = 0
            'Status' = 'Error checking Certificate Services'
        } | & $script:ExportData -Name "CertificateServices" -IsSummary
        
        return
    }

    # Define output paths
    $outputPaths = @{
        Templates    = Join-Path $script:OutputDirectory "$($script:filename)-ADCS-Templates.csv"
        Enrollment   = Join-Path $script:OutputDirectory "$($script:filename)-ADCS-Enrollment.csv"
        Permissions  = Join-Path $script:OutputDirectory "$($script:filename)-ADCS-EnrollmentPermissions.csv"
        NTAuth       = Join-Path $script:OutputDirectory "$($script:filename)-ADCS-NTAuth.csv"
        Logging      = Join-Path $script:OutputDirectory "$($script:filename)-ADCS-Logging.csv"
    }

    try { # Main CA assessment block
        Write-Log -Message "Initiating CA discovery"
        $cas = Get-CA -ErrorAction Stop
        
        if (-not $cas) {
            Write-Console -Message "No Certificate Authorities found, skipping" -Type info
            
            @{
                'CAs_Found' = 0
                'Status' = 'No CAs found in domain'
            } | & $script:ExportData -Name "CertificateServices" -IsSummary
            
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
            Write-Log -Message "Template data exported to: $($outputPaths.Templates)"
        } catch {
            Write-Log -Message "Failed to export template data" -Level ERROR -Exception $_
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
            Write-Log -Message "Enrollment permissions exported to: $($outputPaths.Permissions)"
        } catch {
            Write-Log -Message "Failed to export enrollment permissions" -Level ERROR -Exception $_
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
            Write-Log -Message "Failed to process CA template assignments" -Level ERROR -Exception $_
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
            Write-Log -Message "Failed to process NtAuth certificates" -Level ERROR -Exception $_
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
                        RiskLevel = 'High'
                        Impact = 'Potential certificate misuse'
                        Remediation = 'Review and restrict template permissions'
                        IsSummary = $true
                    }
                }
            } | & $script:ExportData -Name "CertificateServices-Vulnerabilities"

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
            } | & $script:ExportData -Name "CertificateServices-AuditFindings"

            # Generate summary
            @{
                'CAs_Found' = $cas.Count
                'Total_Templates' = $filter.Count
                'Templates_With_Weak_Security' = ($templateAnalysis | Measure-Object).Count
                'CAs_With_Audit_Issues' = ($auditAnalysis | Measure-Object).Count
                'NTAuth_Certificates' = ($ntAuthCerts | Measure-Object).Count
                'Status' = 'Assessment completed'
            } | & $script:ExportData -Name "CertificateServices" -IsSummary

            Write-Console -Message "FINISHED GATHERING CERTIFICATE SERVICES" -Type done

        } catch {
            Write-Log -Message "Failed to process audit configuration" -Level ERROR -Exception $_
        }

    } catch {
        Write-Log -Message "Certificate Services assessment failed" -Level ERROR -Exception $_
        & $script:HandleError "CertificateServices" "Assessment failed: $($_.Exception.Message)"
    }
}

function Initialize-BRAVE {
    [CmdletBinding()]
    param( 
   )
    
    # 1. Cleanup from previous run
    try {
        if (Test-Path $script:OutputDirectory) {
            Write-Log -Message "Removing output directory: $script:OutputDirectory"
            Remove-Item -Path $script:OutputDirectory -Recurse -Force -Confirm:$false
        }
        New-Item -Path $script:OutputDirectory -ItemType Directory -Force | Out-Null
    } catch {
        Write-Log -Message "Cleanup failed: $_" -Level ERROR
        throw  # Re-throw to #Script Execution block
    }

    # 2. Clear only script-scoped variables
    Get-Variable script:* | Remove-Variable -Force

    # 3. Declare core
    $script:Version = "2.0.0"
    $script:StartTime = [System.DateTime]::UtcNow
    $script:RequiredModules = $ModuleList
    $script:OutputDirectory = $OutputDirectory  # Set by ValidateScript param

    # 4. Declare domain (required for filenames)
    try {
        $script:ADDomain = Get-ADDomain
        $script:filename = $script:ADDomain.DNSRoot
    } catch {
        $script:filename = $env:COMPUTERNAME
        Write-Log -Message "AD Domain not found, using computer name: $($script:filename)" -Level INFO
    }

    # 5. Declare paths and names (log, archive)
    $script:LogFile = Join-Path $script:OutputDirectory "$($script:filename).log"
    $script:Archive = Join-Path (Split-Path $script:OutputDirectory) "$($script:filename).zip"

    # 6. Create and initialize log file
    try {
        New-Item -Path $script:LogFile -ItemType File -Force | Out-Null
        "[$(Format-DateTime -Format Write)] === BRAVE Assessment Started ===" | 
            Out-File -FilePath $script:LogFile -Encoding UTF8
    } catch {
        Write-Warning "Failed to create log file: $_"
        throw
    }

    # 7. Initialize AD variables
    Write-Log -Message "Initializing AD variables" -Level INFO
    
        # Age thresholds for account staleness
        $script:LogonAge = 90
        $script:PasswordAge = 90

    try {
        $script:ADForest = Get-ADForest #Forest
        $script:DCs = Get-ADDomainController -Filter * | # Domain controllers
            Select-Object Name, HostName, Site

        $script:PrivilegedGroups = @{ # Privileged groups for recursive lookups
            "Enterprise Admins" = "$($script:ADDomain.DomainSID.Value)-519" # Universal scope
            "Domain Admins"     = "$($script:ADDomain.DomainSID.Value)-512" # Domain scope
            "Schema Admins"     = "$($script:ADDomain.DomainSID.Value)-518" # Forest scope
            "Administrators"    = "S-1-5-32-544"                            # Built-in
            "Protected Users"   = "$($script:ADDomain.DomainSID.Value)-525" # Security group
        }

    } catch {
        Write-Log -Message "Failed to initialize AD variables" -Level ERROR -Exception $_
        Write-Console -Message "Failed to initialize Active Directory" -Type warn
        return $false
    }

    
    # 8. Standard user properties to query
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
    
    # 9. Prerequisites check
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
                    Write-Log -Message "Failed to check client RSAT status. Attempting to install" -Level ERROR -Exception $_
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
                    Write-Log -Message "RSAT failed" -Level ERROR -Exception $_
                    Write-Console -Message "RSAT failed - continuing with limited functionality" -Type warn
                }
            } else {
                Write-Console -Message "RSAT: READY"
                $rsatStatus = $true
            }
        } catch {
            Write-Log -Message "RSAT failed, attempting to continue" -Level ERROR -Exception $_
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
                Write-Log -Message "Import failed, attempting alternate method" -Level ERROR -Exception $_
                # Alternate import method
                try {
                    Import-Module -Name (Get-Module -ListAvailable -Name $ModuleName |
                        Select-Object -First 1).Path -Force -Verbose:$false
                    return "Ready"
                } catch {
                    Write-Log -Message "Alternate import failed" -Level ERROR -Exception $_
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
                Write-Log -Message "NuGet provider installation failed, attempting to continue" -Level ERROR -Exception $_
        }

        try {
            if (Find-Module -Name $ModuleName -ErrorAction Stop) {
                try {
                    Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                    Import-Module -Name $ModuleName -Force -Verbose:$false -ErrorAction Stop
                    return "Ready"
                } catch {
                    Write-Log -Message "Module installation/import failed" -Level ERROR -Exception $_
                    return "InstallFailed"
                }
            }
            return "NotFound"
        } catch {
            Write-Log -Message "Error finding module $ModuleName" -Level ERROR -Exception $_
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
    Write-Console -Message "FINISHED CHECKING PREREQUISITES" -Type done
    return $true # All prerequisites met
}

function Start-BRAVE {
    [CmdletBinding()]
    param (
        [string[]]$Functions
    )

    try {
        # 1. Broadcast status
        $summary = @"
SCRIPT:     v$script:Version
STARTED:    $(Format-DateTime $script:StartTime -Format Write)
DIRECTORY:  $script:OutputDirectory
OS:         $((Get-CimInstance -ClassName Win32_OperatingSystem).Caption)
"@

        $details = @"
PSCommandPath:  ($PSCommandPath)
FOREST:         $($script:ADForest.Name)
DOMAIN:         $($script:ADDomain.DNSRoot)
LOG FILE:       $($script:LogFile)
ARCHIVE FILE:   $($script:Archive)
PDC:            $($script:ADDomain.PDCEmulator)
DCs:            $($script:DCs)
"@
        Write-Console -Message "`n$summary"
        Write-Log -Message $details -Level INFO

        # 2. Discover functions to execute
        Write-Log -Message "Discovering Get-* functions..." -Level INFO
        $allFunctions = Get-Command -CommandType Function |
            Where-Object {
                $_.ScriptBlock.File -eq $PSCommandPath -and # Only from this script
                $_.Name -like "Get-*"                       # Only "Get-" functions
            }

        $scriptBlocks = @($allFunctions | ForEach-Object { [scriptblock]::Create($_.Name) })
        $functionNames = $scriptBlocks | ForEach-Object { $_.ToString() }
        Write-Log -Message "Executing script functions: $($functionNames -join ', ')" -Level INFO

        # 3. Create and execute script blocks
        $total = $scriptBlocks.Count
        $current = 0
        Write-Progress -Activity "Executing BRAVE Script" -Completed

        foreach ($command in $scriptBlocks) {
            $current++
            $percentComplete = ($current / $total) * 100
            Write-Log "Running $($command.ToString())"
            Write-Progress -Activity "Executing BRAVE Audit" -Status "Running $($command.ToString())" -PercentComplete $percentComplete

            try {
                & $command
            }
            catch {
                Write-Log -Message "Command execution failed: $($command.ToString())" -Level ERROR -Exception $_
            }
        } 

        Write-Console -Message "`nCREATING ARCHIVE FILE: $script:Archive"

        # 4. Archive results
        $itemsToArchive = Get-ChildItem -Path $script:OutputDirectory -Recurse -File
        Write-Log -Message "Archive File Count: $($itemsToArchive.Count)" -Level INFO
        Write-Log -Message "Archiving: $($itemsToArchive.Name -join ', ')" -Level INFO

        try {
            # Add files
            if ($itemsToArchive) {
                $nonLogFiles = $itemsToArchive | Where-Object { $_.FullName -ne $script:LogFile }
                Compress-Archive -Path $nonLogFiles.FullName -DestinationPath $script:Archive -Force
                Write-Log -Message "Added output directory contents to archive" -Level INFO
                Start-Sleep -Seconds 1
            }

            # Add PS script
            if ($PSCommandPath) {
                Compress-Archive -Path $PSCommandPath -DestinationPath $script:Archive -Update
                Write-Log -Message "Added script $PSCommandPath to archive" -Level INFO
                Start-Sleep -Seconds 1
            }

            # Write summary
            $duration = [datetime]::UtcNow - $script:StartTime
            $durationFormatted = if ($duration.TotalHours -ge 1) {
                $duration.ToString('hh\:mm\:ss')
            } else {
                $duration.ToString('mm\:ss')
            }

            $summary = @"
CREATED:    $script:Archive
STARTED:    $(Format-DateTime $script:StartTime -Format Write)
FINISHED:   $(Format-DateTime ([datetime]::UtcNow) -Format Write)
DURATION:   $durationFormatted
"@ 
            Write-Log -Message "`n$summary" -Level INFO
            Write-Log -Message "=== BRAVE Assessment Complete ===" -Level INFO
            Start-Sleep -Seconds 2

            # Add log file
            Compress-Archive -Path $script:LogFile -DestinationPath $script:Archive -Update
            Write-Log -Message "Added log file to archive" -Level INFO
            Start-Sleep -Seconds 1

            # Verify archive and cleanup
            if (Test-Path $script:Archive) {
                if (Test-Archive -Path $script:Archive) {
                    try { # Cleanup
                        Get-ChildItem -Path $script:OutputDirectory -Exclude (Split-Path $script:LogFile -Leaf) |
                            Remove-Item -Recurse -Force -Confirm:$false
                        Remove-Item -Path $script:LogFile -Force
                        Remove-Item -Path $script:OutputDirectory -Force
                    }
                    catch {
                        Write-Log -Message "Failed to clean up: $_" -Level ERROR
                    }
                }
                else {
                    Write-Log -Message "Archive verification failed - skipping cleanup" -Level WARN
                    Write-Console -Message "Archive verification failed" -Type warn
                }
            }
            else {
                Write-Log -Message "Archive not found - skipping cleanup" -Level WARN
                Write-Console -Message "Archive not found" -Type warn
            }
        }
        catch {
            Write-Warning "Critical error during archive creation: $_"
            throw
        }
    }
    catch {
        Write-Console -Message "Error starting BRAVE assessment" -Type err
        throw
    }
    finally {
        Write-Progress -Activity "Executing BRAVE Script" -Completed
        Write-Host "`n$summary" -ForegroundColor Cyan
    }
}

# Script Execution
try {
    # Run Initialize-BRAVE
    $initResult = Initialize-BRAVE
    
    # Check return from Initialize-BRAVE
    if ($null -eq $initResult -or $initResult -eq $false) {
        Write-Log -Message "Initalize failed" -Level ERROR
        Write-Console -Message "Error initalizing BRAVE script" -Type err
        exit 1 # Exit script
    }
    
    # Continue with main execution
    Start-BRAVE
} 
catch {
    Write-Log -Message "Main execution failed" -Level ERROR -Exception $_
    Write-Console -Message "Error executing BRAVE script" -Type err
    exit 1
}