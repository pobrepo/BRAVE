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
    [string[]]$RequiredModules = @('ActiveDirectory', 'PSPKI'),
    [string]$Directory = "c:\temp\BRAVE\"
    
)
Get-Variable script:* | Remove-Variable -Force 
$ErrorActionPreference = "SilentlyContinue"
$script:Directory = $Directory
$script:RequiredModules = $RequiredModules

$script:Format = {
    param(
        [Parameter(ValueFromPipeline)]
        $Value,
        [ValidateSet('Write', 'File')]
        [string]$Format = 'Write'
    )
    
    if ($null -eq $Value) { return '' }
    
    switch ($Value) {
        { $_ -is [DateTime] } { 
            $utcTime = $_.ToUniversalTime()
            switch($Format) {
                'Write' { return $utcTime.ToString('dd MMM yyyy HH:mm (UTC)') }
                'File'  { return $utcTime.ToString('ddMMMyyyy_HHmmss_UTC') }
            }
        }
        { $_ -is [TimeSpan] } { return $_.TotalDays }
        default { return $_ }
    }
}

function Write-Info {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$m,
        [ValidateSet('Info', 'Debug', 'Done', 'Warn', 'Error',  'Header', 'Status')]
        [string]$lvl = 'Info',
        [System.Management.Automation.ErrorRecord]$ex,
        [string]$show
    )
    $ts = & $script:Format (Get-Date) -Format Write
    $msg = "[$ts] [$lvl] $m"
   
    try {        
        $msg | Out-File -FilePath $script:Log -Append -Force -Encoding UTF8
    } catch {
        Write-Warning "[!] Write-Info failed: $msg"
    }

    if ($show) {
        switch ($lvl) {
            'Info'   { Write-Host $show -ForegroundColor Cyan }
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

function Get-Prerequisites {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Verify
    )

    Write-Info -m "Checking prerequisites" -show "Checking Prerequisites"
    
    $RequiredModules = $Verify.Clone()
    
    try {
        $RSATInstalled = (Get-WindowsFeature -Name RSAT-AD-PowerShell).Installed
        if ($RSATInstalled) {
            $RequiredModules = $RequiredModules -notmatch "ActiveDirectory"
            Write-Info -m "RSAT installed, AD module available"
        }
    } catch {
        Write-Info -m "Unable to verify RSAT status" -lvl Warn
    }

    $ModulesLoaded = Get-Module | Where-Object { $_.Name -in $RequiredModules }
    $RequiredModules = $RequiredModules | Where-Object { $_ -notin $ModulesLoaded.Name }
    
    if ($ModulesLoaded) {
        Write-Info -m "Already loaded: $($ModulesLoaded.Name -join ', ')"
    }

    if ($RequiredModules.Count -gt 0) {
        Write-Info -m "Processing modules: $($RequiredModules -join ', ')" -show "Installing Modules"
        
        foreach ($Module in $RequiredModules) {
            if (-not (Get-Module -Name $Module -ListAvailable)) {
                Write-Info -m "Installing: $Module" -show "Installing $Module"
                try {
                    Install-Module -Name $Module -Force -Scope CurrentUser
                    Write-Info -m "Installed: $Module"
                } catch {
                    Write-Info -m "Failed installing: $Module" -lvl Error -ex $_
                }
            }
            
            try {
                Import-Module -Name $Module -Force
                Write-Info -m "Loaded: $Module" -lvl Done
            } catch {
                Write-Info -m "Failed loading: $Module" -lvl Error -ex $_
            }
        }
    }

    $FinalModules = Get-Module | Where-Object { $_.Name -in $Verify }
    $Missing = $Verify | Where-Object { $_ -notin $FinalModules.Name }
    
    if ($Missing.Count -eq 0) {
        Write-Info -m "All modules verified" -lvl Done -show "Prerequisites: Ready"
    } else {
        Write-Info -m "Missing modules: $($Missing -join ', ')" -lvl Error -show "Prerequisites: Failed"
    }
}

function  Get-ADCS {
    [CmdletBinding()]
    param (
        [string[]]$Functions
    )

    $transcriptPath = Join-Path $script:Directory "$(Get-Date -Format 'ddMMyyyy_HHmm').transcript"
    Start-Transcript -Path $transcriptPath

    Write-Info -m "Start-BRAVE running"

    # Prerequisites
    Get-Prerequisites -Verify $script:RequiredModules

    # Environment
    $script:ADDomain = Get-ADDomain
    $script:filename = "$($script:ADDomain.DNSRoot)_$(& $script:Format (Get-Date) -Format 'File')"
    $script:Log = Join-Path $script:Directory "$($script:filename).log"
    $script:Archive = Join-Path (Split-Path $script:Directory) "$($script:filename).zip"
    
    try {
        if (-not (Test-Path $script:Directory)) {
            try {
                New-Item -Path $script:Directory -ItemType Directory -Force | Out-Null
                Write-Info -m "Created: $($script:Directory)"
            } catch {
                Write-Info -m "Failed creating $($script:Directory)" -lvl Error -ex $_
            }
        }
        
        "=== ADCS Started ===" | Set-Content -Path $script:Log -Force -Encoding UTF8
    } catch {
        Write-Info -m "Failed creating $($script:Log)" -lvl Error -ex $_
    }

    try {
        $cas = Get-CA
        
        if($cas) {
            $Controls = [ordered]@{
                'ADCS_CA' = {
                    Write-Info -m "Processing CAs" -show "Certificate Authorities"
                    
                    $Authorities = @()
                    foreach ($ca in $cas) {
                        Write-Info -m "Processing: $($ca.Name)"
                        
                        $endpointDetails = if ($ca.EnrollmentEndpoints) {
                            $ca.EnrollmentEndpoints | ForEach-Object {
                                $isHttps = $_.Uri -like "https://*"
                                $usesNTLM = $_.Authentication -like "*NTLM*"
                                
                                "EndpointUri=$($_.Uri); IsHttps=$isHttps; Auth=$($_.Authentication); UsesNTLM=$usesNTLM"
                            }
                        }
                        $enrollmentEndpoints = if ($endpointDetails) { $endpointDetails -join " | " } else { "None" }
                        
                        $Authorities += [PSCustomObject]@{
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
                            OS                 = $ca.OperatingSystem
                            SetupStatus        = $ca.SetupStatus
                            Certificate        = $ca.Certificate
                            ConfigString       = $ca.ConfigString
                            DistinguishedName  = $ca.DistinguishedName
                            ManagerApproval    = $ca.CAManagerApproval
                            EnrollmentEndpoints = $enrollmentEndpoints
                            EnrollmentPrincipals = ($ca.EnrollmentPrincipals -join ", ")
                        } | & $script:Export -Name $section
                    }
                }
            
                'ADCS_TEMPLATES' = {
                    Write-Info -m "Processing Certificate Templates" -show "Certificate Templates"
                    
                    $Templates = Get-CertificateTemplate
                    if (-not $Templates) {
                        Write-Info -m "No templates found" -lvl Warn
                        return @{ Status = "No templates found" } | & $script:Export -Name $section -IsSummary
                    }

                    # Raw template data
                    $Templates | Select-Object * | & $script:Export -Name "$section`_Raw"
                    
                    # Security analysis
                    $LowPrivilegedGroups = "Domain Users|Authenticated Users|Everyone"
                    
                    $FilteredResults = foreach($Template in $Templates) {
                        Write-Info -m "Analyzing template: $($Template.Name)"
                        
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

                        [PSCustomObject]@{
                            Name = $Template.Name
                            SensitiveKeyUsage = $SensitiveKeyUsage
                            LowPrivilegedEnrollment = [bool]$LowPrivilegedEnrollment
                            CAManagerApproval = $CAManagerApproval
                            EnrollmentPrincipals = ($EnrollmentRights | ForEach-Object {
                                "$($_.IdentityReference)"
                            }) -join '; '
                            EnhancedKeyUsage = ($TemplateProps.'pKIExtendedKeyUsage' -join '; ')
                            Risk = $riskLevel
                        }
                    }

                    # Export filtered results
                    $FilteredResults | & $script:Export -Name $section

                    # Generate and export summary
                    $summarized = @(
                        @{ Name = "Total"; Filter = { $true } },
                        @{ Name = "Sensitive"; Filter = { $_.SensitiveKeyUsage } },
                        @{ Name = "Critical"; Filter = { $_.Risk -like "CRITICAL*" } },
                        @{ Name = "High"; Filter = { $_.Risk -like "HIGH*" } },
                        @{ Name = "Medium"; Filter = { $_.Risk -like "MEDIUM*" } },
                        @{ Name = "Low"; Filter = { $_.Risk -like "LOW*" } },
                        @{ Name = "Info"; Filter = { $_.Risk -like "INFO*" } }
                    )

                    $summary = $summarized | ForEach-Object {
                        [PSCustomObject]@{
                            Section = $section
                            Category = $_.Name
                            Count = ($FilteredResults | Where-Object $_.Filter).Count
                        }
                    }

                    # Export summary
                    $summary | & $script:Export -Name $section -IsSummary

                    # Display results to console
                    $FilteredResults | 
                        Sort-Object { switch($_.Risk) {
                            "CRITICAL" {1}
                            "HIGH" {2}
                            "MEDIUM" {3}
                            "LOW" {4}
                            default {5}
                        }} | Format-Table Name, SensitiveKeyUsage, LowPrivilegedEnrollment, CAManagerApproval, Risk -AutoSize
                }

                'ADCS_NTAUTH' = {
                    Write-Info -m "Processing NTAuth Certificates" -show "NTAuth Certificates"
                    
                    $domain = (Get-ADDomain).DNSRoot
                    $ntAuthPath = "CN=NtAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$($domain -replace '\.',',DC=')"
                    
                    Get-ADObject -Filter * -SearchBase $ntAuthPath -Properties * | 
                        Select-Object CanonicalName, CN, Created, Description, DisplayName, objectClass |
                        & $script:Export -Name $section
                }
            
                'ADCS_LOGGING' = {
                    Write-Info -m "Processing CA Logging Configuration" -show "CA Logging"

                    if (-not $cas) {
                        Write-Info -m "No CAs found to audit" -lvl Warn
                        return @{ Status = "No CAs found" } | & $script:Export -Name $section -IsSummary
                    }

                    $results = foreach ($ca in $cas) {
                        Write-Info -m "Auditing logging for: $($ca.ComputerName)" -lvl Debug

                        # Get SCE Policy
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

                        # Get Audit Policy
                        $auditPolicy = try { 
                            $output = auditpol /get /subcategory:"Certification Services" | Out-String
                            if ($output -match 'Certification Services\s+(.+)$') {
                                $matches[1].Trim()
                            } else {
                                "No policy found"
                            }
                        } catch { 
                            "Error: $($_.Exception.Message)"
                        }

                        # Get CA Audit Configuration
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

                        # Create result object
                        [PSCustomObject]@{
                            Name = $ca.ComputerName
                            SCEPolicy = $scePolicy
                            AuditPolicy = $auditPolicy
                            AuditConfiguration = $auditConfig
                            HasSCEPolicy = $scePolicy -notmatch "Error|Not configured"
                            HasAuditPolicy = $auditPolicy -match "Success|Failure"
                            HasAuditConfig = $auditConfig -match "Success|Failure"
                        }
                    }

                    # Export detailed results
                    $results | & $script:Export -Name $section

                    # Generate summary
                    $summary = @{
                        'Total CAs' = $cas.Count
                        'CAs with SCE Policy' = ($results | Where-Object HasSCEPolicy).Count
                        'CAs with Audit Policy' = ($results | Where-Object HasAuditPolicy).Count
                        'CAs with Audit Config' = ($results | Where-Object HasAuditConfig).Count
                        'Fully Configured CAs' = ($results | Where-Object { 
                            $_.HasSCEPolicy -and $_.HasAuditPolicy -and $_.HasAuditConfig 
                        }).Count
                    }

                    # Export summary
                    $summary | & $script:Export -Name $section -IsSummary

                    # Generate detailed audit log
                    $auditLog = foreach ($ca in $results) {
                        "CA: $($ca.Name)"
                        "SCE Policy: $($ca.SCEPolicy)"
                        "Audit Policy: $($ca.AuditPolicy)"
                        "Audit Configuration: $($ca.AuditConfiguration)"
                        "----------------------------------------"
                    }

                    # Export audit log
                    $auditLog | Out-File -FilePath (Join-Path $script:Directory "$($script:filename)-$section-audit.txt") -Encoding UTF8

                    # Display results
                    $results | Format-Table Name, SCEPolicy, AuditPolicy, AuditConfiguration -AutoSize
                }
            } 
        }
       
        $sectionsToProcess = $Controls.Keys
        foreach ($section in $sectionsToProcess) {
            Write-Info -m "Processing section: $section" -show "$section"
            
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
                    Write-Info -m "Error processing: $section" -lvl Warn -ex $_
                    @{
                        $section = $_.Exception.Message
                    } | & $script:Export -Name $section -IsSummary
                }
            } catch {
                Write-Info -m "$section failed" -lvl Warn -ex $_
                @{
                    $section = $_.Exception.Message
                } | & $script:Export -Name $section -IsSummary
            }
        }
    
        try { 
            # Get all items to archive
            $itemsToArchive = @()
            $itemsToArchive += @(Get-ChildItem -Path $script:Directory -File)
            Write-Info -m "Archiving $($itemsToArchive.Count) files"
            Write-Info -m "Archiving: $($itemsToArchive.Name -join ', ')"

            if ($itemsToArchive.Count -gt 0) {
                try {
                    $nonLogFiles = $itemsToArchive | Where-Object { $_.FullName -ne $script:Log }
                    if ($nonLogFiles) {
                        Compress-Archive -Path $nonLogFiles.FullName -DestinationPath $script:Archive -Force
                        Write-Info -m "Added: $($nonLogFiles.FullName -join ', ')" -lvl Debug
                        Start-Sleep -Milliseconds 500
                    }
                } catch {
                    Write-Info -m "Failed creating $($script:Archive)" -lvl Warn -ex $_ -show "Failed Creating $($script:Archive)"
                }
            }

            $duration = [datetime]::UtcNow - $script:StartTime
            $durationFormatted = if ($duration.TotalHours -ge 1) {
                $duration.ToString('hh\:mm\:ss')
            } else {
                $duration.ToString('mm\:ss')
            }

            $summary = @(
                "STARTED:  $(& $script:Format $script:StartTime -Format Write)"
                "FINISHED: $(& $script:FormatValue (Get-Date) -Format Write)"
                "DURATION: $durationFormatted"
                "CREATED:  $script:Archive"
            ) -join "`n"

            Write-Info  "$summary"
            Write-Info -m "=== ADCS Complete ==="
            Start-Sleep -Milliseconds 500

            # Add log file
            Write-Info -m "Adding: $($script:Log) to $($script:Archive)"
            Compress-Archive -Path $script:Log -DestinationPath $script:Archive -Update
            Start-Sleep -Milliseconds 500
        } catch {
            Write-Info -m "Error creating $($script:Archive)" -lvl Warn -ex $_ -show "Unable to create archive"
        }
    } catch {
        Write-Info -m "Failed enumerating CAs" -lvl Warn -ex $_
    }

    Stop-Transcript
}


Get-ADCS