 $outputFilePath = "Windows_Server_2016_Compilance_Report.csv"

# Write system details to the file
function Write-SystemDetails {
    $systemDetails = @"
Serial No., Control Objective, Compliance Status
"@
    Add-Content -Path $outputFilePath -Value $systemDetails
    Write-Host $systemDetails
}

# Function to check compliance status
function Check-ComplianceStatus {
    param (
        [int]$serialNumber,
        [string]$controlObjective,
        [scriptblock]$checkFunction,
        [bool]$manualCheck = $false,
        [bool]$applicable = $true
    )

    if (-not $applicable) {
        $complianceStatus = "Not Applicable"
    } elseif ($manualCheck) {
        $complianceStatus = "Manual Checks Required"
    } else {
        $complianceStatus = try { if (& $checkFunction) { "Compliant" } else { "Non-Compliant" } } catch { "Non-Compliant" }
    }

    $result = "$serialNumber,$controlObjective,$complianceStatus"
    Add-Content -Path $outputFilePath -Value $result
    Write-Host $result
}

# Fetch the security policy settings
function Get-SecurityPolicy {
    secedit /export /cfg C:\Windows\Temp\secpol.cfg
    $settings = Get-Content C:\Windows\Temp\secpol.cfg
    return $settings
}

$securityPolicy = Get-SecurityPolicy

# Define audit checks
$auditChecks = @(
    @{
        SerialNumber = 1
        ControlObjective   = "Ensure 'Account lockout duration' is set to '15 or more minute(s)'"
        CheckFunction      = {
            $lockoutDurationLine = $securityPolicy | Select-String -Pattern "LockoutDuration\s*=\s*(\d+)"
            if ($lockoutDurationLine) {
                $lockoutDuration = [int]($lockoutDurationLine -split '=')[1].Trim()
                return $lockoutDuration -ge 15
            } else {
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    
@{
    SerialNumber = 2
    ControlObjective = "Ensure 'Allow Administrator account lockout' is set to 'Enabled'"
    CheckFunction = {
        $match = $securityPolicy | Select-String -Pattern "AllowAdministratorLockout\s*=\s*(\d+)"
        if ($match) {
            $adminLockout = [int]$match.Matches.Groups[1].Value
            return $adminLockout -eq 1
        } else {
            return $false
        }
    }
    ManualCheck = $false
    Applicable = $true
},

    @{
        SerialNumber = 3
        ControlObjective   = "Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'"
        CheckFunction      = {
            $match = $securityPolicy | Select-String -Pattern "ResetLockoutCount\s*=\s*(\d+)"
            if ($match) {
                $resetCounter = [int]$match.Matches.Groups[1].Value
                return $resetCounter -ge 15
            } else {
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 4
        ControlObjective = "Ensure 'Minimum password age' is set to '1 or more day'"
        CheckFunction = {
            $match = $securityPolicy | Select-String -Pattern "MinimumPasswordAge\s*=\s*(\d+)"
            if ($match) {
                $minPasswordAge = [int]$match.Matches.Groups[1].Value
                return $minPasswordAge -ge 1
            } else {
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 5
        ControlObjective   = "Ensure 'Password must meet complexity requirements' is set to 'Enabled'"
        CheckFunction      = {
            $match = $securityPolicy | Select-String -Pattern "PasswordComplexity\s*=\s*(\d+)"
            if ($match) {
                $passwordComplexity = [int]$match.Matches.Groups[1].Value
                return $passwordComplexity -eq 1
            } else {
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 6
        ControlObjective   = "Ensure 'Store passwords using reversible encryption' is set to 'Disabled'"
        CheckFunction      = {
            $match = $securityPolicy | Select-String -Pattern "ClearTextPassword\s*=\s*(\d+)"
            if ($match) {
                $reversibleEncryption = [int]$match.Matches.Groups[1].Value
                return $reversibleEncryption -eq 0
            } else {
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 7
        ControlObjective   = "Ensure 'Audit Credential Validation' is set to 'Success and Failure'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Credential Validation" | Select-String "Credential Validation").Line
            return $auditSetting -match "Success and Failure"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 8
        ControlObjective   = "Ensure 'Audit Kerberos Authentication Service' is set to 'Success and Failure'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Kerberos Authentication Service" | Select-String "Kerberos Authentication Service").Line
            return $auditSetting -match "Success and Failure"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 9
        ControlObjective   = "Ensure 'Audit Kerberos Service Ticket Operations' is set to 'Success and Failure'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Kerberos Service Ticket Operations" | Select-String "Kerberos Service Ticket Operations").Line
            return $auditSetting -match "Success and Failure"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 10
        ControlObjective   = "Ensure 'Audit Computer Account Management' is set to include 'Success'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Computer Account Management" | Select-String "Computer Account Management").Line
            return $auditSetting -match "Success"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 11
        ControlObjective   = "Ensure 'Audit Distribution Group Management' is set to include 'Success'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Distribution Group Management" | Select-String "Distribution Group Management").Line
            return $auditSetting -match "Success"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 12
        ControlObjective   = "Ensure 'Audit Other Account Management Events' is set to include 'Success'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Other Account Management Events" | Select-String "Other Account Management Events").Line
            return $auditSetting -match "Success"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 13
        ControlObjective   = "Ensure 'Audit Security Group Management' is set to include 'Success'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Security Group Management" | Select-String "Security Group Management").Line
            return $auditSetting -match "Success"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 14
        ControlObjective   = "Ensure 'Audit User Account Management' is set to 'Success and Failure'"
        CheckFunction      = {
            try {
                $auditSetting = auditpol /get /subcategory:"User Account Management" 2>&1
                if ($auditSetting -match "Success" -and $auditSetting -match "Failure") {
                    return $true
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Audit User Account Management: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 15
        ControlObjective   = "Ensure 'Audit PNP Activity' is set to include 'Success' (Automated)"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Plug and Play Events" | Select-String "Plug and Play").Line
            return $auditSetting -match "Success"
        }
        ManualCheck = $false
        Applicable = $true
    },
    

    @{
        SerialNumber = 16
        ControlObjective   = "Ensure 'Audit Process Creation' is set to include 'Success' (Automated)"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Process Creation" | Select-String "Process Creation").Line
            return $auditSetting -match "Success"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 17
        ControlObjective   = "Ensure 'Audit Directory Service Access' is set to include 'Failure'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Directory Service Access" | Select-String "Directory Service Access").Line
            return $auditSetting -match "Failure"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 18
        ControlObjective   = "Ensure 'Audit Directory Service Changes' is set to include 'Success'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Directory Service Changes" | Select-String "Directory Service Changes").Line
            return $auditSetting -match "Success"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 19
        ControlObjective   = "Ensure 'Audit Account Lockout' is set to include 'Failure'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Account Lockout" | Select-String "Account Lockout").Line
            return $auditSetting -match "Failure"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 20
        ControlObjective   = "Ensure 'Audit Group Membership' is set to include 'Success'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Group Membership" | Select-String "Group Membership").Line
            return $auditSetting -match "Success"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 21
        ControlObjective   = "Ensure 'Audit Logoff' is set to include 'Success'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Logoff" | Select-String "Logoff").Line
            return $auditSetting -match "Success"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 22
        ControlObjective   = "Ensure 'Audit Logon' is set to 'Success and Failure'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Logon" | Select-String "Logon").Line
            return $auditSetting -match "Success and Failure"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 23
        ControlObjective   = "Ensure 'Audit Other Logon/Logoff Events' is set to 'Success and Failure'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Other Logon/Logoff Events" | Select-String "Other Logon/Logoff Events").Line
            return $auditSetting -match "Success and Failure"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 24
        ControlObjective   = "Ensure 'Audit Special Logon' is set to include 'Success'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Special Logon" | Select-String "Special Logon").Line
            return $auditSetting -match "Success"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 25
        ControlObjective   = "Ensure 'Audit Detailed File Share' is set to include 'Failure'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Detailed File Share" | Select-String "Detailed File Share").Line
            return $auditSetting -match "Failure"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 26
        ControlObjective   = "Ensure 'Audit File Share' is set to 'Success and Failure'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"File Share" | Select-String "File Share").Line
            return $auditSetting -match "Success and Failure"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 27
        ControlObjective   = "Ensure 'Audit Other Object Access Events' is set to 'Success and Failure'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Other Object Access Events" | Select-String "Other Object Access Events").Line
            return $auditSetting -match "Success and Failure"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 28
        ControlObjective   = "Ensure 'Audit Removable Storage' is set to 'Success and Failure'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Removable Storage" | Select-String "Removable Storage").Line
            return $auditSetting -match "Success and Failure"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 29
        ControlObjective   = "Ensure 'Audit Policy Change' is set to include 'Success'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Audit Policy Change" | Select-String "Audit Policy Change").Line
            return $auditSetting -match "Success"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 30
        ControlObjective   = "Ensure 'Audit Authentication Policy Change' is set to include 'Success'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Authentication Policy Change" | Select-String "Authentication Policy Change").Line
            return $auditSetting -match "Success"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 31
        ControlObjective   = "Ensure 'Audit MPSSVC Rule-Level Policy Change' is set to 'Success and Failure'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"MPSSVC Rule-Level Policy Change" | Select-String "MPSSVC Rule-Level Policy Change").Line
            return $auditSetting -match "Success and Failure"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 32
        ControlObjective   = "Ensure 'Audit Other Policy Change Events' is set to include 'Failure'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Other Policy Change Events" | Select-String "Other Policy Change Events").Line
            return $auditSetting -match "Failure"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 33
        ControlObjective   = "Ensure 'Audit Sensitive Privilege Use' is set to 'Success and Failure'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Sensitive Privilege Use" | Select-String "Sensitive Privilege Use").Line
            return $auditSetting -match "Success and Failure"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 34
        ControlObjective   = "Ensure 'Audit IPsec Driver' is set to 'Success and Failure'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"IPsec Driver" | Select-String "IPsec Driver").Line
            return $auditSetting -match "Success and Failure"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 35
        ControlObjective   = "Ensure 'Audit Other System Events' is set to 'Success and Failure'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Other System Events" | Select-String "Other System Events").Line
            return $auditSetting -match "Success and Failure"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 36
        ControlObjective   = "Ensure 'Audit Security State Change' is set to include 'Success'"
        CheckFunction      = {
            $auditSetting = (auditpol /get /subcategory:"Security State Change" | Select-String "Security State Change").Line
            return $auditSetting -match "Success"
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 37
        ControlObjective   = "Ensure 'Audit Security System Extension' is set to include 'Success'"
        CheckFunction      = {
            try {
                $auditSetting = (auditpol /get /subcategory:"Security System Extension" | Select-String "Security System Extension").Line
                return $auditSetting -match "Success"
            } catch {
                Write-Host "Error checking Audit Security System Extension: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 38
        ControlObjective   = "Ensure 'Audit System Integrity' is set to 'Success and Failure'"
        CheckFunction      = {
            try {
                $auditSetting = (auditpol /get /subcategory:"System Integrity" | Select-String "System Integrity").Line
                return $auditSetting -match "Success and Failure"
            } catch {
                Write-Host "Error checking Audit System Integrity: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 39
        ControlObjective = "Ensure 'Do not display the password reveal button' is set to 'Enabled'"
        CheckFunction = {
            try {
                # Define the policy name and output file path
                $policyName = "Do not display the password reveal button"
                $gpResultFile = "$env:TEMP\GPResult.txt"

                # Generate GPResult report
                gpresult /h $gpResultFile

                # Read the report content
                $gpResultContent = Get-Content $gpResultFile -Raw

                # Check if the policy is present in the report and if it's enabled
                if ($gpResultContent -like "*$policyName*") {
                    if ($gpResultContent -like "*Enabled*") {
                        # Clean up temporary files
                        Remove-Item $gpResultFile
                        return $true
                    } else {
                        # Clean up temporary files
                        Remove-Item $gpResultFile
                        return $false
                    }
                } else {
                    # Clean up temporary files
                    Remove-Item $gpResultFile
                    return $false
                }
            } catch {
                Write-Host "Error checking policy: $_"
                # Clean up temporary files in case of error
                Remove-Item "$env:TEMP\GPResult.txt" -ErrorAction SilentlyContinue
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 40
        ControlObjective   = "Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'"
        CheckFunction      = {
            try {
                # Define the policy name and output file path
                $policyName = "Enumerate administrator accounts on elevation"
                $gpResultFile = "$env:TEMP\GPResult.txt"

                # Generate GPResult report
                gpresult /h $gpResultFile

                # Read the report content
                $gpResultContent = Get-Content $gpResultFile -Raw

                # Check if the policy is present in the report and if it's disabled
                if ($gpResultContent -like "*$policyName*") {
                    if ($gpResultContent -like "*Disabled*") {
                        # Clean up temporary files
                        Remove-Item $gpResultFile
                        return $true
                    } else {
                        # Clean up temporary files
                        Remove-Item $gpResultFile
                        return $false
                    }
                } else {
                    # Clean up temporary files
                    Remove-Item $gpResultFile
                    return $false
                }
            } catch {
                Write-Host "Error checking policy: $_"
                # Clean up temporary files in case of error
                Remove-Item "$env:TEMP\GPResult.txt" -ErrorAction SilentlyContinue
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },


    @{
        SerialNumber = 41
        ControlObjective   = "Ensure 'Minimize the number of simultaneous connections to the Internet' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" -Name "fMinimizeConnections" -ErrorAction SilentlyContinue
                    if ($null -ne $registryValue) {
                        return $registryValue.fMinimizeConnections -eq 1
                    } else {
                        return $false
                    }
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking simultaneous connections: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 42
        ControlObjective   = "Ensure 'Include command line in process creation events' is set to 'Enabled' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
                    return $registryValue.ProcessCreationIncludeCmdLine_Enabled -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking command line inclusion in process creation events: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 43
        ControlObjective   = "Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good unknown and bad but critical' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch" -Name "DriverLoadPolicy" -ErrorAction SilentlyContinue
                    return $registryValue.DriverLoadPolicy -eq 3
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Boot-Start Driver Initialization Policy: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 44
        ControlObjective   = "Ensure 'Configure registry policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoBackgroundPolicy" -ErrorAction SilentlyContinue
                    return $registryValue.NoBackgroundPolicy -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking registry policy processing (background): $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 45
        ControlObjective   = "Ensure 'Continue experiences on this device' is set to 'Disabled' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableCdp" -ErrorAction SilentlyContinue
                    return $registryValue.EnableCdp -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Continue experiences on this device: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 46
        ControlObjective   = "Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled' (Automated)"
        CheckFunction      = {
            try {
                if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableBkGndGroupPolicy")) {
                    return $true
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking background refresh of Group Policy: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 47
        ControlObjective   = "Ensure 'Configure registry policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name "NoGPOListChanges" -ErrorAction SilentlyContinue
                    return $registryValue.NoGPOListChanges -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking registry policy processing (GPO changes): $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 48
        ControlObjective   = "Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoWebServices" -ErrorAction SilentlyContinue
                    return $registryValue.NoWebServices -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Internet download for Web publishing and online ordering wizards: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 49
        ControlObjective   = "Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "DisableWebPnPDownload" -ErrorAction SilentlyContinue
                    return $registryValue.DisableWebPnPDownload -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking download of print drivers over HTTP: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
   
    @{
        SerialNumber = 50
        ControlObjective = "Ensure 'Accounts: Guest account status' is set to 'Disabled'"
        CheckFunction = {
            try {
                # Query the status of the Guest account
                $guestAccountStatus = (Get-WmiObject -Class Win32_UserAccount -Filter "Name='Guest'").Disabled
                
                # Check if the Guest account is disabled
                return $guestAccountStatus -eq $true
            } catch {
                Write-Host "Error checking Accounts: Guest account status: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 51
        ControlObjective   = "Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "NoConnectedUser" -ErrorAction SilentlyContinue
                    return $registryValue.NoConnectedUser -eq 3
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Block Microsoft accounts: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 52
        ControlObjective   = "Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -ErrorAction SilentlyContinue
                    return $registryValue.LimitBlankPasswordUse -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking limit of blank passwords: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 53
        ControlObjective   = "Configure 'Accounts: Rename guest account' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "RenameGuestAccount" -ErrorAction SilentlyContinue
                    return $registryValue.RenameGuestAccount -ne ""
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking rename of guest account: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 54
        ControlObjective   = "Configure 'Accounts: Rename administrator account'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "RenameAdminAccount" -ErrorAction SilentlyContinue
                    return $registryValue.RenameAdminAccount -ne ""
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking rename of administrator account: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 55
        ControlObjective   = "Ensure 'Audit: Force audit policy subcategory settings to override audit policy category settings' is set to 'Enabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SCENoApplyLegacyAuditPolicy" -ErrorAction SilentlyContinue
                    return $registryValue.SCENoApplyLegacyAuditPolicy -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking force audit policy subcategory settings: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 56
        ControlObjective   = "Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "CrashOnAuditFail" -ErrorAction SilentlyContinue
                    return $registryValue.CrashOnAuditFail -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking shut down system on audit failure: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 57
        ControlObjective   = "Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireSignOrSeal" -ErrorAction SilentlyContinue
                    return $registryValue.RequireSignOrSeal -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking digital encryption or signing of secure channel data (always): $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 58
        ControlObjective   = "Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SealSecureChannel" -ErrorAction SilentlyContinue
                    return $registryValue.SealSecureChannel -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking digital encryption of secure channel data (when possible): $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 59
        ControlObjective   = "Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SignSecureChannel" -ErrorAction SilentlyContinue
                    return $registryValue.SignSecureChannel -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking digital signing of secure channel data (when possible): $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 60
        ControlObjective   = "Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "DisablePasswordChange" -ErrorAction SilentlyContinue
                    return $registryValue.DisablePasswordChange -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking disable machine account password changes: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 61
        ControlObjective   = "Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days but not 0'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "MaximumPasswordAge" -ErrorAction SilentlyContinue
                    return $registryValue.MaximumPasswordAge -le 30 -and $registryValue.MaximumPasswordAge -ne 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking maximum machine account password age: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 62
        ControlObjective   = "Ensure 'Domain member: Require strong session key' is set to 'Enabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireStrongKey" -ErrorAction SilentlyContinue
                    return $registryValue.RequireStrongKey -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking require strong session key: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 63
        ControlObjective   = "Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled' (DC only) (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "SubmitControl" -ErrorAction SilentlyContinue
                    return $registryValue.SubmitControl -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking allow server operators to schedule tasks: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 64
        ControlObjective = "Ensure 'Domain controller: Allow vulnerable Netlogon secure channel connections' is set to 'Not Configured' (DC Only) (Automated)"
        CheckFunction = {
            try {
                $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
                $registryValueName = "VulnerableChannelAllowList"
                
                # Check if the registry value exists
                if (Test-Path "$registryPath\$registryValueName") {
                    Write-Host "The policy is configured."
                    return $false  # The policy is configured, not "Not Configured"
                } else {
                    Write-Host "The policy is not configured."
                    return $true  # The policy is "Not Configured"
                }
            } catch {
                Write-Host "Error checking Domain controller: Allow vulnerable Netlogon secure channel connections: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 65
        ControlObjective   = "Ensure 'Domain controller: LDAP server channel binding token requirements' is set to 'Always' (DC Only) (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue
                    return $registryValue.LdapEnforceChannelBinding -eq 2
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking LDAP server channel binding token requirements: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 66
        ControlObjective   = "Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing' (DC only) (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
                    return $registryValue.LDAPServerIntegrity -eq 2
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking LDAP server signing requirements: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 67
        ControlObjective   = "Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled' (DC only) (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RefusePasswordChange" -ErrorAction SilentlyContinue
                    return $registryValue.RefusePasswordChange -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking refuse machine account password changes: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 68
        ControlObjective   = "Ensure 'Interactive logon: Do not display last username' is set to 'Enabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DontDisplayLastUserName" -ErrorAction SilentlyContinue
                    return $registryValue.DontDisplayLastUserName -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking interactive logon: do not display last username: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 69
        ControlObjective   = "Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -ErrorAction SilentlyContinue
                    return $registryValue.DisableCAD -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking interactive logon: do not require CTRL+ALT+DEL: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 70
        ControlObjective   = "Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s) but not 0'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -ErrorAction SilentlyContinue
                    return $registryValue.InactivityTimeoutSecs -le 900 -and $registryValue.InactivityTimeoutSecs -ne 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking interactive logon: machine inactivity limit: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 71
        ControlObjective   = "Configure 'Interactive logon: Message text for users attempting to log on'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeText" -ErrorAction SilentlyContinue
                    return $registryValue.LegalNoticeText -ne ""
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking interactive logon: message text for users attempting to log on: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 72
        ControlObjective   = "Configure 'Interactive logon: Message title for users attempting to log on'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LegalNoticeCaption" -ErrorAction SilentlyContinue
                    return $registryValue.LegalNoticeCaption -ne ""
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking interactive logon: message title for users attempting to log on: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 73
        ControlObjective   = "Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ScRemoveOption" -ErrorAction SilentlyContinue
                    return $registryValue.ScRemoveOption -eq 1 -or $registryValue.ScRemoveOption -eq 2 -or $registryValue.ScRemoveOption -eq 3
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking interactive logon: smart card removal behavior: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 74
        ControlObjective   = "Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "PasswordExpiryWarning" -ErrorAction SilentlyContinue
                    return $registryValue.PasswordExpiryWarning -ge 5 -and $registryValue.PasswordExpiryWarning -le 14
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking interactive logon: prompt user to change password before expiration: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 75
        ControlObjective   = "Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ForceUnlockLogon" -ErrorAction SilentlyContinue
                    return $registryValue.ForceUnlockLogon -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking interactive logon: require domain controller authentication to unlock workstation: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 76
        ControlObjective   = "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
                    return $registryValue.RequireSecuritySignature -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Microsoft network client: digitally sign communications (always): $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 77
        ControlObjective   = "Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnableSecuritySignature" -ErrorAction SilentlyContinue
                    return $registryValue.EnableSecuritySignature -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Microsoft network client: digitally sign communications (if server agrees): $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 78
        ControlObjective   = "Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnablePlainTextPassword" -ErrorAction SilentlyContinue
                    return $registryValue.EnablePlainTextPassword -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Microsoft network client: send unencrypted password to third-party SMB servers: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 79
        ControlObjective   = "Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "AutoDisconnect" -ErrorAction SilentlyContinue
                    return $registryValue.AutoDisconnect -le 15
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Microsoft network server: amount of idle time required before suspending session: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 80
        ControlObjective   = "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
                    return $registryValue.RequireSecuritySignature -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Microsoft network server: digitally sign communications (always): $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 81
        ControlObjective   = "Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "enableforcedlogoff" -ErrorAction SilentlyContinue
                    return $registryValue.enableforcedlogoff -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Microsoft network server: disconnect clients when logon hours expire: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 82
        ControlObjective   = "Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher (MS only) (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "SMBServerNameHardeningLevel" -ErrorAction SilentlyContinue
                    return $registryValue.SMBServerNameHardeningLevel -ge 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Microsoft network server: server SPN target name validation level: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 83
        ControlObjective = "Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'"
        CheckFunction = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "EnableSecuritySignature" -ErrorAction SilentlyContinue
                    if ($null -ne $registryValue) {
                        return $registryValue.EnableSecuritySignature -eq 1
                    } else {
                        return $false
                    }
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Microsoft network server: digitally sign communications (if client agrees): $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 84
        ControlObjective   = "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled' (MS only) (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -ErrorAction SilentlyContinue
                    return $registryValue.RestrictAnonymousSAM -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking network access: do not allow anonymous enumeration of SAM accounts: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 85
        ControlObjective   = "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (MS only) (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -ErrorAction SilentlyContinue
                    return $registryValue.RestrictAnonymous -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking network access: do not allow anonymous enumeration of SAM accounts and shares: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 86
        ControlObjective   = "Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -ErrorAction SilentlyContinue
                    return $registryValue.EveryoneIncludesAnonymous -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking network access: let everyone permissions apply to anonymous users: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 87
        ControlObjective = "Configure 'Network access: Named Pipes that can be accessed anonymously' (MS only) (Automated)"
        CheckFunction = {
            try {
                $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
                $registryValueName = "NullSessionPipes"
                $expectedValues = @("BROWSER")

                # Retrieve the current registry values
                $registryValues = (Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue).$registryValueName

                if ($registryValues) {
                    $configuredValues = $registryValues -split '\0' # Split the multi-string value
                    
                    # Check if configured values are either empty or only include 'BROWSER'
                    if ($configuredValues.Count -eq 0 -or ($configuredValues.Count -eq 1 -and $configuredValues[0] -eq "BROWSER")) {
                        Write-Host "The policy is correctly configured with either none or only 'BROWSER'."
                        return $true
                    } else {
                        Write-Host "The policy is incorrectly configured with additional named pipes: $($configuredValues -join ', ')"
                        return $false
                    }
                } else {
                    Write-Host "The policy is correctly configured with no named pipes."
                    return $true
                }
            } catch {
                Write-Host "Error checking Network access: Named Pipes that can be accessed anonymously: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 88
        ControlObjective   = "Configure 'Network access: Remotely accessible registry paths' is configured (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths" -Name "Machine" -ErrorAction SilentlyContinue
                    return $registryValue.Machine -ne $null
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking network access: remotely accessible registry paths: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber =89
        ControlObjective   = "Configure 'Network access: Remotely accessible registry paths and sub-paths' is configured (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" -Name "Machine" -ErrorAction SilentlyContinue
                    return $registryValue.Machine -ne $null
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking network access: remotely accessible registry paths and sub-paths: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 90
        ControlObjective   = "Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -ErrorAction SilentlyContinue
                    return $registryValue.RestrictNullSessAccess -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking network access: restrict anonymous access to named pipes and shares: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 91
        ControlObjective   = "Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow' (MS only) (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictremotesam" -ErrorAction SilentlyContinue
                    return $registryValue.restrictremotesam -eq "O:BAG:BAD:(A;;RC;;;BA)"
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking network access: restrict clients allowed to make remote calls to SAM: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 92
        ControlObjective = "Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None' (Automated)"
        CheckFunction = {
            try {
                $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
                $registryValueName = "NullSessionShares"

                # Retrieve the current registry values
                $registryValues = (Get-ItemProperty -Path $registryPath -Name $registryValueName -ErrorAction SilentlyContinue).$registryValueName

                # Check if the registry value is empty or not set
                if (-not $registryValues) {
                    Write-Host "The policy is correctly set to 'None' (i.e., no anonymous shares)."
                    return $true
                } else {
                    Write-Host "The policy is incorrectly configured with the following anonymous shares: $($registryValues -join ', ')"
                    return $false
                }
            } catch {
                Write-Host "Error checking Network access: Shares that can be accessed anonymously: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 93
        ControlObjective   = "Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "ForceGuest" -ErrorAction SilentlyContinue
                    return $registryValue.ForceGuest -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking network access: sharing and security model for local accounts: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 94
        ControlObjective = "Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'"
        CheckFunction = {
            try {
                # Define the expected value (0 means Disabled)
                $expectedValue = "0"
    
                # Use secedit to export the security settings to a temporary file
                $tempFile = [System.IO.Path]::GetTempFileName()
                secedit /export /areas SecurityPolicy /cfg $tempFile
    
                # Read the exported file and find the specific policy setting
                $content = Get-Content -Path $tempFile
                $policyLine = $content | Select-String -Pattern "LSAAnonymousNameLookup"
    
                # Clean up the temporary file
                Remove-Item -Path $tempFile
    
                # Check if the policy is set to the expected value
                if ($policyLine -ne $null) {
                    $configuredValue = $policyLine.Line -replace "LSAAnonymousNameLookup = ", ""
    
                    if ($configuredValue -eq $expectedValue) {
                        Write-Host "The policy is correctly set to 'Disabled' (0)."
                        return $true
                    } else {
                        Write-Host "The policy is set to: $configuredValue. Expected: $expectedValue ('Disabled')."
                        return $false
                    }
                } else {
                    Write-Host "The policy is not configured."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Network access: Allow anonymous SID/Name translation': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    



    @{
        SerialNumber = 95
        ControlObjective   = "Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -ErrorAction SilentlyContinue
                    return $registryValue.ShutdownWithoutLogon -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking shutdown: allow system to be shut down without having to log on: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 96
        ControlObjective   = "Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "FilterAdministratorToken" -ErrorAction SilentlyContinue
                    return $registryValue.FilterAdministratorToken -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking user account control: admin approval mode for the built-in administrator account: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 97
        ControlObjective   = "Ensure 'User Account Control: Behaviour of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue
                    return $registryValue.ConsentPromptBehaviorAdmin -eq 2
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking user account control: behaviour of the elevation prompt for administrators in admin approval mode: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 98
        ControlObjective   = "Ensure 'User Account Control: Behaviour of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -ErrorAction SilentlyContinue
                    return $registryValue.ConsentPromptBehaviorUser -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking user account control: behaviour of the elevation prompt for standard users: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 99
        ControlObjective   = "Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableInstallerDetection" -ErrorAction SilentlyContinue
                    return $registryValue.EnableInstallerDetection -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking user account control: detect application installations and prompt for elevation: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 100
        ControlObjective   = "Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSecureUIAPaths" -ErrorAction SilentlyContinue
                    return $registryValue.EnableSecureUIAPaths -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking user account control: only elevate UIAccess applications that are installed in secure locations: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 101
        ControlObjective   = "Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ErrorAction SilentlyContinue
                    return $registryValue.EnableLUA -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking user account control: run all administrators in admin approval mode: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 102
        ControlObjective   = "Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableVirtualization" -ErrorAction SilentlyContinue
                    return $registryValue.EnableVirtualization -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking user account control: virtualize file and registry write failures to per-user locations: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 103
        ControlObjective   = "Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -ErrorAction SilentlyContinue
                    return $registryValue.PromptOnSecureDesktop -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking user account control: switch to the secure desktop when prompting for elevation: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 104
        ControlObjective   = "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue
                    return $registryValue.EnableFirewall -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Windows Firewall: domain: firewall state: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 105
        ControlObjective   = "Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DefaultInboundAction" -ErrorAction SilentlyContinue
                    return $registryValue.DefaultInboundAction -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Windows Firewall: domain: inbound connections: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 106
        ControlObjective   = "Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DisableNotifications" -ErrorAction SilentlyContinue
                    return $registryValue.DisableNotifications -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Windows Firewall: domain: settings: display a notification: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 107
        ControlObjective   = "Ensure 'Audit Computer Account Management' is set to include 'Success' (DC only) (Automated)"
        CheckFunction      = {
            try {
                $auditSetting = (auditpol /get /subcategory:"Computer Account Management" | Select-String "Computer Account Management").Line
                return $auditSetting -match "Success"
            } catch {
                Write-Host "Error checking Audit Computer Account Management: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 108
        ControlObjective   = "Ensure 'Audit Other Account Management Events' is set to include 'Success' (DC only) (Automated)"
        CheckFunction      = {
            try {
                $auditSetting = (auditpol /get /subcategory:"Other Account Management Events" | Select-String "Other Account Management Events").Line
                return $auditSetting -match "Success"
            } catch {
                Write-Host "Error checking Audit Other Account Management Events: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 109
        ControlObjective   = "Ensure 'Audit Distribution Group Management' is set to include 'Success' (DC only) (Automated)"
        CheckFunction      = {
            try {
                $auditSetting = (auditpol /get /subcategory:"Distribution Group Management" | Select-String "Distribution Group Management").Line
                return $auditSetting -match "Success"
            } catch {
                Write-Host "Error checking Audit Distribution Group Management: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 110
        ControlObjective   = "Ensure 'Audit User Account Management' is set to 'Success and Failure' (Automated)"
        CheckFunction      = {
            try {
                $auditSetting = (auditpol /get /subcategory:"User Account Management" | Select-String "User Account Management").Line
                return $auditSetting -match "Success and Failure"
            } catch {
                Write-Host "Error checking Audit User Account Management: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 111
        ControlObjective   = "Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                $expectedValue = ""
                
                # Search for the 'SeTrustedCredManAccessPrivilege' setting
                $settingLine = $policyContent | Select-String "SeTrustedCredManAccessPrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim()
                    
                    # Check if the setting is empty, meaning no one is assigned
                    if ($assignedSIDs -eq $expectedValue) {
                        Write-Host "Compliance: 'Access Credential Manager as a trusted caller' is set to 'No One'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Access Credential Manager as a trusted caller' is assigned to: $assignedSIDs."
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeTrustedCredManAccessPrivilege' not found in the exported file."
                    return $true
                }
            } catch {
                Write-Host "Error checking 'Access Credential Manager as a trusted caller': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 112
        ControlObjective   = "Ensure 'Access this computer from the network' is set to 'Administrators Authenticated Users ENTERPRISE DOMAIN CONTROLLERS'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Expected values
                $expectedRights = @(
                    "*S-1-5-32-544",  # Administrators
                    "*S-1-5-11",      # Authenticated Users
                    "*S-1-5-9"        # Enterprise Domain Controllers
                )
                
                # Search for the 'SeNetworkLogonRight' setting
                $settingLine = $policyContent | Select-String "SeNetworkLogonRight"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim().Split(',')
    
                    # Check if any of the expected rights are present
                    $isCompliant = $expectedRights | ForEach-Object {
                        $assignedSIDs -contains $_
                    } | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
    
                    if ($isCompliant -gt 0) {
                        Write-Host "Compliance: 'Access this computer from the network' is set correctly."
                        return $true
                    } else {
                        Write-Host "Finding: 'Access this computer from the network' is not set to the expected values. Assigned SIDs: $($assignedSIDs -join ', ')"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeNetworkLogonRight' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Access this computer from the network': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 113
        ControlObjective   = "Ensure 'Access this computer from the network' is set to 'Administrators Authenticated Users' (MS only)"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Expected values
                $expectedRights = @(
                    "*S-1-5-32-544",  # Administrators
                    "*S-1-5-11"     # Authenticated Users
                )
                
                # Search for the 'SeNetworkLogonRight' setting
                $settingLine = $policyContent | Select-String "SeNetworkLogonRight"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim().Split(',')
    
                    # Check if any of the expected rights are present
                    $isCompliant = $expectedRights | ForEach-Object {
                        $assignedSIDs -contains $_
                    } | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count
    
                    if ($isCompliant -gt 0) {
                        Write-Host "Compliance: 'Access this computer from the network' is set correctly."
                        return $true
                    } else {
                        Write-Host "Finding: 'Access this computer from the network' is not set to the expected values. Assigned SIDs: $($assignedSIDs -join ', ')"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeNetworkLogonRight' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Access this computer from the network': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 114
        ControlObjective   = "Ensure 'Act as part of the operating system' is set to 'No One'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Expected value for 'No One'
                $expectedValue = ""
    
                # Search for the 'SeTcbPrivilege' setting
                $settingLine = $policyContent | Select-String "SeTcbPrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim()
                    
                    # Check if the setting is empty, meaning no one is assigned
                    if ($assignedSIDs -eq $expectedValue) {
                        Write-Host "Compliance: 'Act as part of the operating system' is set to 'No One'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Act as part of the operating system' is assigned to: $assignedSIDs."
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeTcbPrivilege' not found in the exported file."
                    return $true
                }
            } catch {
                Write-Host "Error checking 'Act as part of the operating system': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 115
        ControlObjective   = "Ensure 'Add workstations to domain' is set to a specific security group"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Expected SID for the Administrators group
                $expectedSID = "*S-1-5-32-544"  # Administrators group
    
                # Search for the 'SeMachineAccountPrivilege' setting
                $settingLine = $policyContent | Select-String "SeMachineAccountPrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim().Split(',')
    
                    # Check if only the expected SID is present
                    $isCompliant = $assignedSIDs.Count -eq 1 -and $assignedSIDs[0] -eq $expectedSID
    
                    if ($isCompliant) {
                        Write-Host "Compliance: 'Add workstations to domain' is set to 'Administrators'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Add workstations to domain' is not set to 'Administrators'. Assigned SIDs: $($assignedSIDs -join ', ')"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeMachineAccountPrivilege' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Add workstations to domain': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 116
        ControlObjective   = "Ensure 'Allow log on locally' is set to 'Administrators'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Expected SID for the Administrators group
                $expectedSID = "*S-1-5-32-544"  # Administrators group
    
                # Search for the 'SeDenyInteractiveLogonRight' setting
                $settingLine = $policyContent | Select-String "SeInteractiveLogonRight"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim().Split(',')
    
                    # Check if only the expected SID is present
                    $isCompliant = $assignedSIDs.Count -eq 1 -and $assignedSIDs[0] -eq $expectedSID
    
                    if ($isCompliant) {
                        Write-Host "Compliance: 'Allow log on locally' is set to 'Administrators'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Allow log on locally' is not set to 'Administrators'. Assigned SIDs: $($assignedSIDs -join ', ')"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeInteractiveLogonRight' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Allow log on locally': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 117
        ControlObjective   = "Ensure 'Allow log on through Remote Desktop Services' is set to specific security group"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Expected SIDs for the Administrators and Remote Desktop Users groups
                $expectedSIDs = @("*S-1-5-32-544", "*S-1-5-32-555")
                
                # Search for the 'SeRemoteInteractiveLogonRight' setting
                $settingLine = $policyContent | Select-String "SeRemoteInteractiveLogonRight"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim().Split(',')
                    
                    # Check if at least one of the expected SIDs is present
                    $isCompliant = $assignedSIDs | ForEach-Object { $expectedSIDs -contains $_ } | Where-Object { $_ -eq $true }

                    if ($isCompliant.Count -gt 0) {
                        Write-Host "Compliance: 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Allow log on through Remote Desktop Services' is not set to 'Administrators, Remote Desktop Users'. Assigned SIDs: $($assignedSIDs -join ', ')"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeRemoteInteractiveLogonRight' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Allow log on through Remote Desktop Services': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    
    @{
        SerialNumber = 118
        ControlObjective   = "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators Remote Desktop Users"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Expected SIDs for the Administrators and Remote Desktop Users groups
                $expectedSIDs = @("*S-1-5-32-544", "*S-1-5-32-555")
                
                # Search for the 'SeRemoteInteractiveLogonRight' setting
                $settingLine = $policyContent | Select-String "SeRemoteInteractiveLogonRight"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim().Split(',')
                    
                    # Check if at least one of the expected SIDs is present
                    $isCompliant = $assignedSIDs | ForEach-Object { $expectedSIDs -contains $_ } | Where-Object { $_ -eq $true }

                    if ($isCompliant.Count -gt 0) {
                        Write-Host "Compliance: 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Allow log on through Remote Desktop Services' is not set to 'Administrators, Remote Desktop Users'. Assigned SIDs: $($assignedSIDs -join ', ')"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeRemoteInteractiveLogonRight' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Allow log on through Remote Desktop Services': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 119
        ControlObjective   = "Ensure 'Change the system time' is set to 'Administrators LOCAL SERVICE'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Expected SIDs for the Administrators and LOCAL SERVICE groups
                $expectedSIDs = @("*S-1-5-19", "*S-1-5-32-544")  # S-1-5-32-544: Administrators, S-1-5-19: LOCAL SERVICE
                
                # Search for the 'SeSystemtimePrivilege' setting
                $settingLine = $policyContent | Select-String "SeSystemtimePrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim().Split(',')
                    
                    # Check if at least one of the expected SIDs is present
                    $isCompliant = $assignedSIDs | ForEach-Object { $expectedSIDs -contains $_ } | Where-Object { $_ -eq $true }

                    if ($isCompliant.Count -gt 0) {
                        Write-Host "Compliance: 'Change the system time' is set to 'Administrators, LOCAL SERVICE'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Change the system time' is not set to 'Administrators, LOCAL SERVICE'. Assigned SIDs: $($assignedSIDs -join ', ')"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeSystemtimePrivilege' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Change the system time': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 120
        ControlObjective   = "Ensure 'Change the time zone' is set to 'Administrators LOCAL SERVICE'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Expected SIDs for the Administrators and LOCAL SERVICE groups
                $expectedSIDs = @("*S-1-5-19", "*S-1-5-32-544")  # S-1-5-32-544: Administrators, S-1-5-19: LOCAL SERVICE
                
                # Search for the 'SeTimeZonePrivilege' setting
                $settingLine = $policyContent | Select-String "SeTimeZonePrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim().Split(',')
                    
                    # Check if at least one of the expected SIDs is present
                    $isCompliant = $assignedSIDs | ForEach-Object { $expectedSIDs -contains $_ } | Where-Object { $_ -eq $true }
    
                    if ($isCompliant.Count -gt 0) {
                        Write-Host "Compliance: 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Change the time zone' is not set to 'Administrators, LOCAL SERVICE'. Assigned SIDs: $($assignedSIDs -join ', ')"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeTimeZonePrivilege' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Change the time zone': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 121
        ControlObjective   = "Ensure 'Create a pagefile' is set to 'Administrators'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Expected SID for the Administrators group
                $expectedSID = "*S-1-5-32-544"  # Administrators group
                
                # Search for the 'SeCreatePagefilePrivilege' setting
                $settingLine = $policyContent | Select-String "SeCreatePagefilePrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim().Split(',')
                    
                    # Check if only the expected SID is present
                    $isCompliant = $assignedSIDs.Count -eq 1 -and $assignedSIDs[0] -eq $expectedSID
                    
                    if ($isCompliant) {
                        Write-Host "Compliance: 'Create a pagefile' is set to 'Administrators'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Create a pagefile' is not set to 'Administrators'. Assigned SIDs: $($assignedSIDs -join ', ')"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeCreatePagefilePrivilege' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Create a pagefile': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 122
        ControlObjective   = "Ensure 'Create global objects' is set to 'Administrators LOCAL SERVICE NETWORK SERVICE SERVICE'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Expected SIDs for the required groups
                $expectedSIDs = @(
                    "*S-1-5-32-544",  # Administrators
                    "*S-1-5-6",       # SERVICE
                    "*S-1-5-19",      # LOCAL SERVICE
                    "*S-1-5-20"       # NETWORK SERVICE
                )
                
                # Search for the 'SeCreateGlobalPrivilege' setting
                $settingLine = $policyContent | Select-String "SeCreateGlobalPrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim().Split(',')
                    
                    # Check if at least one of the expected SIDs is present
                    $isCompliant = $false
                    foreach ($expectedSID in $expectedSIDs) {
                        if ($assignedSIDs -contains $expectedSID) {
                            $isCompliant = $true
                            break
                        }
                    }
                    
                    if ($isCompliant) {
                        Write-Host "Compliance: 'Create global objects' is set to include one or more of the required groups."
                        return $true
                    } else {
                        Write-Host "Finding: 'Create global objects' does not include any of the required groups. Assigned SIDs: $($assignedSIDs -join ', ')"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeCreateGlobalPrivilege' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Create global objects': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 123
        ControlObjective   = "Ensure 'Force shutdown from a remote system' is set to 'Administrators'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Expected SID for the Administrators group
                $expectedSID = "*S-1-5-32-544"  # Administrators group
                
                # Search for the 'SeRemoteShutdownPrivilege' setting
                $settingLine = $policyContent | Select-String "SeRemoteShutdownPrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim().Split(',')
                    
                    # Check if the expected SID is the only one present
                    $isCompliant = $assignedSIDs.Count -eq 1 -and $assignedSIDs[0] -eq $expectedSID
                    
                    if ($isCompliant) {
                        Write-Host "Compliance: 'Force shutdown from a remote system' is set to 'Administrators'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Force shutdown from a remote system' is not set to 'Administrators'. Assigned SIDs: $($assignedSIDs -join ', ')"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeRemoteShutdownPrivilege' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Force shutdown from a remote system': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 124
        ControlObjective   = "Ensure 'Generate security audits' is set to 'LOCAL SERVICE NETWORK SERVICE'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Expected SIDs for LOCAL SERVICE and NETWORK SERVICE groups
                $expectedSIDs = @("*S-1-5-19", "*S-1-5-20")  # S-1-5-19: LOCAL SERVICE, S-1-5-20: NETWORK SERVICE
                
                # Search for the 'SeAuditPrivilege' setting
                $settingLine = $policyContent | Select-String "SeAuditPrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim().Split(',')
                    
                    # Check if at least one of the expected SIDs is present
                    $isCompliant = $assignedSIDs | ForEach-Object { $expectedSIDs -contains $_ } | Where-Object { $_ -eq $true }
    
                    if ($isCompliant.Count -gt 0) {
                        Write-Host "Compliance: 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Generate security audits' is not set to 'LOCAL SERVICE, NETWORK SERVICE'. Assigned SIDs: $($assignedSIDs -join ', ')"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeAuditPrivilege' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Generate security audits': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 125
        ControlObjective   = "Ensure 'Impersonate a client after authentication' is set to 'Administrators LOCAL SERVICE NETWORK SERVICE SERVICE' (DC only)"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Expected SIDs for Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE groups
                $expectedSIDs = @("*S-1-5-32-544", "*S-1-5-19", "*S-1-5-20", "*S-1-5-6")  # S-1-5-32-544: Administrators, S-1-5-19: LOCAL SERVICE, S-1-5-20: NETWORK SERVICE, S-1-5-6: SERVICE
                
                # Search for the 'SeImpersonatePrivilege' setting
                $settingLine = $policyContent | Select-String "SeImpersonatePrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim().Split(',')
                    
                    # Check if at least one of the expected SIDs is present
                    $isCompliant = $assignedSIDs | ForEach-Object { $expectedSIDs -contains $_ } | Where-Object { $_ -eq $true }
    
                    if ($isCompliant.Count -gt 0) {
                        Write-Host "Compliance: 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Impersonate a client after authentication' is not set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'. Assigned SIDs: $($assignedSIDs -join ', ')"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeImpersonatePrivilege' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Impersonate a client after authentication': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 126
        ControlObjective   = "Ensure 'Impersonate a client after authentication' is set to 'Administrators LOCAL SERVICE NETWORK SERVICE SERVICE' and (when the Web Server (IIS) Role with Web Services Role Service is installed) 'IIS_IUSRS' (MS only)"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Expected SIDs for Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE, and IIS_IUSRS
                $expectedSIDs = @("*S-1-5-32-544", "*S-1-5-19", "*S-1-5-20", "*S-1-5-6")  # S-1-5-32-544: Administrators, S-1-5-19: LOCAL SERVICE, S-1-5-20: NETWORK SERVICE, S-1-5-6: SERVICE
                $iisIusrsSID = "*S-1-5-80-0"  # Replace with actual SID for IIS_IUSRS
                
                # Search for the 'SeImpersonatePrivilege' setting
                $settingLine = $policyContent | Select-String "SeImpersonatePrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim().Split(',')
                    
                    # Check if at least one of the expected SIDs is present
                    $isCompliant = $assignedSIDs | ForEach-Object { $expectedSIDs -contains $_ -or $_ -eq $iisIusrsSID } | Where-Object { $_ -eq $true }
    
                    # Additional check if IIS_IUSRS should be included
                    $iisInstalled = Get-WindowsFeature -Name Web-Server | Select-Object -ExpandProperty Installed
                    
                    if ($iisInstalled -and $assignedSIDs -contains $iisIusrsSID) {
                        $isCompliant = $true
                    }
    
                    if ($isCompliant.Count -gt 0) {
                        Write-Host "Compliance: 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' and (when IIS is installed) 'IIS_IUSRS'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Impersonate a client after authentication' is not set correctly. Assigned SIDs: $($assignedSIDs -join ', ')"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeImpersonatePrivilege' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Impersonate a client after authentication': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 127
        ControlObjective   = "Ensure 'Increase scheduling priority' is set to 'Administrators Window Manager\Window Manager Group'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Expected SIDs for Administrators and Window Manager Group
                $expectedSIDs = @("*S-1-5-32-544")  # S-1-5-32-544: Administrators, S-1-5-90-0: Window Manager Group
                
                # Search for the 'SeIncreaseBasePriorityPrivilege' setting
                $settingLine = $policyContent | Select-String "SeIncreaseBasePriorityPrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim().Split(',')
                    
                    # Check if all expected SIDs are present
                    $isCompliant = $expectedSIDs | ForEach-Object { $assignedSIDs -contains $_ } | Where-Object { $_ -eq $true }
    
                    if ($isCompliant.Count -eq $expectedSIDs.Count) {
                        Write-Host "Compliance: 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Increase scheduling priority' is not set to 'Administrators, Window Manager\Window Manager Group'. Assigned SIDs: $($assignedSIDs -join ', ')"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeIncreaseBasePriorityPrivilege' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Increase scheduling priority': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    }

    @{
        SerialNumber = 128
        ControlObjective   = "Ensure 'Load and unload device drivers' is set to 'Administrators'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Expected SID for Administrators group
                $expectedSID = "*S-1-5-32-544"  # S-1-5-32-544: Administrators
                
                # Search for the 'SeLoadDriverPrivilege' setting
                $settingLine = $policyContent | Select-String "SeLoadDriverPrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim().Split(',')
                    
                    # Check if the expected SID is present
                    $isCompliant = $assignedSIDs -contains $expectedSID
    
                    if ($isCompliant) {
                        Write-Host "Compliance: 'Load and unload device drivers' is set to 'Administrators'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Load and unload device drivers' is not set to 'Administrators'. Assigned SIDs: $($assignedSIDs -join ', ')"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeLoadDriverPrivilege' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Load and unload device drivers': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 129
        ControlObjective   = "Ensure 'Lock pages in memory' is set to 'No One'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Search for the 'SeLockMemoryPrivilege' setting
                $settingLine = $policyContent | Select-String "SeLockMemoryPrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim()
                    
                    # Check if the setting is blank (indicating 'No One')
                    if ([string]::IsNullOrWhiteSpace($assignedSIDs)) {
                        Write-Host "Compliance: 'Lock pages in memory' is set to 'No One'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Lock pages in memory' is not set to 'No One'. Assigned SIDs: $assignedSIDs"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeLockMemoryPrivilege' not found in the exported file."
                    return $true
                }
            } catch {
                Write-Host "Error checking 'Lock pages in memory': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 130
        ControlObjective   = "Ensure 'Manage auditing and security log' is set to 'Administrators'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Search for the 'SeSecurityPrivilege' setting
                $settingLine = $policyContent | Select-String "SeSecurityPrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim()
                    
                    # Expected SID for Administrators group
                    $expectedSID = "*S-1-5-32-544"
                    
                    # Check if only Administrators group is assigned
                    if ($assignedSIDs -eq $expectedSID) {
                        Write-Host "Compliance: 'Manage auditing and security log' is set to 'Administrators'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Manage auditing and security log' is not set to 'Administrators'. Assigned SIDs: $assignedSIDs"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeSecurityPrivilege' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Manage auditing and security log': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 131
        ControlObjective   = "Ensure 'Modify an object label' is set to 'No One'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Search for the 'SeRelabelPrivilege' setting
                $settingLine = $policyContent | Select-String "SeRelabelPrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim()
                    
                    # Check if no SID is assigned
                    if ([string]::IsNullOrWhiteSpace($assignedSIDs)) {
                        Write-Host "Compliance: 'Modify an object label' is set to 'No One'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Modify an object label' is assigned to: $assignedSIDs"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeRelabelPrivilege' not found in the exported file."
                    return $true
                }
            } catch {
                Write-Host "Error checking 'Modify an object label': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 132
        ControlObjective   = "Ensure 'Modify firmware environment values' is set to 'Administrators'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Search for the 'SeSystemEnvironmentPrivilege' setting
                $settingLine = $policyContent | Select-String "SeSystemEnvironmentPrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim()
                    
                    # SID for 'Administrators' is S-1-5-32-544
                    $adminSID = "*S-1-5-32-544"
                    
                    # Check if the 'Administrators' SID is present
                    if ($assignedSIDs -eq $adminSID) {
                        Write-Host "Compliance: 'Modify firmware environment values' is correctly set to 'Administrators'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Modify firmware environment values' is not correctly set. Currently assigned to: $assignedSIDs"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeSystemEnvironmentPrivilege' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Modify firmware environment values': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 133
        ControlObjective   = "Ensure 'Perform volume maintenance tasks' is set to 'Administrators'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Search for the 'SeManageVolumePrivilege' setting
                $settingLine = $policyContent | Select-String "SeManageVolumePrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim()
                    
                    # SID for 'Administrators' is S-1-5-32-544
                    $adminSID = "*S-1-5-32-544"
                    
                    # Check if the 'Administrators' SID is present
                    if ($assignedSIDs -eq $adminSID) {
                        Write-Host "Compliance: 'Perform volume maintenance tasks' is correctly set to 'Administrators'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Perform volume maintenance tasks' is not correctly set. Currently assigned to: $assignedSIDs"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeManageVolumePrivilege' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Perform volume maintenance tasks': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 134
        ControlObjective   = "Ensure 'Profile single process' is set to 'Administrators'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Search for the 'SeProfileSingleProcessPrivilege' setting
                $settingLine = $policyContent | Select-String "SeProfileSingleProcessPrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim()
                    
                    # SID for 'Administrators' is S-1-5-32-544
                    $adminSID = "*S-1-5-32-544"
                    
                    # Check if the 'Administrators' SID is present
                    if ($assignedSIDs -eq $adminSID) {
                        Write-Host "Compliance: 'Profile single process' is correctly set to 'Administrators'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Profile single process' is not correctly set. Currently assigned to: $assignedSIDs"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeProfileSingleProcessPrivilege' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Profile single process': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 135
        ControlObjective   = "Ensure 'Restore files and directories' is set to 'Administrators'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Search for the 'SeRestorePrivilege' setting
                $settingLine = $policyContent | Select-String "SeRestorePrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim()
                    
                    # SID for 'Administrators' is S-1-5-32-544
                    $adminSID = "*S-1-5-32-544"
                    
                    # Check if the 'Administrators' SID is present
                    if ($assignedSIDs -eq $adminSID) {
                        Write-Host "Compliance: 'Restore files and directories' is correctly set to 'Administrators'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Restore files and directories' is not correctly set. Currently assigned to: $assignedSIDs"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeRestorePrivilege' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Restore files and directories': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 136
        ControlObjective   = "Ensure 'Shut down the system' is set to 'Administrators'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Search for the 'SeShutdownPrivilege' setting
                $settingLine = $policyContent | Select-String "SeShutdownPrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim()
                    
                    # SID for 'Administrators' is S-1-5-32-544
                    $adminSID = "*S-1-5-32-544"
                    
                    # Check if the 'Administrators' SID is present
                    if ($assignedSIDs -eq $adminSID) {
                        Write-Host "Compliance: 'Shut down the system' is correctly set to 'Administrators'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Shut down the system' is not correctly set. Currently assigned to: $assignedSIDs"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeShutdownPrivilege' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Shut down the system': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    

    @{
        SerialNumber = 137
        ControlObjective   = "Ensure 'Take ownership of files or other objects' is set to 'Administrators'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Search for the 'SeTakeOwnershipPrivilege' setting
                $settingLine = $policyContent | Select-String "SeTakeOwnershipPrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim()
                    
                    # SID for 'Administrators' is S-1-5-32-544
                    $adminSID = "*S-1-5-32-544"
                    
                    # Check if the 'Administrators' SID is present
                    if ($assignedSIDs -eq $adminSID) {
                        Write-Host "Compliance: 'Take ownership of files or other objects' is correctly set to 'Administrators'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Take ownership of files or other objects' is not correctly set. Currently assigned to: $assignedSIDs"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeTakeOwnershipPrivilege' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Take ownership of files or other objects': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 138
        ControlObjective   = "Ensure 'Back up files and directories' is set to 'Administrators and Backup Operators'"
        CheckFunction      = {
            try {
                # Export the User Rights Assignment settings
                $exportFilePath = "$env:TEMP\secpol_export.txt"
                secedit /export /areas User_Rights /cfg $exportFilePath | Out-Null
                
                # Read the exported settings
                $policyContent = Get-Content $exportFilePath
                
                # Search for the 'SeBackupPrivilege' setting
                $settingLine = $policyContent | Select-String "SeBackupPrivilege"
                
                if ($settingLine) {
                    $assignedSIDs = ($settingLine -split '=')[1].Trim()
                    
                    # SIDs for 'Administrators' and 'Backup Operators'
                    $adminSID = "S-1-5-32-544"
                    $backupOpsSID = "S-1-5-32-551"
                    
                    # Check if both SIDs are present
                    if ($assignedSIDs -match "$adminSID" -and $assignedSIDs -match "$backupOpsSID") {
                        Write-Host "Compliance: 'Back up files and directories' is correctly set to 'Administrators and Backup Operators'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Back up files and directories' is not correctly set. Currently assigned to: $assignedSIDs"
                        return $false
                    }
                } else {
                    Write-Host "Setting 'SeBackupPrivilege' not found in the exported file."
                    return $false
                }
            } catch {
                Write-Host "Error checking 'Back up files and directories': $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 139
        ControlObjective   = "Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockUserFromShowingAccountDetailsOnSignin" -ErrorAction SilentlyContinue
                    if ($null -ne $registryValue) {
                        return $registryValue.BlockUserFromShowingAccountDetailsOnSignin -eq 1
                    } else {
                        return $false
                    }
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Block user from showing account details on sign-in: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 140
        ControlObjective   = "Ensure 'Do not display network selection UI' is set to 'Enabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -ErrorAction SilentlyContinue
                    if ($null -ne $registryValue) {
                        return $registryValue.DontDisplayNetworkSelectionUI -eq 1
                    } else {
                        return $false
                    }
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Do not display network selection UI: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 141
        ControlObjective   = "Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled' (MS only) (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnumerateLocalUsers" -ErrorAction SilentlyContinue
                    if ($null -ne $registryValue) {
                        return $registryValue.EnumerateLocalUsers -eq 0
                    } else {
                        return $false
                    }
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Enumerate local users on domain-joined computers: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 142
        ControlObjective   = "Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontEnumerateConnectedUsers" -ErrorAction SilentlyContinue
                    if ($null -ne $registryValue) {
                        return $registryValue.DontEnumerateConnectedUsers -eq 1
                    } else {
                        return $false
                    }
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Do not enumerate connected users on domain-joined computers: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 143
        ControlObjective   = "Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon" -ErrorAction SilentlyContinue
                    if ($null -ne $registryValue) {
                        return $registryValue.AllowDomainPINLogon -eq 0
                    } else {
                        return $false
                    }
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Turn on convenience PIN sign-in: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 144
        ControlObjective   = "Ensure 'Turn off picture password sign-in' is set to 'Enabled' (Automated)"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "BlockDomainPicturePassword" -ErrorAction SilentlyContinue
                    if ($null -ne $registryValue) {
                        return $registryValue.BlockDomainPicturePassword -eq 1
                    } else {
                        return $false
                    }
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Turn off picture password sign-in: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 145
        ControlObjective   = "Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'"
        CheckFunction      = {
            try {
                if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System") {
                    $registryValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DisableLockScreenAppNotifications" -ErrorAction SilentlyContinue
                    if ($null -ne $registryValue) {
                        return $registryValue.DisableLockScreenAppNotifications -eq 1
                    } else {
                        return $false
                    }
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Turn off app notifications on the lock screen: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 146
        ControlObjective   = "Ensure 'Security: Control Event Log behaviour when the log file reaches its maximum size' is set to 'Disabled'"
        CheckFunction      = {
            try {
                # Registry path for the policy setting
                $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
                $regName = "Retention"
                
                # Check if the registry key exists and read its value
                if (Test-Path $regPath) {
                    $regValue = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
                    if ($regValue -ne $null -and $regValue.Retention -eq 0) {
                        Write-Host "Compliance: 'Control Event Log behaviour when the log file reaches its maximum size' is set to 'Disabled'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Control Event Log behaviour when the log file reaches its maximum size' is not set to 'Disabled'."
                        return $false
                    }
                } else {
                    Write-Host "Registry path for Event Log Security settings does not exist."
                    return $false
                }
            } catch {
                Write-Host "Error checking Event Log behavior setting: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 147
        ControlObjective   = "Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32768 or greater'"
        CheckFunction      = {
            try {
                # Registry path for the maximum log file size setting
                $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application"
                $regName = "MaxSize"
                
                # Check if the registry key exists and read its value
                if (Test-Path $regPath) {
                    $regValue = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
                    if ($regValue -ne $null -and $regValue.MaxSize -ge 32768) {
                        Write-Host "Compliance: 'Specify the maximum log file size (KB)' is set to '32,768 or greater'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Specify the maximum log file size (KB)' is not set to '32,768 or greater'."
                        return $false
                    }
                } else {
                    Write-Host "Registry path for Event Log Application settings does not exist."
                    return $false
                }
            } catch {
                Write-Host "Error checking maximum log file size setting: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 148
        ControlObjective   = "Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196608 or greater'"
        CheckFunction      = {
            try {
                # Registry path for the maximum log file size setting
                $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"
                $regName = "MaxSize"
                
                # Check if the registry key exists and read its value
                if (Test-Path $regPath) {
                    $regValue = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
                    if ($regValue -ne $null -and $regValue.MaxSize -ge 196608) {
                        Write-Host "Compliance: 'Specify the maximum log file size (KB)' is set to '196,608 or greater'."
                        return $true
                    } else {
                        Write-Host "Finding: 'Specify the maximum log file size (KB)' is not set to '196,608 or greater'."
                        return $false
                    }
                } else {
                    Write-Host "Registry path for Event Log Security settings does not exist."
                    return $false
                }
            } catch {
                Write-Host "Error checking maximum log file size setting: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 149
        ControlObjective = "Ensure 'Always prompt for password upon connection' is set to 'Enabled'"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "fPromptForPassword" -ErrorAction SilentlyContinue
                    return $value.fPromptForPassword -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Always prompt for password upon connection: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 150
        ControlObjective = "Ensure 'Require secure RPC communication' is set to 'Enabled'"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "fEncryptRPCTraffic" -ErrorAction SilentlyContinue
                    return $value.fEncryptRPCTraffic -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Require secure RPC communication: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 151
        ControlObjective = "Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "SecurityLayer" -ErrorAction SilentlyContinue
                    return $value.SecurityLayer -eq 2
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Require use of specific security layer for remote (RDP) connections: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 152
        ControlObjective = "Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "UserAuthentication" -ErrorAction SilentlyContinue
                    return $value.UserAuthentication -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Require user authentication for remote connections by using Network Level Authentication: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 153
        ControlObjective = "Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue
                    return $value.MinEncryptionLevel -eq 3
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Set client connection encryption level: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 154
        ControlObjective = "Ensure 'Setup: Control Event Log behaviour when the log file reaches its maximum size' is set to 'Disabled'"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "Retention" -ErrorAction SilentlyContinue
                    return $value.Retention -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Setup: Control Event Log behaviour when the log file reaches its maximum size: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 155
        ControlObjective = "Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32768 or greater'"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "MaxSize" -ErrorAction SilentlyContinue
                    return $value.MaxSize -ge 32768
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Setup: Specify the maximum log file size (KB): $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 156
        ControlObjective = "Ensure 'System: Control Event Log behaviour when the log file reaches its maximum size' is set to 'Disabled'"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "Retention" -ErrorAction SilentlyContinue
                    return $value.Retention -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking System: Control Event Log behaviour when the log file reaches its maximum size: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 157
        ControlObjective = "Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32768 or greater'"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "MaxSize" -ErrorAction SilentlyContinue
                    return $value.MaxSize -ge 32768
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking System: Specify the maximum log file size (KB): $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 158
        ControlObjective = "Ensure 'Always install with elevated privileges' is set to 'Disabled'"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
                    return $value.AlwaysInstallElevated -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Always install with elevated privileges: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 159
        ControlObjective = "Ensure 'Allow user control over installs' is set to 'Disabled'"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "EnableUserControl" -ErrorAction SilentlyContinue
                    return $value.EnableUserControl -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Allow user control over installs: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 160
        ControlObjective = "Ensure 'Allow Basic authentication' is set to 'Disabled'"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "AllowBasic" -ErrorAction SilentlyContinue
                    return $value.AllowBasic -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Allow Basic authentication: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 161
        ControlObjective = "Ensure 'Disallow Digest authentication' is set to 'Enabled'"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "AllowDigest" -ErrorAction SilentlyContinue
                    return $value.AllowDigest -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Disallow Digest authentication: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 162
        ControlObjective = "Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "AllowUnencryptedTraffic" -ErrorAction SilentlyContinue
                    return $value.AllowUnencryptedTraffic -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Allow unencrypted traffic: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 163
        ControlObjective = "Ensure 'Allow Basic authentication' is set to 'Disabled'"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "AllowBasic" -ErrorAction SilentlyContinue
                    return $value.AllowBasic -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Allow Basic authentication: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 164
        ControlObjective = "Ensure 'Allow unencrypted traffic' is set to 'Disabled'"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "AllowUnencryptedTraffic" -ErrorAction SilentlyContinue
                    return $value.AllowUnencryptedTraffic -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Allow unencrypted traffic: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 165
        ControlObjective = "Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "DisableRunAs" -ErrorAction SilentlyContinue
                    return $value.DisableRunAs -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Disallow WinRM from storing RunAs credentials: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 166
        ControlObjective = "Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "fAllowUnsolicited" -ErrorAction SilentlyContinue
                    return $value.fAllowUnsolicited -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Configure Offer Remote Assistance: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    
    @{
        SerialNumber = 167
        ControlObjective = "Ensure 'Do not delete temp folders upon exit' is set to 'Disabled' (Automated)"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "DeleteTempDirsOnExit" -ErrorAction SilentlyContinue
                    return $value.DeleteTempDirsOnExit -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Do not delete temp folders upon exit: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 168
        ControlObjective = "Ensure 'Do not use temporary folders per session' is set to 'Disabled' (Automated)"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "PerSessionTempDir" -ErrorAction SilentlyContinue
                    return $value.PerSessionTempDir -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Do not use temporary folders per session: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 169
        ControlObjective = "Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass' (Automated)"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "EnableSmartScreen" -ErrorAction SilentlyContinue
                    return $value.EnableSmartScreen -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "The policy is not set correctly."
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    
    @{
        SerialNumber = 170
        ControlObjective = "Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled' (Automated)"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
                    return $value.EnableScriptBlockLogging -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Turn on PowerShell Script Block Logging: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 171
        ControlObjective = "Ensure 'Turn on PowerShell Transcription' is set to 'Enabled' (Automated)"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "EnableTranscripting" -ErrorAction SilentlyContinue
                    return $value.EnableTranscripting -eq 1
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Turn on PowerShell Transcription: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 172
        ControlObjective = "Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled' (Automated)"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
                if (Test-Path $key) {
                    $value = Get-ItemProperty -Path $key -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
                    return $value.NoAutoRebootWithLoggedOnUsers -eq 0
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking No auto-restart with logged on users for scheduled automatic updates installations: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },

    @{
        SerialNumber = 173
        ControlObjective = "Ensure 'Select when Preview Builds and Feature Updates are received' is set to 'Enabled: 180 or more days' (Automated)"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
                if (Test-Path $key) {
                    $value1 = Get-ItemProperty -Path $key -Name "DeferFeatureUpdates" -ErrorAction SilentlyContinue
                    $value2 = Get-ItemProperty -Path $key -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
                    return ($value1.DeferFeatureUpdates -eq 1) -and ($value2.DeferFeatureUpdatesPeriodInDays -ge 180)
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Select when Preview Builds and Feature Updates are received: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    },
    @{
        SerialNumber = 174
        ControlObjective = "Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days' (Automated)"
        CheckFunction = {
            try {
                $key = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
                if (Test-Path $key) {
                    $value1 = Get-ItemProperty -Path $key -Name "DeferQualityUpdates" -ErrorAction SilentlyContinue
                    $value2 = Get-ItemProperty -Path $key -Name "DeferQualityUpdatesPeriodInDays" -ErrorAction SilentlyContinue
                    return ($value1.DeferQualityUpdates -eq 1) -and ($value2.DeferQualityUpdatesPeriodInDays -eq 0)
                } else {
                    return $false
                }
            } catch {
                Write-Host "Error checking Select when Quality Updates are received: $_"
                return $false
            }
        }
        ManualCheck = $false
        Applicable = $true
    }
)

# Write system details
Write-SystemDetails

# Perform audit checks
foreach ($auditCheck in $auditChecks) {
    Check-ComplianceStatus -serialNumber $auditCheck.SerialNumber -controlObjective $auditCheck.ControlObjective -checkFunction $auditCheck.CheckFunction -manualCheck $auditCheck.ManualCheck -applicable ([bool]$auditCheck.Applicable)
}
 
