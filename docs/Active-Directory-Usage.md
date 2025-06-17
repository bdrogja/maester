# Active Directory Testing with Maester

Maester now supports comprehensive Active Directory (On-Premises) security testing alongside its existing Microsoft 365 capabilities. This guide covers everything you need to know about using Maester for AD security assessments.

## Overview

The Active Directory integration provides:
- Security configuration assessments
- Password policy validation
- Privileged group auditing
- Domain controller health checks
- Service account security reviews
- Compliance reporting (CIS benchmarks)

## Prerequisites

### 1. PowerShell Modules
- **Active Directory PowerShell Module** (RSAT)
- **Maester Module** (includes AD support)

### 2. Permissions
Your user account needs appropriate permissions to read AD configuration:
- Domain Users (minimum for basic tests)
- Domain Admins or Read-Only Domain Admin (for comprehensive tests)

### 3. Network Access
- LDAP connectivity (port 389) to domain controllers
- RPC connectivity for some advanced queries

## Installation

### Install RSAT (Windows)
```powershell
# Windows 10/11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

# Windows Server
Add-WindowsFeature RSAT-AD-PowerShell
```

### Install Maester
```powershell
Install-Module -Name Maester -Scope CurrentUser
```

## Quick Start

### 1. Basic AD Connection
```powershell
# Import Maester
Import-Module Maester

# Connect to current domain
Connect-MtActiveDirectory

# Run AD tests
Invoke-Maester -IncludeActiveDirectory
```

### 2. Advanced Connection Options
```powershell
# Connect to specific domain controller
Connect-MtActiveDirectory -DomainController "DC01.contoso.com"

# Connect with alternate credentials
$cred = Get-Credential
Connect-MtActiveDirectory -Credential $cred

# Connect to specific domain
Connect-MtActiveDirectory -DomainName "child.contoso.com"

# Skip connection test (for offline scenarios)
Connect-MtActiveDirectory -SkipConnectionTest
```

## Running Tests

### Test Categories

#### Security-Focused Tests
```powershell
# Run only security tests
Invoke-Maester -Tag "AD", "Security"

# Run CIS benchmark tests
Invoke-Maester -Tag "AD", "CIS"
```

#### Specific Test Areas
```powershell
# Password policy tests only
Invoke-Maester -Tag "AD", "PasswordPolicy"

# Privileged group tests
Invoke-Maester -Tag "AD", "PrivilegedGroups"

# Domain controller tests
Invoke-Maester -Tag "AD", "DomainControllers"
```

### Output Options
```powershell
# Generate HTML report
Invoke-Maester -IncludeActiveDirectory -OutputFolder "./ad-reports"

# Export to CSV for analysis
Invoke-Maester -IncludeActiveDirectory -ExportCsv -OutputFolder "./reports"

# Send email report
Invoke-Maester -IncludeActiveDirectory -MailRecipient "security@company.com"
```

## Test Categories

### Password Policy Tests (AD.PP*)
- **AD.PP01**: Minimum password length (≥14 characters)
- **AD.PP02**: Password complexity requirements
- **AD.PP03**: Password history (≥24 passwords)
- **AD.PP04**: Maximum password age (≤60 days)
- **AD.PP05**: Minimum password age (≥1 day)
- **AD.PP06**: Account lockout threshold (≤10 attempts)
- **AD.PP07**: Account lockout duration (≥30 minutes)

### Privileged Groups Tests (AD.PG*)
- **AD.PG01**: Domain Admins group size
- **AD.PG02**: Enterprise Admins group monitoring
- **AD.PG03**: Schema Admins group restrictions
- **AD.PG04**: Built-in Administrator account status
- **AD.PG05**: Service account privileges
- **AD.PG06**: Dormant privileged accounts

### Domain Controllers Tests (AD.DC*)
- **AD.DC01**: Domain controller patch levels
- **AD.DC02**: FSMO role distribution
- **AD.DC03**: Global Catalog configuration
- **AD.DC04**: Time synchronization
- **AD.DC05**: DNS configuration
- **AD.DC06**: Replication health

### Service Accounts Tests (AD.SA*)
- **AD.SA01**: Service account password policies
- **AD.SA02**: Kerberos delegation settings
- **AD.SA03**: Service Principal Name (SPN) configuration
- **AD.SA04**: Managed Service Account usage

## Advanced Usage

### Custom Test Configurations
```powershell
# Create custom test configuration
$testConfig = @{
    MinPasswordLength = 16
    MaxPrivilegedUsers = 5
    RequiredSecurityGroups = @("Protected Users")
}

# Run with custom settings
Invoke-Maester -IncludeActiveDirectory -TestConfiguration $testConfig
```

### Automated Reporting
```powershell
# Daily automated security scan
$scriptBlock = {
    Connect-MtActiveDirectory
    Invoke-Maester -IncludeActiveDirectory -ExportCsv -OutputFolder "C:\Reports\Daily"
}

# Schedule with Task Scheduler or as a service
```

### Integration with CI/CD
```powershell
# Example for Azure DevOps or GitHub Actions
try {
    Connect-MtActiveDirectory -SkipConnectionTest
    $results = Invoke-Maester -IncludeActiveDirectory -PassThru
    
    if ($results.FailedCount -gt 0) {
        Write-Warning "Security tests failed: $($results.FailedCount) issues found"
        exit 1
    }
} catch {
    Write-Error "AD security test failed: $_"
    exit 1
}
```

## Troubleshooting

### Common Issues

#### Connection Problems
```powershell
# Test AD connectivity manually
Test-NetConnection -ComputerName "domain.com" -Port 389

# Check if AD module is loaded
Get-Module ActiveDirectory -ListAvailable

# Verify domain trust
Test-ComputerSecureChannel -Verbose
```

#### Permission Issues
```powershell
# Check current user permissions
whoami /groups
Get-ADUser $env:USERNAME -Properties MemberOf
```

#### Cross-Platform Compatibility
```powershell
# For non-Windows platforms
if ($PSVersionTable.Platform -ne 'Win32NT') {
    Write-Warning "Some AD tests require Windows PowerShell"
    # Use alternative connection methods
}
```

### Logging and Debugging
```powershell
# Enable verbose logging
Invoke-Maester -IncludeActiveDirectory -Verbosity Detailed

# Check Maester session
Get-MtSession | Select-Object -ExpandProperty ADConnection
```

## Best Practices

### Security Recommendations
1. **Use Read-Only Accounts**: Create dedicated service accounts with minimal permissions
2. **Regular Scanning**: Schedule automated security assessments
3. **Baseline Management**: Establish security baselines and track deviations
4. **Incident Response**: Integrate failed tests into security monitoring

### Performance Optimization
1. **Target Specific Tests**: Use tags to run only necessary tests
2. **Cache Management**: Use `Clear-MtAdCache` between test runs
3. **Batch Operations**: Run comprehensive tests during maintenance windows

### Compliance Integration
1. **CIS Benchmarks**: Use CIS-tagged tests for compliance reporting
2. **Custom Standards**: Extend tests for organization-specific requirements
3. **Audit Trails**: Maintain test result history for compliance evidence

## Example Workflows

### Weekly Security Assessment
```powershell
# Full weekly security scan
Connect-MtActiveDirectory
$results = Invoke-Maester -IncludeActiveDirectory -OutputFolder ".\WeeklyReports\$(Get-Date -Format 'yyyy-MM-dd')"

# Email results to security team
if ($results.FailedCount -gt 0) {
    Send-MtMail -To "security-team@company.com" -Subject "AD Security Issues Found" -HtmlReport $results.HtmlReportPath
}
```

### Pre-Change Validation
```powershell
# Before making AD changes
$preChangeResults = Invoke-Maester -IncludeActiveDirectory -PassThru
Export-Clixml -InputObject $preChangeResults -Path ".\PreChange-Baseline.xml"

# After changes
$postChangeResults = Invoke-Maester -IncludeActiveDirectory -PassThru
Compare-MtTestResult -ReferenceResults $preChangeResults -DifferenceResults $postChangeResults
```

## Integration with Microsoft 365 Testing

Maester can test both AD and M365 environments simultaneously:

```powershell
# Connect to both environments
Connect-MtActiveDirectory
Connect-MgGraph -Scopes "Directory.Read.All"

# Run comprehensive tests
Invoke-Maester -Service All -IncludeActiveDirectory

# Compare hybrid configuration
$adResults = Invoke-Maester -Tag "AD" -PassThru
$m365Results = Invoke-Maester -Tag "Entra" -PassThru
# Analyze consistency between on-premises and cloud
```

## Support and Contributing

- **Documentation**: https://maester.dev/docs/active-directory
- **Issues**: https://github.com/maester365/maester/issues
- **Contributions**: Submit new AD tests following the established patterns
- **Community**: Join discussions about AD security testing

For more advanced scenarios and custom test development, see the [Custom Test Development Guide](./Custom-Test-Development.md).