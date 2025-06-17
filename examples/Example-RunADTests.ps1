<#
.SYNOPSIS
    Example script showing how to run Maester AD tests

.DESCRIPTION
    This script demonstrates the complete workflow for running
    Active Directory security tests with Maester.

.EXAMPLE
    .\Example-RunADTests.ps1

    Runs AD tests with default settings

.EXAMPLE
    .\Example-RunADTests.ps1 -DomainController "DC01.contoso.com" -Credential $cred

    Runs AD tests with specific DC and credentials
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$DomainController,

    [Parameter(Mandatory = $false)]
    [PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "./ad-test-results",

    [Parameter(Mandatory = $false)]
    [string[]]$SpecificTests,

    [Parameter(Mandatory = $false)]
    [switch]$ExportToCsv,

    [Parameter(Mandatory = $false)]
    [switch]$SendEmail,

    [Parameter(Mandatory = $false)]
    [string]$EmailRecipient
)

# Banner
Write-Host @"
╔═══════════════════════════════════════════════════════════╗
║          Maester Active Directory Security Tests          ║
╚═══════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# Step 1: Check prerequisites
Write-Host "`n📋 Checking prerequisites..." -ForegroundColor Yellow

# Check if Maester is installed
if (-not (Get-Module -ListAvailable -Name Maester)) {
    Write-Host "   ❌ Maester not installed" -ForegroundColor Red
    Write-Host "   Installing Maester..." -ForegroundColor Yellow
    Install-Module -Name Maester -Scope CurrentUser -Force
}

# Check if AD module is available
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Host "   ❌ Active Directory PowerShell module not found" -ForegroundColor Red
    Write-Host "   Please install RSAT (Remote Server Administration Tools)" -ForegroundColor Yellow
    exit 1
}

Write-Host "   ✅ Prerequisites met" -ForegroundColor Green

# Step 2: Connect to Active Directory
Write-Host "`n🔐 Connecting to Active Directory..." -ForegroundColor Yellow

$connectParams = @{}
if ($DomainController) { $connectParams.DomainController = $DomainController }
if ($Credential) { $connectParams.Credential = $Credential }

try {
    Connect-MtActiveDirectory @connectParams
} catch {
    Write-Host "   ❌ Failed to connect to Active Directory: $_" -ForegroundColor Red
    exit 1
}

# Step 3: Install/Update Maester tests
Write-Host "`n📦 Checking Maester tests..." -ForegroundColor Yellow

if (-not (Test-Path "./tests")) {
    Write-Host "   Installing Maester tests..." -ForegroundColor Yellow
    Install-MaesterTests
} else {
    Write-Host "   Updating Maester tests..." -ForegroundColor Yellow
    Update-MaesterTests
}

# Step 4: Run tests
Write-Host "`n🧪 Running Active Directory security tests..." -ForegroundColor Yellow

$maesterParams = @{
    OutputFolder = $OutputPath
    IncludeActiveDirectory = $true
}

# Add specific test tags if requested
if ($SpecificTests) {
    $maesterParams.Tag = $SpecificTests
} else {
    $maesterParams.Tag = @("AD")
}

# Add CSV export if requested
if ($ExportToCsv) {
    $maesterParams.ExportCsv = $true
}

# Add email if requested
if ($SendEmail -and $EmailRecipient) {
    $maesterParams.MailRecipient = $EmailRecipient
}

# Run the tests
$results = Invoke-Maester @maesterParams

# Step 5: Summary
Write-Host "`n📊 Test Summary:" -ForegroundColor Yellow

if ($results) {
    $totalTests = $results.TotalCount
    $passedTests = $results.PassedCount
    $failedTests = $results.FailedCount
    $skippedTests = $results.SkippedCount

    Write-Host "   Total Tests: $totalTests" -ForegroundColor White
    Write-Host "   ✅ Passed: $passedTests" -ForegroundColor Green
    Write-Host "   ❌ Failed: $failedTests" -ForegroundColor Red
    Write-Host "   ⏭️  Skipped: $skippedTests" -ForegroundColor Yellow

    # Show critical failures
    if ($failedTests -gt 0) {
        Write-Host "`n⚠️  Critical Issues Found:" -ForegroundColor Red

        # Get failed tests
        $criticalTests = $results.Tests | Where-Object {
            $_.Result -eq 'Failed' -and
            $_.Tags -contains 'Security'
        } | Select-Object -First 5

        foreach ($test in $criticalTests) {
            Write-Host "   - $($test.Name)" -ForegroundColor Red
        }

        if ($failedTests -gt 5) {
            Write-Host "   ... and $($failedTests - 5) more" -ForegroundColor Red
        }
    }
}

# Step 6: Next steps
Write-Host "`n📌 Next Steps:" -ForegroundColor Cyan
Write-Host "   1. Review detailed results in: $OutputPath" -ForegroundColor White
Write-Host "   2. Address any failed tests, starting with high-severity issues" -ForegroundColor White
Write-Host "   3. Re-run tests after making changes to verify fixes" -ForegroundColor White

if ($ExportToCsv) {
    Write-Host "   4. CSV report available for management review" -ForegroundColor White
}

Write-Host "`n✨ Maester AD security assessment complete!" -ForegroundColor Green

# Example remediation suggestions
if ($failedTests -gt 0) {
    Write-Host "`n💡 Quick Remediation Tips:" -ForegroundColor Yellow

    # Check for common issues
    $passwordPolicyFailed = $results.Tests | Where-Object {
        $_.Name -like "*password*" -and $_.Result -eq 'Failed'
    }

    if ($passwordPolicyFailed) {
        Write-Host "   - Review and strengthen password policies" -ForegroundColor White
        Write-Host "     Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14" -ForegroundColor DarkGray
    }

    $privGroupsFailed = $results.Tests | Where-Object {
        $_.Name -like "*privileged*" -and $_.Result -eq 'Failed'
    }

    if ($privGroupsFailed) {
        Write-Host "   - Audit and reduce privileged group memberships" -ForegroundColor White
        Write-Host "     Get-ADGroupMember 'Domain Admins' | Review" -ForegroundColor DarkGray
    }
}