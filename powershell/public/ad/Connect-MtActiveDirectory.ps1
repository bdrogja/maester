function Connect-MtActiveDirectory {
    <#
    .SYNOPSIS
        Connects to Active Directory for Maester tests

    .DESCRIPTION
        This command connects to Active Directory and stores the connection information in the Maester session.
        It verifies the connection and loads necessary AD modules.

    .EXAMPLE
        Connect-MtActiveDirectory

        Connects to the current domain using current user credentials

    .EXAMPLE
        Connect-MtActiveDirectory -DomainController "DC01.contoso.com" -Credential $cred

        Connects to a specific domain controller with alternate credentials

    .LINK
        https://maester.dev/docs/commands/Connect-MtActiveDirectory
    #>
    [CmdletBinding()]
    param(
        # Domain Controller to connect to (optional)
        [Parameter(Mandatory = $false)]
        [string]$DomainController,

        # Credentials for connection (optional)
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,

        # Domain name (optional, uses current domain if not specified)
        [Parameter(Mandatory = $false)]
        [string]$DomainName,

        # Skip connection test
        [Parameter(Mandatory = $false)]
        [switch]$SkipConnectionTest
    )

    Write-Host "[AD] Connecting to Active Directory..." -ForegroundColor Cyan

    # Check if AD module is available
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Error "Active Directory PowerShell module is not installed. Please install RSAT."
        return
    }

    # Import AD module
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    catch {
        Write-Error "Failed to import Active Directory module"
        return
    }

    # Initialize session if not exists
    if (-not $__MtSession) {
        Initialize-MtSession
    }

    try {
        # Set AD drive parameters
        $adParams = @{}
        if ($DomainController) { $adParams.Server = $DomainController }
        if ($Credential) { $adParams.Credential = $Credential }

        # Test connection
        if (-not $SkipConnectionTest) {
            Write-Verbose "Testing AD connection..."
            if ($DomainName) { $adParams.Identity = $DomainName }
            $domain = Get-ADDomain @adParams

            # Get a DC for testing
            $testDC = if ($DomainController) { $DomainController } else { $domain.PDCEmulator }

            # Test LDAP connectivity (cross-platform compatible)
            try {
                if ($PSVersionTable.Platform -eq 'Win32NT' -or $PSVersionTable.PSEdition -eq 'Desktop') {
                    # Windows PowerShell or Windows PowerShell Core
                    $ldapTest = Test-NetConnection -ComputerName $testDC -Port 389 -WarningAction SilentlyContinue
                    if (-not $ldapTest.TcpTestSucceeded) {
                        throw "Cannot connect to LDAP port 389 on $testDC"
                    }
                } else {
                    # Non-Windows platforms
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    $tcpClient.Connect($testDC, 389)
                    $tcpClient.Close()
                }
            } catch {
                throw "Cannot connect to LDAP port 389 on $testDC"
            }
        }

        # Store connection info in session
        $__MtSession.ADConnection = @{
            Connected = $true
            DomainController = $DomainController
            DomainName = if ($domain) { $domain.DNSRoot } else { $DomainName }
            DomainDN = if ($domain) { $domain.DistinguishedName } else { $null }
            ForestName = if ($domain) { $domain.Forest } else { $null }
            ConnectedAt = Get-Date
            Credential = if ($Credential) { $Credential.UserName } else { $env:USERNAME }
        }

        # Set default AD parameters for session
        if ($domain) {
            $PSDefaultParameterValues["Get-AD*:Server"] = if ($DomainController) { $DomainController } else { $domain.PDCEmulator }
        }
        if ($Credential) {
            $PSDefaultParameterValues["Get-AD*:Credential"] = $Credential
        }

        Write-Host "[OK] Connected to Active Directory" -ForegroundColor Green
        Write-Host "   Domain: $($__MtSession.ADConnection.DomainName)" -ForegroundColor Gray
        Write-Host "   User: $($__MtSession.ADConnection.Credential)" -ForegroundColor Gray
        if ($DomainController) {
            Write-Host "   DC: $DomainController" -ForegroundColor Gray
        }

    } catch {
        $__MtSession.ADConnection = @{ Connected = $false }
        $errorMessage = if ($_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
        Write-Error "Failed to connect to Active Directory: $errorMessage"
        return
    }
}