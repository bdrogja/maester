<#
.SYNOPSIS
    Gets Active Directory configuration information for Maester tests

.DESCRIPTION
    This command collects various AD configuration settings and returns them
    in a format useful for Maester tests.

.EXAMPLE
    Get-MtAdConfiguration

    Returns AD configuration information

.LINK
    https://maester.dev/docs/commands/Get-MtAdConfiguration
#>
function Get-MtAdConfiguration {
    [CmdletBinding()]
    param()

    # Check if connected to AD
    if (-not (Test-MtContext -ActiveDirectory)) {
        throw "Not connected to Active Directory. Please run Connect-MtActiveDirectory first."
    }

    Write-Verbose "Collecting Active Directory configuration..."

    $config = [PSCustomObject]@{
        Domain = $null
        Forest = $null
        DomainControllers = @()
        FunctionalLevels = @{}
        FSMO = @{}
        Sites = @()
        Trusts = @()
        GlobalCatalogs = @()
        ReadOnlyDCs = @()
        SchemaVersion = $null
        RecycleBin = $false
    }

    try {
        # Get domain info
        $domain = Get-ADDomain
        $config.Domain = [PSCustomObject]@{
            DNSRoot = $domain.DNSRoot
            NetBIOSName = $domain.NetBIOSName
            DistinguishedName = $domain.DistinguishedName
            DomainMode = $domain.DomainMode
            PDCEmulator = $domain.PDCEmulator
            RIDMaster = $domain.RIDMaster
            InfrastructureMaster = $domain.InfrastructureMaster
        }

        # Get forest info
        $forest = Get-ADForest
        $config.Forest = [PSCustomObject]@{
            Name = $forest.Name
            RootDomain = $forest.RootDomain
            ForestMode = $forest.ForestMode
            SchemaMaster = $forest.SchemaMaster
            DomainNamingMaster = $forest.DomainNamingMaster
            Domains = $forest.Domains
            GlobalCatalogs = $forest.GlobalCatalogs
            Sites = $forest.Sites
        }

        # Get functional levels
        $config.FunctionalLevels = [PSCustomObject]@{
            Domain = $domain.DomainMode.ToString()
            Forest = $forest.ForestMode.ToString()
        }

        # Get FSMO roles
        $config.FSMO = [PSCustomObject]@{
            PDCEmulator = $domain.PDCEmulator
            RIDMaster = $domain.RIDMaster
            InfrastructureMaster = $domain.InfrastructureMaster
            SchemaMaster = $forest.SchemaMaster
            DomainNamingMaster = $forest.DomainNamingMaster
        }

        # Get domain controllers
        $dcs = Get-ADDomainController -Filter *
        $config.DomainControllers = $dcs | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Site = $_.Site
                IPv4Address = $_.IPv4Address
                OperatingSystem = $_.OperatingSystem
                OperatingSystemVersion = $_.OperatingSystemVersion
                IsGlobalCatalog = $_.IsGlobalCatalog
                IsReadOnly = $_.IsReadOnly
                Roles = $_.OperationMasterRoles
            }
        }

        # Get sites
        $config.Sites = Get-ADReplicationSite -Filter * | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Description = $_.Description
                Location = $_.Location
            }
        }

        # Get trusts
        $config.Trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Direction = $_.Direction
                TrustType = $_.TrustType
                ForestTransitive = $_.ForestTransitive
                SelectiveAuthentication = $_.SelectiveAuthentication
                SIDFilteringForestAware = $_.SIDFilteringForestAware
                SIDFilteringQuarantined = $_.SIDFilteringQuarantined
            }
        }

        # Check if Recycle Bin is enabled
        $recycleBin = Get-ADOptionalFeature -Filter {Name -like "Recycle Bin Feature"} -ErrorAction SilentlyContinue
        $config.RecycleBin = $recycleBin.EnabledScopes.Count -gt 0

        # Get schema version
        $schema = Get-ADObject -Identity "CN=Schema,$((Get-ADRootDSE).schemaNamingContext)" -Properties objectVersion
        $config.SchemaVersion = $schema.objectVersion

    } catch {
        Write-Error "Failed to collect AD configuration: $_"
    }

    return $config
}

<#
.SYNOPSIS
    Gets AD security configuration for reporting

.DESCRIPTION
    Collects security-specific AD settings for Maester reports

.EXAMPLE
    Get-MtAdSecurityConfig

    Returns AD security configuration
#>
function Get-MtAdSecurityConfig {
    [CmdletBinding()]
    param()

    # Check if connected to AD
    if (-not (Test-MtContext -ActiveDirectory)) {
        throw "Not connected to Active Directory. Please run Connect-MtActiveDirectory first."
    }

    $secConfig = [PSCustomObject]@{
        PasswordPolicy = $null
        LockoutPolicy = $null
        FineGrainedPolicies = @()
        PrivilegedGroups = @{}
        ProtectedUsers = @()
        AdminSDHolder = @()
        KerberosPolicy = @{}
        AuditPolicy = @{}
    }

    try {
        # Get default domain password policy
        $secConfig.PasswordPolicy = Get-ADDefaultDomainPasswordPolicy

        # Get fine-grained password policies
        $secConfig.FineGrainedPolicies = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue

        # Get privileged group membership counts
        $privGroups = @(
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            "Account Operators",
            "Backup Operators",
            "Print Operators",
            "Server Operators"
        )

        foreach ($group in $privGroups) {
            try {
                $members = Get-ADGroupMember -Identity $group -ErrorAction Stop
                $secConfig.PrivilegedGroups[$group] = $members.Count
            } catch {
                $secConfig.PrivilegedGroups[$group] = "N/A"
            }
        }

        # Get Protected Users group members
        try {
            $protectedUsers = Get-ADGroupMember -Identity "Protected Users" -ErrorAction Stop
            $secConfig.ProtectedUsers = $protectedUsers | Select-Object Name, SamAccountName, ObjectClass
        } catch {
            # Protected Users group doesn't exist in older domains
        }

        # Get objects with AdminSDHolder flag
        $adminSDHolderObjects = Get-ADObject -LDAPFilter "(adminCount=1)" -Properties adminCount
        $secConfig.AdminSDHolder = $adminSDHolderObjects.Count

    } catch {
        Write-Error "Failed to collect AD security configuration: $_"
    }

    return $secConfig
}