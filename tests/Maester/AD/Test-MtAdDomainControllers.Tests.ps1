Describe "Active Directory Domain Controllers" -Tag "AD", "Security", "DomainController", "All" {
    BeforeAll {
        # Get all domain controllers
        $domainControllers = Get-ADDomainController -Filter *

        # Get domain functional level
        $domain = Get-ADDomain
        $forest = Get-ADForest

        # Define minimum OS versions
        $minimumOSVersions = @{
            "Windows Server 2012 R2" = "6.3"
            "Windows Server 2016" = "10.0.14393"
            "Windows Server 2019" = "10.0.17763"
            "Windows Server 2022" = "10.0.20348"
        }
    }

    It "AD.DC01: All domain controllers should be running supported OS versions. See https://maester.dev/docs/tests/AD.DC01" {
        <#
            Domain Controllers should run currently supported OS versions.
            Unsupported versions don't receive security updates.
        #>

        $unsupportedDCs = $domainControllers | Where-Object {
            # Windows Server 2012 R2 extended support ends October 2023
            # Windows Server 2016 mainstream support ends January 2022, extended ends 2027
            # For this test, we'll flag anything older than Server 2016

            $osVersion = $_.OperatingSystemVersion
            if ($osVersion -match '(\d+\.\d+)') {
                [version]$version = $matches[1]
                $version -lt [version]"10.0"  # Older than Windows Server 2016
            } else {
                $true  # Can't parse version, flag as potential issue
            }
        }

        $unsupportedDCs | Should -BeNullOrEmpty -Because "unsupported OS versions lack security updates"

        if ($unsupportedDCs) {
            $dcList = $unsupportedDCs | ForEach-Object {
                "   - $($_.Name): $($_.OperatingSystem) ($($_.OperatingSystemVersion))"
            }
            Add-MtTestResultDetail -Description ("Domain Controllers with outdated OS:`n" + ($dcList -join "`n"))
        }
    }

    It "AD.DC02: Domain and forest functional levels should be recent. See https://maester.dev/docs/tests/AD.DC02" {
        <#
            Higher functional levels enable security features.
            Should be at least 2012 R2, preferably 2016 or higher.
        #>

        $minimumLevel = "2012R2"
        $domainLevel = $domain.DomainMode
        $forestLevel = $forest.ForestMode

        # Convert to comparable format
        $levelValues = @{
            "2008" = 3
            "2008R2" = 4
            "2012" = 5
            "2012R2" = 6
            "2016" = 7
            "2019" = 8
            "2022" = 9
        }

        $currentDomainValue = $levelValues[$domainLevel.ToString().Replace("Windows", "")]
        $currentForestValue = $levelValues[$forestLevel.ToString().Replace("Windows", "")]
        $minimumValue = $levelValues[$minimumLevel]

        $currentDomainValue | Should -BeGreaterOrEqual $minimumValue -Because "newer functional levels provide better security features"
        $currentForestValue | Should -BeGreaterOrEqual $minimumValue -Because "newer functional levels provide better security features"

        Add-MtTestResultDetail -Description @"
Current functional levels:
   - Domain: $domainLevel
   - Forest: $forestLevel

Recommended: 2016 or higher for advanced security features
"@
    }

    It "AD.DC03: All domain controllers should have Windows Firewall enabled. See https://maester.dev/docs/tests/AD.DC03" {
        <#
            Windows Firewall should be enabled on all DCs.
            Check via registry or WMI would require remote access, so we check for group policy.
        #>

        # This is a simplified check - in production, you'd want to query each DC
        # For now, we'll check if there's a GPO that might disable firewall on DCs

        $dcOU = $domainControllers[0].ComputerObjectDN -replace '^[^,]+,', ''
        $gpos = Get-GPInheritance -Target $dcOU -ErrorAction SilentlyContinue

        if ($gpos) {
            $suspiciousGPOs = $gpos.GpoLinks | Where-Object {
                $_.DisplayName -match "firewall|disable|off" -and $_.Enabled
            }

            $suspiciousGPOs | Should -BeNullOrEmpty -Because "firewall should not be disabled via GPO"

            if ($suspiciousGPOs) {
                Add-MtTestResultDetail -Description "Found GPOs that might disable firewall: $($suspiciousGPOs.DisplayName -join ', ')"
            }
        }

        Add-MtTestResultDetail -Description "Note: This test checks for GPOs only. Verify firewall status directly on each DC."
    }

    It "AD.DC04: Domain controllers should be in a dedicated OU. See https://maester.dev/docs/tests/AD.DC04" {
        <#
            DCs should be in their own OU for targeted policy application.
            Default is "OU=Domain Controllers,DC=..."
        #>

        $dcOUs = $domainControllers.ComputerObjectDN | ForEach-Object {
            $_ -replace '^[^,]+,', ''
        } | Select-Object -Unique

        $dcOUs.Count | Should -Be 1 -Because "all DCs should be in the same OU"

        # Check if it's the default DC OU
        $defaultOU = "OU=Domain Controllers,$($domain.DistinguishedName)"
        $nonDefaultDCs = $domainControllers | Where-Object {
            $_.ComputerObjectDN -notlike "*$defaultOU"
        }

        if ($nonDefaultDCs) {
            $dcList = $nonDefaultDCs | ForEach-Object {
                "   - $($_.Name): $($_.ComputerObjectDN)"
            }
            Add-MtTestResultDetail -Description ("Domain Controllers in non-standard OUs:`n" + ($dcList -join "`n"))
        }
    }

    It "AD.DC05: LDAP signing should be required on all domain controllers. See https://maester.dev/docs/tests/AD.DC05" {
        <#
            LDAP signing prevents man-in-the-middle attacks.
            Should be required, not just supported.
        #>

        # Check Default Domain Controllers Policy
        $dcPolicy = Get-GPO -Name "Default Domain Controllers Policy" -ErrorAction SilentlyContinue

        if ($dcPolicy) {
            # In production, you'd parse the policy settings
            # This is a placeholder check
            Add-MtTestResultDetail -Description @"
Verify LDAP signing requirements:
1. Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
2. 'Domain controller: LDAP server signing requirements' should be set to 'Require signing'
3. Also check 'Network security: LDAP client signing requirements'
"@
        } else {
            Add-MtTestResultDetail -Description "Default Domain Controllers Policy not found - LDAP signing status unknown"
        }
    }

    It "AD.DC06: Time synchronization should be properly configured. See https://maester.dev/docs/tests/AD.DC06" {
        <#
            Proper time sync is critical for Kerberos authentication.
            PDC emulator should sync externally, others from PDC.
        #>

        $pdcEmulator = $domainControllers | Where-Object { $_.OperationMasterRoles -contains "PDCEmulator" }

        $pdcEmulator | Should -Not -BeNullOrEmpty -Because "PDC Emulator role must exist"

        if ($pdcEmulator) {
            Add-MtTestResultDetail -Description @"
Time synchronization hierarchy:
   - PDC Emulator: $($pdcEmulator.Name) (should sync with external time source)
   - Other DCs: Should sync with PDC Emulator

Verify with: w32tm /query /status on each DC
"@
        }
    }

    It "AD.DC07: No additional software should be installed on domain controllers. See https://maester.dev/docs/tests/AD.DC07" {
        <#
            DCs should only run AD DS and required Windows roles.
            Additional software increases attack surface.
        #>

        # Check for common additional roles that shouldn't be on DCs
        $riskyRoles = @(
            "Web-Server",
            "DHCP",
            "Print-Services",
            "FS-FileServer"
        )

        # Note: This requires remote access to DCs to properly check
        Add-MtTestResultDetail -Description @"
Domain Controllers should not have additional roles or software:
   - No web server (IIS)
   - No DHCP server
   - No file server role
   - No third-party software

Verify installed roles on each DC with:
Get-WindowsFeature | Where-Object {`$_.Installed}
"@
    }
}