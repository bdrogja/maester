Describe "Active Directory Service Accounts" -Tag "AD", "Security", "ServiceAccount", "All" {
    BeforeAll {
        # Get all user accounts
        $allUsers = Get-ADUser -Filter * -Properties ServicePrincipalName, PasswordLastSet, PasswordNeverExpires,
            LastLogonDate, WhenCreated, Description, MemberOf, UserAccountControl, msDS-SupportedEncryptionTypes

        # Identify service accounts by various patterns
        $serviceAccounts = $allUsers | Where-Object {
            $_.ServicePrincipalName -or
            $_.SamAccountName -match '^(svc|service|srv|app)[-_]' -or
            $_.Description -match 'service account|svc account|application account' -or
            ($_.PasswordNeverExpires -eq $true -and $_.Enabled -eq $true)
        }

        # Get Managed Service Accounts
        $managedServiceAccounts = Get-ADServiceAccount -Filter * -ErrorAction SilentlyContinue
    }

    It "AD.SA01: Service accounts should use Managed Service Accounts (MSA) or Group Managed Service Accounts (gMSA). See https://maester.dev/docs/tests/AD.SA01" {
        <#
            MSAs and gMSAs provide automatic password management and simplified SPN management.
            They cannot be used for interactive logon and support Kerberos only.
        #>

        if ($null -eq $managedServiceAccounts) {
            Set-ItResult -Skipped -Because "Managed Service Accounts not supported in this environment"
            return
        }

        $traditionalServiceAccounts = $serviceAccounts | Where-Object {
            $_.SamAccountName -notin $managedServiceAccounts.SamAccountName
        }

        # Allow some traditional accounts but flag if too many
        $traditionalServiceAccounts.Count | Should -BeLessOrEqual 10 -Because "prefer Managed Service Accounts for better security"

        if ($traditionalServiceAccounts.Count -gt 0) {
            $accountList = $traditionalServiceAccounts | Select-Object -First 10 | ForEach-Object {
                "   - $($_.SamAccountName) (Password Age: $((New-TimeSpan $_.PasswordLastSet).Days) days)"
            }
            Add-MtTestResultDetail -Description ("Traditional service accounts found (consider migrating to MSA/gMSA):`n" + ($accountList -join "`n"))
        }
    }

    It "AD.SA02: Service accounts should not have passwords set to never expire. See https://maester.dev/docs/tests/AD.SA02" {
        <#
            Even service accounts should have password rotation.
            Use MSAs/gMSAs for automatic rotation or implement a manual process.
        #>

        $neverExpireAccounts = $serviceAccounts | Where-Object {
            $_.PasswordNeverExpires -eq $true -and
            $_.SamAccountName -notin $managedServiceAccounts.SamAccountName
        }

        $neverExpireAccounts | Should -BeNullOrEmpty -Because "passwords should rotate even for service accounts"

        if ($neverExpireAccounts) {
            $accountList = $neverExpireAccounts | Select-Object -First 10 | ForEach-Object {
                $passwordAge = if ($_.PasswordLastSet) { (New-TimeSpan $_.PasswordLastSet).Days } else { "Unknown" }
                "   - $($_.SamAccountName) (Password Age: $passwordAge days)"
            }
            Add-MtTestResultDetail -Description ("Service accounts with non-expiring passwords:`n" + ($accountList -join "`n"))
        }
    }

    It "AD.SA03: Service accounts should not be members of privileged groups. See https://maester.dev/docs/tests/AD.SA03" {
        <#
            Service accounts should have minimal permissions.
            They should not be in Domain Admins, Administrators, etc.
        #>

        $privilegedGroups = @(
            "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
            "Account Operators", "Backup Operators", "Server Operators"
        )

        $privilegedServiceAccounts = @()
        foreach ($account in $serviceAccounts) {
            $groups = $account.MemberOf | ForEach-Object {
                (Get-ADGroup $_ -ErrorAction SilentlyContinue).Name
            }

            $privGroups = $groups | Where-Object { $_ -in $privilegedGroups }
            if ($privGroups) {
                $privilegedServiceAccounts += [PSCustomObject]@{
                    Account = $account.SamAccountName
                    Groups = $privGroups -join ", "
                }
            }
        }

        $privilegedServiceAccounts | Should -BeNullOrEmpty -Because "service accounts should use least privilege"

        if ($privilegedServiceAccounts) {
            $accountList = $privilegedServiceAccounts | ForEach-Object {
                "   - $($_.Account): $($_.Groups)"
            }
            Add-MtTestResultDetail -Description ("Service accounts in privileged groups:`n" + ($accountList -join "`n"))
        }
    }

    It "AD.SA04: Service accounts should have strong encryption types enabled. See https://maester.dev/docs/tests/AD.SA04" {
        <#
            Service accounts should support AES encryption and not rely on weak DES or RC4.
            Check msDS-SupportedEncryptionTypes attribute.
        #>

        $weakEncryptionAccounts = $serviceAccounts | Where-Object {
            # If not set, defaults are used (which may include weak encryption)
            $null -eq $_.'msDS-SupportedEncryptionTypes' -or
            # Check if only weak encryption is enabled (DES = 3, RC4 = 4)
            ($_.'msDS-SupportedEncryptionTypes' -band 24) -eq 0 -or
            # Check if DES is enabled
            ($_.'msDS-SupportedEncryptionTypes' -band 3) -ne 0
        }

        $weakEncryptionAccounts | Should -BeNullOrEmpty -Because "service accounts should use AES encryption"

        if ($weakEncryptionAccounts) {
            $accountList = $weakEncryptionAccounts | Select-Object -First 10 | ForEach-Object {
                $encTypes = $_.'msDS-SupportedEncryptionTypes'
                "   - $($_.SamAccountName) (Encryption Types: $encTypes)"
            }
            Add-MtTestResultDetail -Description ("Service accounts with weak encryption:`n" + ($accountList -join "`n"))
        }
    }

    It "AD.SA05: Service accounts should have documented SPNs. See https://maester.dev/docs/tests/AD.SA05" {
        <#
            Service Principal Names should be properly set for Kerberos authentication.
            Duplicate SPNs cause authentication failures.
        #>

        # Get all SPNs in the domain
        $allSPNs = @{}
        $duplicateSPNs = @()

        foreach ($account in $allUsers) {
            if ($account.ServicePrincipalName) {
                foreach ($spn in $account.ServicePrincipalName) {
                    if ($allSPNs.ContainsKey($spn)) {
                        $duplicateSPNs += [PSCustomObject]@{
                            SPN = $spn
                            Account1 = $allSPNs[$spn]
                            Account2 = $account.SamAccountName
                        }
                    } else {
                        $allSPNs[$spn] = $account.SamAccountName
                    }
                }
            }
        }

        $duplicateSPNs | Should -BeNullOrEmpty -Because "duplicate SPNs cause Kerberos authentication failures"

        if ($duplicateSPNs) {
            $spnList = $duplicateSPNs | ForEach-Object {
                "   - $($_.SPN): $($_.Account1) & $($_.Account2)"
            }
            Add-MtTestResultDetail -Description ("Duplicate SPNs found:`n" + ($spnList -join "`n"))
        }
    }

    It "AD.SA06: Unused service accounts should be disabled. See https://maester.dev/docs/tests/AD.SA06" {
        <#
            Service accounts not used in 90+ days should be disabled.
            Unused accounts are attack vectors.
        #>

        $threshold = (Get-Date).AddDays(-90)
        $unusedAccounts = $serviceAccounts | Where-Object {
            $_.Enabled -eq $true -and
            $_.LastLogonDate -and
            $_.LastLogonDate -lt $threshold
        }

        $unusedAccounts | Should -BeNullOrEmpty -Because "unused service accounts should be disabled"

        if ($unusedAccounts) {
            $accountList = $unusedAccounts | Select-Object -First 10 | ForEach-Object {
                $daysSinceLogon = (New-TimeSpan $_.LastLogonDate).Days
                "   - $($_.SamAccountName) (Last Logon: $daysSinceLogon days ago)"
            }
            Add-MtTestResultDetail -Description ("Active service accounts not used in 90+ days:`n" + ($accountList -join "`n"))
        }
    }
}