Describe "Active Directory Password Policy" -Tag "AD", "Security", "CIS", "All" {
    BeforeAll {
        # Get current password policy
        $passwordPolicy = Get-ADDefaultDomainPasswordPolicy
        $fineGrainedPolicies = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue
    }

    It "AD.PP01: Minimum password length should be at least 14 characters. See https://maester.dev/docs/tests/AD.PP01" {
        <#
            Passwords with at least 14 characters are significantly more resistant to brute force attacks.
            CIS recommends a minimum of 14 characters for standard security environments.
        #>
        $passwordPolicy.MinPasswordLength | Should -BeGreaterOrEqual 14 -Because "passwords shorter than 14 characters are vulnerable to attacks"
    }

    It "AD.PP02: Password complexity requirements should be enabled. See https://maester.dev/docs/tests/AD.PP02" {
        <#
            Complexity requirements ensure passwords contain uppercase, lowercase, numbers, and special characters.
            This significantly increases the password keyspace and resistance to dictionary attacks.
        #>
        $passwordPolicy.ComplexityEnabled | Should -Be $true -Because "complex passwords are harder to crack"
    }

    It "AD.PP03: Password history should remember at least 24 passwords. See https://maester.dev/docs/tests/AD.PP03" {
        <#
            Password history prevents users from reusing old passwords.
            24 passwords with a 60-day change cycle means passwords cannot be reused for 4 years.
        #>
        $passwordPolicy.PasswordHistoryCount | Should -BeGreaterOrEqual 24 -Because "password reuse increases security risks"
    }

    It "AD.PP04: Maximum password age should not exceed 365 days. See https://maester.dev/docs/tests/AD.PP04" {
        <#
            Regular password changes limit the window of opportunity for compromised credentials.
            While NIST has moved away from mandatory changes, many compliance frameworks still require it.
        #>
        $maxAge = $passwordPolicy.MaxPasswordAge.Days
        if ($maxAge -eq 0) {
            # 0 means passwords never expire
            $maxAge | Should -Not -Be 0 -Because "passwords should expire periodically"
        } else {
            $maxAge | Should -BeLessOrEqual 365 -Because "passwords older than 1 year pose increased risk"
        }
    }

    It "AD.PP05: Minimum password age should be at least 1 day. See https://maester.dev/docs/tests/AD.PP05" {
        <#
            Minimum password age prevents users from rapidly cycling through password history.
            Without this, users could change their password 24 times in a row to reuse an old password.
        #>
        $passwordPolicy.MinPasswordAge.Days | Should -BeGreaterOrEqual 1 -Because "prevents password cycling attacks"
    }

    It "AD.PP06: Account lockout threshold should be configured. See https://maester.dev/docs/tests/AD.PP06" {
        <#
            Account lockout after failed attempts prevents brute force attacks.
            Recommended: 5-10 invalid attempts before lockout.
        #>
        $passwordPolicy.LockoutThreshold | Should -BeGreaterThan 0 -Because "protects against brute force attacks"
        $passwordPolicy.LockoutThreshold | Should -BeLessOrEqual 10 -Because "too high threshold reduces protection"
    }

    It "AD.PP07: Account lockout duration should be at least 15 minutes. See https://maester.dev/docs/tests/AD.PP07" {
        <#
            Lockout duration should be long enough to deter attacks but not overly impact legitimate users.
            15-30 minutes is a common recommendation.
        #>
        if ($passwordPolicy.LockoutDuration) {
            $passwordPolicy.LockoutDuration.TotalMinutes | Should -BeGreaterOrEqual 15 -Because "shorter durations don't deter attackers"
        }
    }

    It "AD.PP08: Fine-grained password policies should be used for privileged accounts. See https://maester.dev/docs/tests/AD.PP08" {
        <#
            Privileged accounts should have stronger password requirements.
            Fine-grained policies allow different requirements for different user groups.
        #>
        $fineGrainedPolicies | Should -Not -BeNullOrEmpty -Because "privileged accounts need stronger policies"

        # Check if any policy applies to admin groups
        $adminPolicies = @()
        foreach ($policy in $fineGrainedPolicies) {
            $subjects = Get-ADFineGrainedPasswordPolicySubject $policy
            $adminGroups = $subjects | Where-Object {
                $_.Name -match "admin|privilege" -or
                $_.SID -in @("S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551")
            }
            if ($adminGroups) {
                $adminPolicies += $policy
            }
        }

        $adminPolicies | Should -Not -BeNullOrEmpty -Because "admin accounts need specialized password policies"
    }
}