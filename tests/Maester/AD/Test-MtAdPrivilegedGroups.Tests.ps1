Describe "Active Directory Privileged Groups" -Tag "AD", "Security", "Privilege", "All" {
    BeforeAll {
        # Define privileged groups to check
        $privilegedGroups = @{
            "Domain Admins" = @{
                MaxMembers = 5
                RequireEmptyInChildDomain = $false
            }
            "Enterprise Admins" = @{
                MaxMembers = 3
                RequireEmptyInChildDomain = $true
            }
            "Schema Admins" = @{
                MaxMembers = 1
                RequireEmptyInChildDomain = $true
            }
            "Administrators" = @{
                MaxMembers = 10
                RequireEmptyInChildDomain = $false
            }
            "Account Operators" = @{
                MaxMembers = 0
                RequireEmptyInChildDomain = $false
            }
            "Backup Operators" = @{
                MaxMembers = 3
                RequireEmptyInChildDomain = $false
            }
            "Print Operators" = @{
                MaxMembers = 0
                RequireEmptyInChildDomain = $false
            }
            "Server Operators" = @{
                MaxMembers = 0
                RequireEmptyInChildDomain = $false
            }
        }

        # Check if we're in root domain
        $currentDomain = Get-ADDomain
        $forestRoot = Get-ADForest | Select-Object -ExpandProperty RootDomain
        $isRootDomain = $currentDomain.DNSRoot -eq $forestRoot
    }

    foreach ($groupName in $privilegedGroups.Keys) {
        $groupConfig = $privilegedGroups[$groupName]

        Context "Group: $groupName" {
            BeforeAll {
                try {
                    $group = Get-ADGroup -Identity $groupName -ErrorAction Stop
                    $members = Get-ADGroupMember -Identity $groupName -ErrorAction Stop
                } catch {
                    $group = $null
                    $members = @()
                }
            }

            It "AD.PG01.$($groupName.Replace(' ', '')): Should have minimal members (max: $($groupConfig.MaxMembers)). See https://maester.dev/docs/tests/AD.PG01" {
                if ($null -eq $group) {
                    Set-ItResult -Skipped -Because "Group '$groupName' not found in domain"
                    return
                }

                $members.Count | Should -BeLessOrEqual $groupConfig.MaxMembers -Because "privileged groups should have minimal membership"

                # Add details about members
                if ($members.Count -gt 0) {
                    $memberList = $members | ForEach-Object {
                        $obj = Get-ADObject $_ -Properties LastLogonDate, WhenCreated
                        "   - $($_.Name) (Type: $($_.objectClass), Created: $($obj.WhenCreated.ToString('yyyy-MM-dd')))"
                    }
                    Add-MtTestResultDetail -Description ("Current members:`n" + ($memberList -join "`n"))
                }
            }

            if ($groupConfig.RequireEmptyInChildDomain -and -not $isRootDomain) {
                It "AD.PG02.$($groupName.Replace(' ', '')): Should be empty in child domain. See https://maester.dev/docs/tests/AD.PG02" {
                    if ($null -eq $group) {
                        Set-ItResult -Skipped -Because "Group '$groupName' not found in domain"
                        return
                    }

                    $members.Count | Should -Be 0 -Because "'$groupName' should be empty in child domains"
                }
            }

            It "AD.PG03.$($groupName.Replace(' ', '')): Should not contain user accounts directly. See https://maester.dev/docs/tests/AD.PG03" {
                if ($null -eq $group) {
                    Set-ItResult -Skipped -Because "Group '$groupName' not found in domain"
                    return
                }

                $userMembers = $members | Where-Object { $_.objectClass -eq 'user' }

                # For Domain Admins and Enterprise Admins, we might allow some direct users
                if ($groupName -in @("Domain Admins", "Enterprise Admins")) {
                    $userMembers.Count | Should -BeLessOrEqual 3 -Because "prefer using groups for role management"
                } else {
                    $userMembers.Count | Should -Be 0 -Because "use role groups instead of direct user membership"
                }

                if ($userMembers.Count -gt 0) {
                    $userList = $userMembers | ForEach-Object { "   - $($_.Name)" }
                    Add-MtTestResultDetail -Description ("Direct user members found:`n" + ($userList -join "`n"))
                }
            }
        }
    }

    It "AD.PG04: No nested privileged group memberships should exist. See https://maester.dev/docs/tests/AD.PG04" {
        <#
            Privileged groups should not be members of other privileged groups.
            This creates complex permission chains that are hard to audit.
        #>
        $nestedMemberships = @()

        foreach ($groupName in $privilegedGroups.Keys) {
            try {
                $members = Get-ADGroupMember -Identity $groupName -ErrorAction Stop
                $groupMembers = $members | Where-Object { $_.objectClass -eq 'group' }

                foreach ($member in $groupMembers) {
                    if ($member.Name -in $privilegedGroups.Keys) {
                        $nestedMemberships += "$groupName contains $($member.Name)"
                    }
                }
            } catch {
                # Group doesn't exist, skip
            }
        }

        $nestedMemberships | Should -BeNullOrEmpty -Because "nested privileged groups create security risks"

        if ($nestedMemberships) {
            Add-MtTestResultDetail -Description ("Nested memberships found:`n   - " + ($nestedMemberships -join "`n   - "))
        }
    }

    It "AD.PG05: Protected Users group should contain all privileged accounts. See https://maester.dev/docs/tests/AD.PG05" {
        <#
            The Protected Users group provides additional protections against credential theft.
            All privileged accounts should be members (except service accounts that require Kerberos delegation).
        #>

        try {
            $protectedUsers = Get-ADGroupMember "Protected Users" -ErrorAction Stop
        } catch {
            Set-ItResult -Skipped -Because "Protected Users group not found (requires Windows Server 2012 R2 or later)"
            return
        }

        # Get all privileged users
        $allPrivilegedUsers = @()
        foreach ($groupName in @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")) {
            try {
                $members = Get-ADGroupMember -Identity $groupName -Recursive -ErrorAction Stop |
                    Where-Object { $_.objectClass -eq 'user' }
                $allPrivilegedUsers += $members
            } catch {
                # Group doesn't exist, skip
            }
        }

        # Remove duplicates
        $uniquePrivilegedUsers = $allPrivilegedUsers | Select-Object -Unique -Property SamAccountName

        # Check which privileged users are not protected
        $unprotectedUsers = $uniquePrivilegedUsers | Where-Object {
            $_.SamAccountName -notin $protectedUsers.SamAccountName -and
            $_.SamAccountName -notmatch '^(krbtgt|Guest|DefaultAccount)$'
        }

        $unprotectedUsers | Should -BeNullOrEmpty -Because "all privileged users should be in Protected Users group"

        if ($unprotectedUsers) {
            $userList = $unprotectedUsers | ForEach-Object { "   - $($_.SamAccountName)" }
            Add-MtTestResultDetail -Description ("Privileged users not in Protected Users group:`n" + ($userList -join "`n"))
        }
    }
}