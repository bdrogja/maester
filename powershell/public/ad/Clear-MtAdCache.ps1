function Clear-MtAdCache {
    <#
    .SYNOPSIS
        Clears the Active Directory cache in the current Maester session.

    .DESCRIPTION
        This command clears any cached Active Directory data to ensure fresh results in subsequent tests.
        While AD cmdlets don't require extensive caching like Graph API calls, this function maintains
        consistency with other service cache management functions.

    .EXAMPLE
        Clear-MtAdCache

        Clears the AD cache in the current session.

    .LINK
        https://maester.dev/docs/commands/Clear-MtAdCache
    #>
    [CmdletBinding()]
    param()

    Write-Verbose "Clearing Active Directory cache..."
    
    if ($__MtSession) {
        $__MtSession.AdCache = @{}
        Write-Verbose "Active Directory cache cleared."
    } else {
        Write-Warning "No active Maester session found."
    }
}