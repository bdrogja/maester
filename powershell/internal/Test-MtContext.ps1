<#
.SYNOPSIS
    Validates the MgContext to ensure a valid connection to Microsoft Graph including the required permissions.
#>
function Test-MtContext {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        # If specified, the scope will be checked to send email.
        [Parameter(Mandatory = $false)]
        [switch] $SendMail,

        # If specified, the scope will be checked to send Teams channel messages.
        [Parameter(Mandatory = $false)]
        [switch] $SendTeamsMessage,

        # If specified, validates Active Directory connection instead of Microsoft Graph
        [Parameter(Mandatory = $false)]
        [switch] $ActiveDirectory
    )

    $validContext = $true
    
    # Check Active Directory context if specified
    if ($ActiveDirectory) {
        if (-not $__MtSession -or -not $__MtSession.ADConnection -or -not $__MtSession.ADConnection.Connected) {
            $message = "Not connected to Active Directory. Please use 'Connect-MtActiveDirectory'. For more information, use 'Get-Help Connect-MtActiveDirectory'."
            $validContext = $false
        } else {
            # Test if connection is still valid
            try {
                Get-ADDomain -ErrorAction Stop | Out-Null
            } catch {
                $message = "Active Directory connection is no longer valid. Please reconnect using 'Connect-MtActiveDirectory'."
                $validContext = $false
            }
        }
    } elseif (-not ($context = Get-MgContext)) {
        $message = "Not connected to Microsoft Graph. Please use 'Connect-Maester'. For more information, use 'Get-Help Connect-Maester'."
        $validContext = $false
    } else {
        $requiredScopes = if ($context.AuthType -eq 'Delegated') {
            Get-MtGraphScope -SendMail:$SendMail -SendTeamsMessage:$SendTeamsMessage
        } else {
            # Do not include Mail.Send for applications. Not compatible with Exchange Online RBAC for Applications
            Get-MtGraphScope -SendTeamsMessage:$SendTeamsMessage
        }
        $currentScopes = $context.Scopes
        $missingScopes = $requiredScopes | Where-Object { $currentScopes -notcontains $_ -and $currentScopes -notcontains ($_ -replace '.Read.', '.ReadWrite.') }

        if ($missingScopes) {
            $message = "These Graph permissions are missing in the current connection => ($($missingScopes))."

            if ($context.AuthType -eq 'Delegated') {
                $message += " Please use 'Connect-Maester'. For more information, use 'Get-Help Connect-Maester'."
            } else {
                $clientId = $context.ClientId
                $urlTemplate = "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/$clientId/isMSAApp~/false"
                $message += " Add the missing 'Application' permissions in the Microsoft Entra portal and grant consent. You will also need to Disconnect-Graph to refresh the permissions."
                $message += " Click here to open the 'API Permissions' blade for this app (GitHub/Azure DevOps might prevent this link from working): $urlTemplate"
            }
            $validContext = $false
        }
    }

    if (!$validContext) {
        throw $message
    }
    return $validContext
}