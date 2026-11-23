<#
    Written by Olivier Lumeau
    https://github.com/Solisys-Cloud/token-anatomy
#>

@{
    RootModule        = 'TokenAnatomy.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = '3f6b8c1e-2a7d-4e59-9b0c-5d1e8f4a7c20'
    Author            = 'Olivier Lumeau'
    CompanyName       = 'Solisys SRL'
    Copyright         = '(c) 2026 Olivier Lumeau, Solisys SRL. MIT License.'
    Description       = 'Decode SAML responses, OIDC ID tokens and OAuth 2.0 access tokens, and answer one question: who is the token for?'
    PowerShellVersion = '7.2'
    FunctionsToExport = @('ConvertFrom-JwtToken', 'ConvertFrom-SamlResponse', 'Get-TokenAnatomy')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('SAML', 'OAuth2', 'OIDC', 'OpenIDConnect', 'JWT', 'EntraID', 'Identity', 'Security')
            LicenseUri = 'https://github.com/Solisys-Cloud/token-anatomy/blob/main/LICENSE'
            ProjectUri = 'https://github.com/Solisys-Cloud/token-anatomy'
        }
    }
}
