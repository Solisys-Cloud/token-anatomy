BeforeAll {
    $root = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $root 'src/TokenAnatomy.psd1') -Force
    $samples = Join-Path $root 'samples'
    $idToken = (Get-Content (Join-Path $samples 'id-token.jwt') -Raw).Trim()
    $accessToken = (Get-Content (Join-Path $samples 'access-token.jwt') -Raw).Trim()
    $appOnlyToken = (Get-Content (Join-Path $samples 'app-only-access-token.jwt') -Raw).Trim()
    $samlBase64 = (Get-Content (Join-Path $samples 'saml-response.b64') -Raw).Trim()
    $samlXml = Get-Content (Join-Path $samples 'saml-response.xml') -Raw
}

Describe 'ConvertFrom-JwtToken' {
    It 'decodes the header and the payload' {
        $jwt = ConvertFrom-JwtToken -Token $idToken
        $jwt.Header.alg | Should -Be 'RS256'
        $jwt.Payload.preferred_username | Should -Be 'alice@contoso.com'
    }

    It 'classifies an ID token' {
        (ConvertFrom-JwtToken -Token $idToken).Kind | Should -Be 'IdToken'
    }

    It 'classifies a delegated access token' {
        (ConvertFrom-JwtToken -Token $accessToken).Kind | Should -Be 'AccessToken'
    }

    It 'classifies an app-only access token' {
        (ConvertFrom-JwtToken -Token $appOnlyToken).Kind | Should -Be 'AppOnlyAccessToken'
    }

    It 'accepts a Bearer header value' {
        (ConvertFrom-JwtToken -Token "Bearer $accessToken").Kind | Should -Be 'AccessToken'
    }

    It 'converts exp to a UTC date' {
        (ConvertFrom-JwtToken -Token $idToken).ExpiresOn | Should -Be ([datetime]::new(2026, 11, 20, 10, 0, 0, [DateTimeKind]::Utc))
    }

    It 'rejects a value that is not a JWT' {
        { ConvertFrom-JwtToken -Token 'not-a-token' } | Should -Throw
    }
}

Describe 'ConvertFrom-SamlResponse' {
    It 'decodes a Base64 SAMLResponse' {
        $saml = ConvertFrom-SamlResponse -SamlResponse $samlBase64
        $saml.NameId | Should -Be 'alice@contoso.com'
        $saml.Audience | Should -Be 'https://app.contoso.com/saml'
    }

    It 'decodes a URL-encoded SAMLResponse' {
        $encoded = [Uri]::EscapeDataString($samlBase64)
        (ConvertFrom-SamlResponse -SamlResponse $encoded).NameId | Should -Be 'alice@contoso.com'
    }

    It 'decodes raw XML' {
        (ConvertFrom-SamlResponse -SamlResponse $samlXml).Issuer | Should -Match '^https://sts.windows.net/'
    }

    It 'reads multi-valued attributes' {
        $saml = ConvertFrom-SamlResponse -SamlResponse $samlXml
        $saml.Attributes['http://schemas.microsoft.com/ws/2008/06/identity/claims/groups'].Count | Should -Be 2
    }

    It 'detects the assertion signature element' {
        (ConvertFrom-SamlResponse -SamlResponse $samlXml).AssertionSigned | Should -BeTrue
    }

    It 'refuses a DTD (Document Type Definition)' {
        $dtd = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e "x">]><x>&e;</x>'
        { ConvertFrom-SamlResponse -SamlResponse $dtd } | Should -Throw
    }
}

Describe 'Get-TokenAnatomy' {
    It 'says an ID token is for the client application' {
        (Get-TokenAnatomy -Token $idToken).IntendedFor | Should -BeLike 'The client application*'
    }

    It 'says an access token is for the API' {
        $summary = Get-TokenAnatomy -Token $accessToken
        $summary.IntendedFor | Should -BeLike 'The API*'
        $summary.Permissions | Should -Match 'scp: Orders.Read'
    }

    It 'flags app-only tokens as having no user' {
        (Get-TokenAnatomy -Token $appOnlyToken).IntendedFor | Should -BeLike '*no user involved'
    }

    It 'says a SAML assertion is for the Service Provider' {
        $summary = Get-TokenAnatomy -Token $samlBase64
        $summary.Protocol | Should -Be 'SAML 2.0'
        $summary.IntendedFor | Should -BeLike '*Service Provider*'
        $summary.Permissions | Should -Match 'Finance.Approver'
    }

    It 'processes several tokens from the pipeline' {
        @($idToken, $accessToken, $samlBase64 | Get-TokenAnatomy).Count | Should -Be 3
    }
}
