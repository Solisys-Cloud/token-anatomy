Set-StrictMode -Version Latest

# Well-known identifiers of the Microsoft Graph resource.
$script:GraphAudiences = @(
    'https://graph.microsoft.com',
    'https://graph.microsoft.com/',
    '00000003-0000-0000-c000-000000000000'
)

function ConvertFrom-Base64Url {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]
        [string] $Value
    )

    $base64 = $Value.Replace('-', '+').Replace('_', '/')
    switch ($base64.Length % 4) {
        2 { $base64 += '==' }
        3 { $base64 += '=' }
        1 { throw 'Invalid Base64Url string.' }
    }
    return [Convert]::FromBase64String($base64)
}

function ConvertTo-UtcDate {
    [CmdletBinding()]
    [OutputType([Nullable[datetime]])]
    param(
        [Parameter()]
        $UnixTime
    )

    if ($null -eq $UnixTime) { return $null }
    return [DateTimeOffset]::FromUnixTimeSeconds([long] $UnixTime).UtcDateTime
}

function Get-ClaimValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [psobject] $Payload,

        [Parameter(Mandatory)]
        [string] $Name
    )

    $property = $Payload.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Test-JwtFormat {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Value
    )

    return $Value.Trim() -match '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$'
}

function ConvertFrom-JwtToken {
    <#
    .SYNOPSIS
    Decodes a JSON Web Token (JWT) without validating it.

    .DESCRIPTION
    Splits a JWT into its header and payload, decodes both, and classifies the
    token as an ID token, a delegated access token or an app-only access token.
    The signature is NOT validated. Decoding a token tells you what it claims,
    not whether it can be trusted.

    .PARAMETER Token
    The raw JWT, in compact serialization (header.payload.signature).

    .EXAMPLE
    Get-Content ./samples/id-token.jwt | ConvertFrom-JwtToken
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string] $Token
    )

    process {
        $raw = $Token.Trim()
        if ($raw -match '^Bearer\s+') { $raw = $raw -replace '^Bearer\s+', '' }
        if (-not (Test-JwtFormat -Value $raw)) {
            throw 'The value is not a JWT in compact serialization (header.payload.signature).'
        }

        $parts = $raw.Split('.')
        $utf8 = [System.Text.Encoding]::UTF8
        $header = $utf8.GetString((ConvertFrom-Base64Url -Value $parts[0])) | ConvertFrom-Json
        $payload = $utf8.GetString((ConvertFrom-Base64Url -Value $parts[1])) | ConvertFrom-Json

        $scp = Get-ClaimValue -Payload $payload -Name 'scp'
        $roles = Get-ClaimValue -Payload $payload -Name 'roles'
        $idtyp = Get-ClaimValue -Payload $payload -Name 'idtyp'
        $nonce = Get-ClaimValue -Payload $payload -Name 'nonce'
        $atHash = Get-ClaimValue -Payload $payload -Name 'at_hash'
        $aud = Get-ClaimValue -Payload $payload -Name 'aud'

        $kind = 'Unknown'
        # App-only tokens carry roles but no scp. In Microsoft Entra ID tokens, sub equals oid
        # for an application identity, while a user gets a pairwise sub. The optional idtyp
        # claim, when emitted, settles it.
        $sub = Get-ClaimValue -Payload $payload -Name 'sub'
        $oid = Get-ClaimValue -Payload $payload -Name 'oid'
        if ($idtyp -eq 'app' -or ($roles -and -not $scp -and $sub -and $sub -eq $oid)) {
            $kind = 'AppOnlyAccessToken'
        }
        elseif ($scp -or $roles) {
            $kind = 'AccessToken'
        }
        elseif ($nonce -or $atHash -or (Get-ClaimValue -Payload $payload -Name 'c_hash')) {
            $kind = 'IdToken'
        }
        elseif ((Get-ClaimValue -Payload $payload -Name 'preferred_username') -or (Get-ClaimValue -Payload $payload -Name 'email')) {
            $kind = 'IdToken'
        }

        [pscustomobject]@{
            PSTypeName = 'TokenAnatomy.Jwt'
            Kind       = $kind
            Audience   = $aud
            Header     = $header
            Payload    = $payload
            HasSignature = [bool] $parts[2]
            IssuedAt   = ConvertTo-UtcDate -UnixTime (Get-ClaimValue -Payload $payload -Name 'iat')
            NotBefore  = ConvertTo-UtcDate -UnixTime (Get-ClaimValue -Payload $payload -Name 'nbf')
            ExpiresOn  = ConvertTo-UtcDate -UnixTime (Get-ClaimValue -Payload $payload -Name 'exp')
        }
    }
}

function ConvertFrom-SamlResponse {
    <#
    .SYNOPSIS
    Decodes a SAML 2.0 response or assertion without validating it.

    .DESCRIPTION
    Accepts the SAMLResponse value captured from a browser POST (Base64, optionally
    URL-encoded) or raw XML. Returns the issuer, subject, audience, validity window
    and attributes. The XML signature is NOT validated.

    .PARAMETER SamlResponse
    Base64-encoded SAMLResponse, URL-encoded SAMLResponse, or raw XML.

    .EXAMPLE
    Get-Content ./samples/saml-response.b64 -Raw | ConvertFrom-SamlResponse
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string] $SamlResponse
    )

    process {
        $value = $SamlResponse.Trim()
        if ($value -match '%[0-9A-Fa-f]{2}') {
            $value = [System.Uri]::UnescapeDataString($value)
        }
        if ($value -match '^SAMLResponse=') {
            $value = $value.Substring('SAMLResponse='.Length)
        }

        if (-not $value.StartsWith('<')) {
            try {
                $value = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($value))
            }
            catch {
                throw 'The value is neither XML nor a Base64-encoded SAML response.'
            }
        }

        $settings = [System.Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($value), $settings)
        $xml = [System.Xml.XmlDocument]::new()
        $xml.PreserveWhitespace = $true
        $xml.Load($reader)
        $reader.Dispose()

        $ns = [System.Xml.XmlNamespaceManager]::new($xml.NameTable)
        $ns.AddNamespace('saml', 'urn:oasis:names:tc:SAML:2.0:assertion')
        $ns.AddNamespace('samlp', 'urn:oasis:names:tc:SAML:2.0:protocol')
        $ns.AddNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#')

        $assertion = $xml.SelectSingleNode('//saml:Assertion', $ns)
        if ($null -eq $assertion) {
            throw 'No SAML 2.0 assertion found. Encrypted assertions must be decrypted by the Service Provider first.'
        }

        $conditions = $assertion.SelectSingleNode('saml:Conditions', $ns)
        $attributes = [ordered]@{}
        foreach ($attribute in $assertion.SelectNodes('saml:AttributeStatement/saml:Attribute', $ns)) {
            $values = @($attribute.SelectNodes('saml:AttributeValue', $ns) | ForEach-Object { $_.InnerText })
            $attributes[$attribute.GetAttribute('Name')] = if ($values.Count -eq 1) { $values[0] } else { $values }
        }

        $notBefore = $null
        $notOnOrAfter = $null
        if ($conditions) {
            if ($conditions.GetAttribute('NotBefore')) { $notBefore = ([datetime] $conditions.GetAttribute('NotBefore')).ToUniversalTime() }
            if ($conditions.GetAttribute('NotOnOrAfter')) { $notOnOrAfter = ([datetime] $conditions.GetAttribute('NotOnOrAfter')).ToUniversalTime() }
        }

        [pscustomobject]@{
            PSTypeName   = 'TokenAnatomy.Saml'
            Kind         = 'SamlAssertion'
            Issuer       = $assertion.SelectSingleNode('saml:Issuer', $ns).InnerText
            NameId       = $assertion.SelectSingleNode('saml:Subject/saml:NameID', $ns).InnerText
            Audience     = @($assertion.SelectNodes('saml:Conditions/saml:AudienceRestriction/saml:Audience', $ns) | ForEach-Object { $_.InnerText })
            NotBefore    = $notBefore
            NotOnOrAfter = $notOnOrAfter
            Attributes   = $attributes
            ResponseSigned  = $null -ne $xml.SelectSingleNode('/samlp:Response/ds:Signature', $ns)
            AssertionSigned = $null -ne $assertion.SelectSingleNode('ds:Signature', $ns)
        }
    }
}

function Get-TokenAnatomy {
    <#
    .SYNOPSIS
    Answers one question about a token: who is it for?

    .DESCRIPTION
    Detects whether the input is a JWT (ID token or access token) or a SAML
    response, decodes it, and returns a uniform summary: protocol, token type,
    intended consumer, audience, issuer, subject, permissions and validity.
    Pipe several tokens and use Format-Table or Format-List to compare them.
    Nothing is validated: this is an inspection tool, not an authorization check.

    .PARAMETER Token
    A raw JWT, a "Bearer" header value, a Base64 SAMLResponse or SAML XML.

    .EXAMPLE
    Get-Content ./samples/id-token.jwt, ./samples/access-token.jwt | Get-TokenAnatomy | Format-List

    .EXAMPLE
    $tokens = ./scripts/Invoke-OidcSignIn.ps1 -TenantId $tenant -ClientId $app
    $tokens.IdToken, $tokens.AccessToken | Get-TokenAnatomy | Format-Table Type, IntendedFor, Audience
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string] $Token
    )

    process {
        $value = $Token.Trim()
        if (-not $value) { return }
        $now = [datetime]::UtcNow

        if (Test-JwtFormat -Value ($value -replace '^Bearer\s+', '')) {
            $jwt = ConvertFrom-JwtToken -Token $value
            $p = $jwt.Payload
            $aud = $jwt.Audience
            $notes = [System.Collections.Generic.List[string]]::new()

            switch ($jwt.Kind) {
                'IdToken' {
                    $type = 'OIDC ID token'
                    $intendedFor = "The client application ($aud)"
                    $notes.Add('Proves an authentication event to the client. Grants no permission. Never send it to an API.')
                }
                'AccessToken' {
                    $type = 'OAuth 2.0 access token (delegated)'
                    $intendedFor = "The API ($aud)"
                    $notes.Add('Issued for the API in aud. The client should treat it as opaque and only forward it.')
                }
                'AppOnlyAccessToken' {
                    $type = 'OAuth 2.0 access token (app-only)'
                    $intendedFor = "The API ($aud), no user involved"
                    $notes.Add('Client credentials flow: the application proved its own identity. No user was authenticated.')
                }
                default {
                    $type = 'JWT (unclassified)'
                    $intendedFor = "Whoever matches aud ($aud)"
                }
            }

            if ($aud -in $script:GraphAudiences) {
                $notes.Add('Microsoft Graph token: Graph validates it. Do not validate or parse it in your own code.')
            }
            if ($jwt.ExpiresOn -and $jwt.ExpiresOn -lt $now) {
                $notes.Add('Expired.')
            }

            $permissions = [System.Collections.Generic.List[string]]::new()
            $scp = Get-ClaimValue -Payload $p -Name 'scp'
            $roles = Get-ClaimValue -Payload $p -Name 'roles'
            if ($scp) { $permissions.Add("scp: $scp") }
            if ($roles) { $permissions.Add("roles: $(@($roles) -join ', ')") }

            $subject = Get-ClaimValue -Payload $p -Name 'preferred_username'
            if (-not $subject) { $subject = Get-ClaimValue -Payload $p -Name 'upn' }
            if (-not $subject) { $subject = Get-ClaimValue -Payload $p -Name 'oid' }
            if (-not $subject) { $subject = Get-ClaimValue -Payload $p -Name 'sub' }

            [pscustomobject]@{
                PSTypeName  = 'TokenAnatomy.Summary'
                Protocol    = if ($jwt.Kind -eq 'IdToken') { 'OpenID Connect' } else { 'OAuth 2.0' }
                Type        = $type
                IntendedFor = $intendedFor
                Audience    = $aud
                Issuer      = Get-ClaimValue -Payload $p -Name 'iss'
                Subject     = $subject
                ClientApp   = if (Get-ClaimValue -Payload $p -Name 'azp') { Get-ClaimValue -Payload $p -Name 'azp' } else { Get-ClaimValue -Payload $p -Name 'appid' }
                Permissions = if ($permissions.Count) { $permissions -join ' | ' } else { 'none' }
                ValidFrom   = $jwt.NotBefore
                ValidTo     = $jwt.ExpiresOn
                Notes       = $notes -join ' '
            }
            return
        }

        $saml = ConvertFrom-SamlResponse -SamlResponse $value
        $attributeSummary = @($saml.Attributes.GetEnumerator() | ForEach-Object {
                $shortName = ($_.Key -split '/')[-1]
                "${shortName}: $(@($_.Value) -join ', ')"
            }) -join ' | '

        $samlNotes = [System.Collections.Generic.List[string]]::new()
        $samlNotes.Add('Read by the application, which must validate the signature, issuer, audience and validity window.')
        if (-not ($saml.ResponseSigned -or $saml.AssertionSigned)) { $samlNotes.Add('No signature element found.') }
        if ($saml.NotOnOrAfter -and $saml.NotOnOrAfter -lt $now) { $samlNotes.Add('Expired.') }

        [pscustomobject]@{
            PSTypeName  = 'TokenAnatomy.Summary'
            Protocol    = 'SAML 2.0'
            Type        = 'SAML assertion'
            IntendedFor = "The application, Service Provider ($($saml.Audience -join ', '))"
            Audience    = $saml.Audience -join ', '
            Issuer      = $saml.Issuer
            Subject     = $saml.NameId
            ClientApp   = $null
            Permissions = if ($attributeSummary) { $attributeSummary } else { 'none' }
            ValidFrom   = $saml.NotBefore
            ValidTo     = $saml.NotOnOrAfter
            Notes       = $samlNotes -join ' '
        }
    }
}

Export-ModuleMember -Function ConvertFrom-JwtToken, ConvertFrom-SamlResponse, Get-TokenAnatomy
