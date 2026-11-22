<#
.SYNOPSIS
Signs in to Microsoft Entra ID with OpenID Connect (authorization code with PKCE)
and returns the ID token and the access token.

.DESCRIPTION
Runs the same flow as a modern native application:
  1. Generates a code_verifier, its SHA-256 code_challenge, a state and a nonce.
  2. Opens the browser on the /authorize endpoint with the openid scope.
  3. Receives the authorization code on a loopback redirect URI (http://localhost).
  4. Redeems the code with the code_verifier at the /token endpoint.
  5. Checks the state and the nonce, then returns both tokens.

Tokens are returned in memory only. Nothing is written to disk.
Treat them as credentials: do not paste them into online decoders or commit them.

Prerequisites, see labs/01-oidc-sign-in.md:
  - An app registration with the "Mobile and desktop applications" platform
    and the redirect URI http://localhost
  - The delegated permission User.Read on Microsoft Graph (default)

.PARAMETER TenantId
Directory (tenant) ID or verified domain of your Microsoft Entra ID tenant.

.PARAMETER ClientId
Application (client) ID of the app registration.

.PARAMETER Scope
Scopes to request. "openid" is what turns an OAuth 2.0 request into an
OpenID Connect request. Default: openid profile email User.Read

.PARAMETER Port
Loopback port for the redirect URI. Default: a free port chosen at random.

.PARAMETER TimeoutSeconds
How long to wait for the browser sign-in. Default: 180.

.EXAMPLE
$tokens = ./scripts/Invoke-OidcSignIn.ps1 -TenantId contoso.onmicrosoft.com -ClientId 11111111-2222-3333-4444-555555555555
$tokens.IdToken, $tokens.AccessToken | Get-TokenAnatomy | Format-List
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $TenantId,

    [Parameter(Mandatory)]
    [string] $ClientId,

    [string[]] $Scope = @('openid', 'profile', 'email', 'User.Read'),

    [ValidateRange(1024, 65535)]
    [int] $Port,

    [ValidateRange(30, 900)]
    [int] $TimeoutSeconds = 180
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-RandomBase64Url {
    param([int] $ByteCount = 32)
    $bytes = [byte[]]::new($ByteCount)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $freePort = ([System.Net.IPEndPoint] $listener.LocalEndpoint).Port
    $listener.Stop()
    return $freePort
}

function Get-JwtClaim {
    param([string] $Jwt, [string] $Name)
    $segment = $Jwt.Split('.')[1].Replace('-', '+').Replace('_', '/')
    switch ($segment.Length % 4) { 2 { $segment += '==' } 3 { $segment += '=' } }
    $payload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($segment)) | ConvertFrom-Json
    $property = $payload.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

if (-not $Port) { $Port = Get-FreeTcpPort }

# Microsoft Entra ID ignores the port of an http://localhost redirect URI for
# public client applications, so http://localhost is the only URI to register.
$redirectUri = "http://localhost:$Port"
$authority = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0"

# PKCE (Proof Key for Code Exchange), state and nonce.
$codeVerifier = Get-RandomBase64Url -ByteCount 32
$challengeBytes = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::ASCII.GetBytes($codeVerifier))
$codeChallenge = [Convert]::ToBase64String($challengeBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$state = Get-RandomBase64Url -ByteCount 16
$nonce = Get-RandomBase64Url -ByteCount 16
$scopeString = $Scope -join ' '

$query = [ordered]@{
    client_id             = $ClientId
    response_type         = 'code'
    redirect_uri          = $redirectUri
    response_mode         = 'query'
    scope                 = $scopeString
    state                 = $state
    nonce                 = $nonce
    code_challenge        = $codeChallenge
    code_challenge_method = 'S256'
    prompt                = 'select_account'
}
$queryString = ($query.GetEnumerator() | ForEach-Object { "$($_.Key)=$([Uri]::EscapeDataString($_.Value))" }) -join '&'
$authorizeUrl = "$authority/authorize?$queryString"

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("$redirectUri/")
$listener.Start()

try {
    Write-Verbose "Listening on $redirectUri"
    Write-Information "Opening the browser for sign-in. Waiting up to $TimeoutSeconds seconds." -InformationAction Continue
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new($authorizeUrl)
    $startInfo.UseShellExecute = $true
    [void] [System.Diagnostics.Process]::Start($startInfo)

    $contextTask = $listener.GetContextAsync()
    if (-not $contextTask.Wait([TimeSpan]::FromSeconds($TimeoutSeconds))) {
        throw "No response from the browser within $TimeoutSeconds seconds."
    }
    $context = $contextTask.Result
    $params = [System.Web.HttpUtility]::ParseQueryString($context.Request.Url.Query)

    $html = '<html><body style="font-family:sans-serif"><h3>Sign-in complete.</h3><p>You can close this window and return to PowerShell.</p></body></html>'
    if ($params['error']) {
        $html = '<html><body style="font-family:sans-serif"><h3>Sign-in failed.</h3><p>Return to PowerShell for details.</p></body></html>'
    }
    $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
    $context.Response.ContentType = 'text/html; charset=utf-8'
    $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
    $context.Response.Close()
}
finally {
    $listener.Stop()
    $listener.Close()
}

if ($params['error']) {
    throw "Authorization error: $($params['error']). $($params['error_description'])"
}
if ($params['state'] -ne $state) {
    throw 'State mismatch: the response does not belong to this sign-in request.'
}

$tokenResponse = Invoke-RestMethod -Method Post -Uri "$authority/token" -ContentType 'application/x-www-form-urlencoded' -Body @{
    client_id     = $ClientId
    grant_type    = 'authorization_code'
    code          = $params['code']
    redirect_uri  = $redirectUri
    code_verifier = $codeVerifier
    scope         = $scopeString
}

if (-not $tokenResponse.id_token) {
    throw 'No ID token returned. Check that the openid scope was requested.'
}
if ((Get-JwtClaim -Jwt $tokenResponse.id_token -Name 'nonce') -ne $nonce) {
    throw 'Nonce mismatch: the ID token was not issued for this sign-in request.'
}

[pscustomobject]@{
    IdToken     = $tokenResponse.id_token
    AccessToken = $tokenResponse.access_token
    Scope       = $tokenResponse.scope
    ExpiresIn   = $tokenResponse.expires_in
}
