# Lab 01 - OpenID Connect sign-in: one sign-in, two tokens

**Goal:** sign in once with OpenID Connect (OIDC) against your own Microsoft Entra ID tenant, receive an ID token and an access token, and prove that they are meant for two different consumers.

**Time:** about 15 minutes.

**You need:**

- A Microsoft Entra ID tenant where you can register an application (a lab or developer tenant is ideal)
- PowerShell 7.2 or later
- Optional: Azure CLI (Command-Line Interface), for step 1

## 1. Register a public client application

The script behaves like a desktop application: it cannot keep a secret, so it is a **public client** and it uses PKCE (Proof Key for Code Exchange) instead.

**Option A, Azure CLI:**

```powershell
az login --tenant <your-tenant-id>
$app = az ad app create `
    --display-name 'token-anatomy-lab' `
    --sign-in-audience AzureADMyOrg `
    --public-client-redirect-uris 'http://localhost' | ConvertFrom-Json
$app.appId
```

**Option B, Microsoft Entra admin center:**

1. **Entra ID** > **App registrations** > **New registration**.
2. Name: `token-anatomy-lab`. Supported account types: **this organizational directory only**.
3. Redirect URI: platform **Public client/native (mobile and desktop)**, value `http://localhost`.
4. Select **Register** and copy the **Application (client) ID**.

Why `http://localhost` without a port? Microsoft Entra ID ignores the port of a localhost redirect URI, as RFC (Request for Comments) 8252 recommends for native apps. The script picks a free port at random and the URI still matches. See [Redirect URI restrictions](https://learn.microsoft.com/entra/identity-platform/reply-url#localhost-exceptions).

Microsoft Graph `User.Read` is the only API permission used. Users can usually consent to it themselves. If user consent is disabled in your tenant, grant admin consent on the app registration.

## 2. Sign in

```powershell
Import-Module ./src/TokenAnatomy.psd1
$tokens = ./scripts/Invoke-OidcSignIn.ps1 -TenantId '<your-tenant-id>' -ClientId '<application-client-id>'
```

Your browser opens on the Microsoft Entra ID sign-in page. MFA (multifactor authentication) and Conditional Access apply as usual. When the browser says "Sign-in complete", return to PowerShell.

What happened under the hood:

| Step | Who | What |
|---|---|---|
| 1 | Script | Generates `code_verifier`, `code_challenge` (SHA-256), `state` and `nonce` |
| 2 | Browser | Calls `/authorize` with `scope=openid profile email User.Read` |
| 3 | Entra ID | Authenticates you and redirects to `http://localhost:<port>` with a code |
| 4 | Script | Checks `state`, redeems the code with the `code_verifier` at `/token` |
| 5 | Script | Checks that the `nonce` in the ID token matches the one it sent |

## 3. Ask each token who it is for

```powershell
$tokens.IdToken, $tokens.AccessToken | Get-TokenAnatomy | Format-List Type, IntendedFor, Audience, ClientApp, Permissions, Notes
```

What to observe:

- **ID token:** `aud` is your application's client ID. No `scp`, no `roles`: it grants nothing. It is proof, for your application, that you signed in.
- **Access token:** `aud` is Microsoft Graph, not your application. `scp` contains `User.Read`. Your application only carries it to Graph.

Same sign-in, two audiences. That is the whole difference between authentication and delegated authorization.

## 4. Use each token where it belongs

```powershell
# Correct: the access token goes to the API it was issued for.
Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/me' -Headers @{ Authorization = "Bearer $($tokens.AccessToken)" } |
    Select-Object displayName, userPrincipalName

# Wrong on purpose: the ID token is not for Graph. Expect 401 Unauthorized.
try {
    Invoke-RestMethod -Uri 'https://graph.microsoft.com/v1.0/me' -Headers @{ Authorization = "Bearer $($tokens.IdToken)" }
}
catch {
    "Graph refused the ID token: $($_.Exception.Response.StatusCode)"
}
```

## 5. Clean up

```powershell
Remove-Variable tokens
az ad app delete --id <application-client-id>
```

Or delete the app registration in the admin center.

## Safety notes

- Tokens are credentials until they expire. Never paste real tokens into online decoders, tickets or chats.
- `Get-TokenAnatomy` decodes tokens. It does not validate signatures. In an application, validate tokens with a maintained library such as MSAL (Microsoft Authentication Library) or Microsoft.IdentityModel.
- Microsoft Graph access tokens are meant for Graph only. Do not build logic on their content.
