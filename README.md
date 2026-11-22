# token-anatomy

**Who is the token for?** Decode SAML (Security Assertion Markup Language) responses, OpenID Connect (OIDC) ID tokens and OAuth 2.0 access tokens with PowerShell, and see at a glance which party each one is meant for.

[![CI](https://github.com/Solisys-Cloud/token-anatomy/actions/workflows/ci.yml/badge.svg)](https://github.com/Solisys-Cloud/token-anatomy/actions/workflows/ci.yml)

Companion repository of the article [SAML vs OAuth 2.0 vs OpenID Connect: Who Is the Token For?](https://www.solisys.be/blog/saml-oauth-oidc-who-is-the-token-for/)

## Why

SAML, OAuth 2.0 and OpenID Connect are often presented as three ways to sign in. Only two of them authenticate. The fastest way to tell them apart is to read the audience of the token:

| Token | Protocol | Meant for | Answers |
|---|---|---|---|
| SAML assertion | SAML 2.0 | The application (Service Provider) | Who are you? |
| ID token | OpenID Connect | The client application | Who are you? |
| Access token | OAuth 2.0 | The API (Application Programming Interface) | What can this app do on your behalf? |

## What is inside

| Path | Content |
|---|---|
| `src/` | `TokenAnatomy` PowerShell module: `Get-TokenAnatomy`, `ConvertFrom-JwtToken`, `ConvertFrom-SamlResponse` |
| `scripts/Invoke-OidcSignIn.ps1` | OIDC sign-in against your own Microsoft Entra ID tenant: authorization code with PKCE (Proof Key for Code Exchange), loopback redirect, state and nonce checks |
| `samples/` | Fictitious tokens: ID token, delegated access token, app-only access token, SAML response |
| `labs/` | Two hands-on labs with Microsoft Entra ID |
| `tests/` | Pester tests, run by GitHub Actions on Windows and Linux |

## Quick start

Requires PowerShell 7.2 or later. No Azure subscription or tenant needed for the samples.

```powershell
git clone https://github.com/Solisys-Cloud/token-anatomy.git
cd token-anatomy
Import-Module ./src/TokenAnatomy.psd1

Get-ChildItem ./samples/*.jwt, ./samples/saml-response.b64 |
    ForEach-Object { Get-Content $_.FullName -Raw } |
    Get-TokenAnatomy |
    Format-Table Type, IntendedFor, Permissions -Wrap
```

Output:

```text
Type                               IntendedFor                                                      Permissions
----                               -----------                                                      -----------
OAuth 2.0 access token (delegated) The API (99999999-8888-7777-6666-555555555555)                   scp: Orders.Read | roles: Orders.Approver
OAuth 2.0 access token (app-only)  The API (99999999-8888-7777-6666-555555555555), no user involved roles: Orders.Sync
OIDC ID token                      The client application (11111111-2222-3333-4444-555555555555)    none
SAML assertion                     The application, Service Provider (https://app.contoso.com/saml) displayname: Alice Martin | role: Finance.Approver | groups: ...
```

Inspect one token in detail:

```powershell
Get-Content ./samples/id-token.jwt -Raw | ConvertFrom-JwtToken | Select-Object -ExpandProperty Payload
Get-Content ./samples/saml-response.b64 -Raw | ConvertFrom-SamlResponse | Format-List
```

## Labs

| Lab | You will | Time |
|---|---|---|
| [01 - OpenID Connect sign-in](labs/01-oidc-sign-in.md) | Sign in once, get an ID token and an access token, see two audiences, call Microsoft Graph with the right one | 15 min |
| [02 - SAML 2.0 assertion](labs/02-saml-toolkit.md) | Configure the Microsoft Entra SAML Toolkit, capture the assertion your browser posts, read its audience and attributes | 20 min |

## How the classification works

`Get-TokenAnatomy` reads the claims, it does not guess from the format alone:

| Signal | Classified as |
|---|---|
| SAML `Assertion` element | SAML assertion, for the Service Provider in `Audience` |
| `idtyp` is `app`, or `roles` without `scp` and `sub` equal to `oid` | App-only access token (client credentials flow) |
| `scp` or `roles` present | Delegated access token, for the API in `aud` |
| `nonce`, `at_hash` or `c_hash` present, or a user name claim without permissions | ID token, for the client application in `aud` |

## Important

- **Decoding is not validating.** This module reads tokens. It never checks signatures. In an application, validate tokens with a maintained library such as MSAL (Microsoft Authentication Library) or Microsoft.IdentityModel.
- **Tokens are credentials.** Do not paste real tokens into online decoders, tickets or chats. Do not commit them: the `captures/` folder is ignored by Git for that purpose.
- **Microsoft Graph tokens are for Graph.** Do not build logic on their content.
- XML parsing refuses DTDs (Document Type Definitions) to stay safe with untrusted input.

## References

- IETF (Internet Engineering Task Force), [RFC 6749: The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749)
- IETF, [RFC 7636: Proof Key for Code Exchange](https://www.rfc-editor.org/rfc/rfc7636)
- IETF, [RFC 8252: OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252)
- OpenID Foundation, [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- OASIS, [SAML 2.0 Technical Overview](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html)
- Microsoft Learn, [ID tokens](https://learn.microsoft.com/entra/identity-platform/id-tokens) and [Access tokens](https://learn.microsoft.com/entra/identity-platform/access-tokens)

## License

[MIT](LICENSE)

Maintained by Olivier Lumeau, Solisys SRL.
