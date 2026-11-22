# Lab 02 - SAML 2.0: capture and read a real assertion

**Goal:** configure SAML single sign-on (SSO) for the Microsoft Entra SAML Toolkit test application, capture the SAML response that your browser posts to it, and read what the application receives.

**Time:** about 20 minutes.

**You need:**

- A Microsoft Entra ID tenant and a role of at least Cloud Application Administrator
- A test user assigned to the application
- A browser with developer tools
- PowerShell 7.2 or later

## 1. Configure the Microsoft Entra SAML Toolkit

Follow the official tutorial, it takes a few minutes: [Configure Microsoft Entra SAML Toolkit for single sign-on](https://learn.microsoft.com/entra/identity/saas-apps/saml-toolkit-tutorial).

In short:

1. **Entra ID** > **Enterprise apps** > **New application**, add **Microsoft Entra SAML Toolkit** from the gallery.
2. **Single sign-on** > **SAML**. Set the Reply URL (ACS (Assertion Consumer Service) URL) and the Sign on URL given in the tutorial.
3. Download the **Certificate (Raw)**.
4. Register on the toolkit site, create the SAML configuration with the Login URL, the Microsoft Entra Identifier and the certificate.
5. Assign your test user to the enterprise application.

Optional: under **Attributes and Claims**, add a group claim or an app role. You will see it in the assertion.

## 2. Capture the SAML response

1. Open a private browser window and the developer tools (F12), **Network** tab.
2. Enable **Preserve log**.
3. Browse to the toolkit sign-on URL and sign in with the test user.
4. In the network list, find the `POST` request to the ACS URL, ending in `/SAML/Consume`.
5. Open **Payload** (or **Request**), and copy the value of `SAMLResponse`.

The browser is only the courier. It posts the assertion to the application, which is the one that reads and validates it.

## 3. Read it

```powershell
Import-Module ./src/TokenAnatomy.psd1
$samlResponse = Get-Clipboard -Raw

$samlResponse | Get-TokenAnatomy | Format-List
$samlResponse | ConvertFrom-SamlResponse | Select-Object -ExpandProperty Attributes
```

Both the raw Base64 value and the URL-encoded value are accepted.

What to observe:

- **Audience:** the toolkit's Entity ID. The assertion is for this application and no other.
- **Issuer:** `https://sts.windows.net/<tenant-id>/`, your tenant.
- **NameId:** the user, in the format configured for the application.
- **NotBefore / NotOnOrAfter:** a short validity window. A replayed assertion is rejected after it.
- **Attributes:** display name, email, and any group or role claims. Applications use them for authorization, so "SAML is identity only" is a myth.
- **Signature:** present. The application must validate it with the certificate you uploaded.

## 4. Compare with lab 01

```powershell
$samlResponse, $tokens.IdToken, $tokens.AccessToken | Get-TokenAnatomy | Format-Table Protocol, Type, IntendedFor -Wrap
```

SAML and the OIDC ID token both say who signed in, to an application. Only the access token is for an API.

## 5. Clean up

Delete the **Microsoft Entra SAML Toolkit** enterprise application and the test user if you created one for this lab.

## Safety notes

- A captured SAML response is a credential until `NotOnOrAfter`. Do not share it, even expired, if it contains real names or group IDs.
- Do not commit captures. The repository `.gitignore` excludes a `captures/` folder for that purpose.
- `ConvertFrom-SamlResponse` does not validate the signature. It refuses DTDs (Document Type Definitions) to stay safe with untrusted XML.
- Encrypted assertions can only be read by the application that holds the decryption key.
