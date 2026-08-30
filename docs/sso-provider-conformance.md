# SSO provider conformance

Dockyard supports OpenID Connect authorization-code login with PKCE and nonce
binding, plus signed SAML 2.0 SP- and IdP-initiated login. Treat a provider as
production-ready only after completing this checklist in an isolated
organization and preserving the results with the release evidence.

OIDC and SAML configuration can be managed with the corresponding
`dockyard_*_provider` Terraform/OpenTofu resources or dedicated `dockyardctl`
commands. SAML signing-certificate rollover remains an explicit begin,
IdP-import, and promote sequence; do not model promotion as an automatic
Terraform update.

The SAML CLI lifecycle is `saml-providers`, `create-saml-provider JSON`,
`update-saml-provider ID JSON`, `enable-saml-provider ID`, and
`disable-saml-provider ID`. Certificate rollover uses
`rotate-saml-certificate ID`, then `promote-saml-certificate ID PROVIDER_NAME`
after the IdP imports the replacement, or `cancel-saml-certificate ID` to abort.
Pass `-` instead of JSON when metadata should not appear in shell history.

The OIDC redirect URI is:

```text
https://dockyard.example.com/v1/auth/sso/callback
```

Use `openid profile email` scopes. Dockyard accepts the signed `email` claim
only when `email_verified` is explicitly true. When `email` is absent, it can
use the standard signed `preferred_username` claim for providers such as Entra.
The resulting address must match an allowed organization domain. Domain
allowlists accept only normalized DNS names—never wildcards, ports, URL
components, single-label names, or malformed labels.

## Microsoft Entra ID

Create a single-tenant web application registration and use this issuer, with
the tenant UUID substituted:

```text
https://login.microsoftonline.com/TENANT_ID/v2.0
```

Do not use `common`, `organizations`, or `consumers`: a tenant-specific issuer
is required to keep the trust boundary explicit. Configure the redirect URI as
a Web URI and create a client secret. Entra workforce tokens may omit `email`;
Dockyard accepts an email-shaped `preferred_username` after signature, issuer,
audience, nonce, and allowed-domain validation.

## Okta

Create an OIDC Web Application using an organization authorization server or a
dedicated custom authorization server. Example issuers are:

```text
https://example.okta.com
https://example.okta.com/oauth2/default
```

Assign only the conformance users and ensure the ID token contains `email` and
`email_verified`. Configure the Dockyard callback as the sign-in redirect URI.

## Google Workspace

Create an OAuth 2.0 Web application and use:

```text
https://accounts.google.com
```

Configure the Dockyard callback as an authorized redirect URI. Restrict access
to the Workspace organization in Google and configure the same Workspace
domain in Dockyard; Dockyard independently checks the signed email address
against that allowed domain.

## Required evidence

For every configured provider, verify and record:

1. discovery and authorization-code login complete over TLS;
2. PKCE, state-cookie binding, nonce validation, and callback replay rejection;
3. JIT provisioning assigns the configured non-owner default role;
4. an unverified email and an email outside the allowed domains are rejected;
5. disabled providers cannot start or complete login;
6. sessions are bound to the intended organization;
7. two organizations using the same email remain tenant-isolated;
8. mandatory SSO and the documented owner break-glass procedure both work.

For SAML-capable providers, additionally import Dockyard's generated service
provider metadata, require signed assertions, test both supported initiation
modes, and prove assertion replay is rejected. Keycloak automation is available
through `make test-keycloak-sso`; Entra ID, Okta, and Google Workspace require
operator-owned tenants and must not be represented as passed until those runs
are completed.
