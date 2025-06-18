# JWT Token Generation Node Server

---

## Features
- Generate JWT tokens (user and guest)
- OIDC metadata endpoint
- JWKS endpoint for public key discovery
- Userinfo endpoint (dummy)
- PEM public/private key endpoints
- Info page (renders this README as HTML)

---


## ServiceNow IdP Integration Example

1. Go to **Multi-Provider SSO → Identity Provider**.
2. Click **New**.
3. Select **OpenID Connect**.
4. Fill in:
   - **Name:** `JWT Idp`
   - **Client ID:** `embeddables_token`
   - **Client Secret:** `12345678`
   - **Well Known Configuration URL:** `http://localhost:3000/.well-known/openid-configuration`

---


