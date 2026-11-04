# Identity

Mandat needs to know **which person** an agent acts for, and which person approved an action. It doesn't run its own login system; it trusts your **identity provider** through standard OpenID Connect: Auth0, Okta, Microsoft Entra ID, Keycloak and others.

By default, `mandat init` turns on a **test login** (dev IdP) that accepts any name. That's useful locally, but anyone can claim to be anyone. Turn it off before real use.

## Connect an identity provider (Auth0 example)

**1. Create an application** (Auth0 Dashboard → Applications → *Create Application*)
- **Type:** *Native*. The CLI can't keep a secret, so PKCE protects the login instead.
- **Allowed Callback URLs:** `http://127.0.0.1:8765/callback` for `mandat login`, plus `https://<control-plane>/auth/callback` for console sign-in. Separate them with a comma.
- **Grant types:** *Authorization Code* and *Refresh Token* (on by default for Native apps).
- **Leave "third party" off;** this is your own application.
- **Copy the Domain and Client ID.**

**2. Trust it on the control plane**, then restart `mandat serve`:

```bash
mandat idp add --issuer https://YOUR_DOMAIN/ --client-id YOUR_CLIENT_ID --disable-dev-idp
# Auth0 Organizations: add --tenant-claim org_id
```

The issuer must include `https://` and, for Auth0, end with a slash. A bare domain also works.

## Agents act for signed-in users

```bash
mandat login --issuer https://YOUR_DOMAIN/ --client-id YOUR_CLIENT_ID   # opens the browser once
mandat login status
```

The session is stored in `~/.mandat/session.json` (mode 0600) and refreshed automatically when the provider issues a refresh token. Then use `--login` in the bridge ([Connect agents](agents.md)).

Every call is then attributed to the real user (for example `auth0|…`, with their e-mail and organisation). The token exchange accepts only ID tokens from the trusted issuer **issued to that client ID**.

## Approvers and admins sign in

Signing in proves who someone is. What they may do is an explicit grant:

```bash
mandat users grant --email you@example.com --roles admin,approver
mandat users grant --email colleague@example.com --roles approver
mandat users list
mandat users revoke colleague@example.com
```

- **Console:** click **Sign in with <your-provider>**. The session is an HttpOnly, SameSite=Strict cookie valid for 8 hours.
- **CLI:** add `--login`, for example `mandat approvals approve apr_… --login`.
- **Self-approval is refused.** It's checked against every verified identifier of the approver (IdP subject and e-mail).
- **Test-login tokens are never accepted** as a person's credential.

API keys still work for automation and scripts.
