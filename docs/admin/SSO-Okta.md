# Okta

This page sets up an Okta OIDC application for Goodnight Check. The examples use the
Okta Integrator Free Plan (formerly Developer Edition), but the steps are the same in
a paid org. For the generic OIDC/BFF behavior, see [Authentication](Authentication.md);
the environment variables are in
[Configuration → Authentication and sessions](Configuration.md#authentication-and-sessions).

Tested with the Okta Integrator Free Plan on 2026-11-09, using the default custom
authorization server.

## What Check needs

Check is a confidential OIDC client. It needs:

- the issuer URL of an Okta authorization server (the org authorization server, or a
  custom authorization server);
- a confidential OIDC application with the authorization-code flow and the exact
  callback URL;
- a claim in the ID token that carries the user's group or role names;
- the three Check roles: `admin`, `operator`, `viewer`. The Okta group names are
  yours; the `OIDC_*_GROUP` values map them to these roles.

The default mapping is a `groups` claim whose values are the Okta group names, mapped
by `OIDC_ADMIN_GROUP`, `OIDC_OPERATOR_GROUP` and `OIDC_VIEWER_GROUP`. This page uses
that default. A claim named `roles` works the same way: set `OIDC_ROLES_CLAIM=roles`
and use the Okta group names as the `OIDC_*_GROUP` values.

## 1. Create the groups

Create three groups for the Check roles. Their names are your choice; for example:

- `<your-admin-group>`
- `<your-operator-group>`
- `<your-viewer-group>`

Each name must match the corresponding `OIDC_ADMIN_GROUP`, `OIDC_OPERATOR_GROUP` or
`OIDC_VIEWER_GROUP` value exactly. If your directory already has groups for these
roles, use those names.

## 2. Create the users

For each person, **Directory → People → Add person**: enter the profile and activate
the account. Then **Groups → Assign** and add the person to the group for their Check
role.

For a first test, create one user per group. A user can be in more than one group;
Check stores every mapped role and the highest one decides access
(`admin` ⊃ `operator` ⊃ `viewer`).

## 3. Create the OIDC application

**Applications → Applications → Create App Integration**:

- Sign-in method: **OIDC - OpenID Connect**.
- Application type: **Web Application**.
- Name: `gn-check`, or your chosen name.

Then set:

- **Grant type**: Authorization Code. Clear Implicit and other grants unless you need
  them.
- **Sign-in redirect URIs**: the exact `OIDC_REDIRECT_URL`, for example
  `https://check.example.com/api/auth/callback`.
- **Sign-out redirect URIs**: your Check origin, for example
  `https://check.example.com/`.
- **Assignments**: assign the three groups (or the users) to the app.
- Save, then copy the **Client ID** and **Client secret** from the app's **General**
  tab.

Check sends the scopes in `OIDC_SCOPES`, by default `openid,profile,email`.

## 4. Add the groups claim

The claim must be in the ID token, with the group names Check maps. Use one of the
two routes below.

### Option A: org authorization server

1. Open the app and go to **Sign On**.
2. In **OpenID Connect ID Token**, click **Edit**.
3. Set **Groups claim type** to **Filter**.
4. Set the claim name `groups` and a filter that matches your three groups, for
   example **Matches regex** `check-.*`.
5. Save.
6. Add the `groups` scope to Check: set `OIDC_SCOPES` to
   `openid,profile,email,groups`.

Use the org issuer in Check: `https://<your-okta-domain>`.

### Option B: custom authorization server

Use this route if you need the claim in an access token, or if you want to manage
the claim through the Okta API. The default custom authorization server in an
Integrator Free Plan org may have no access policy; add one that includes the Check
client.

1. **Security → API → Authorization Servers → default** (or your custom
   authorization server).
2. **Claims → Add Claim**:
   - Name: `groups`
   - Include in token type: **ID Token**, **Always**
   - Value type: **Groups**
   - Filter: **Matches regex** `check-.*`
3. **Access Policies → Add Policy**, then add a rule that allows the Check client and
   the users or groups that sign in. A rule with **Authorization Code** as the grant
   type and the `openid` scope is enough.
4. Save.

Use the custom issuer in Check: `https://<your-okta-domain>/oauth2/default`.

Check reads the claim from the ID token. Do not create a second claim with the same
name.

## 5. Configure Check

Set these on the backend; the full list is in
[Configuration](Configuration.md#authentication-and-sessions).

| Variable | Set to |
|---|---|
| `APP_BASE_URL` | `https://check.example.com` |
| `OIDC_ISSUER` | `https://<your-okta-domain>` (Option A) or `https://<your-okta-domain>/oauth2/default` (Option B) |
| `OIDC_CLIENT_ID` | the Client ID from step 3 |
| `OIDC_CLIENT_SECRET` | the Client secret from step 3 |
| `OIDC_REDIRECT_URL` | `https://check.example.com/api/auth/callback` (the default is `APP_BASE_URL/api/auth/callback`) |
| `OIDC_SCOPES` | `openid,profile,email,groups` (Option A) or `openid,profile,email` (Option B) |
| `OIDC_ROLES_CLAIM` | `groups` |
| `OIDC_ADMIN_GROUP` | `<your-admin-group>` |
| `OIDC_OPERATOR_GROUP` | `<your-operator-group>` |
| `OIDC_VIEWER_GROUP` | `<your-viewer-group>` |
| `COOKIE_SECURE` | `true` (default; keep it for HTTPS) |
| `SESSION_TTL` | `12h` default, 15m to 24h |

Production uses TLS. The callback, `APP_BASE_URL` and the issuer must use the same
browser-visible origin.

## 6. Verify the token

Sign in with one user of each group. Check the roles:

- the SPA shows the user and the navigation for the role;
- `GET /api/auth/me` returns the mapped roles;
- the ID token's `groups` claim contains the Okta group names (decode it with any JWT
  decoder; do not send the token to a third party).

If the claim is missing, check the route you chose: Option A needs the `groups` scope
in `OIDC_SCOPES`; Option B needs the claim on the authorization server that
`OIDC_ISSUER` names.

## Troubleshooting

- **The Okta sign-in page returns to itself, or the app shows no groups.** Check that
  the redirect URI is exactly `OIDC_REDIRECT_URL`, and that the app is assigned to
  the user or their group.
- **The token has no `groups` claim.** For Option A, add the `groups` scope and
  confirm the app's Sign On groups claim. For Option B, confirm the claim is on the
  authorization server in `OIDC_ISSUER` and is included in the ID token.
- **Okta rejects the sign-in with a policy error.** Okta's app sign-on policy still
  applies. The Integrator Free Plan defaults to two factors; the test user needs a
  passkey, or a policy that allows password-only for the test groups.
- **`OIDC_ISSUER` mismatch.** Use the org issuer for Option A and the custom
  authorization server issuer for Option B. The token's `iss` claim must match
  `OIDC_ISSUER`.
