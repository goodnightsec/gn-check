# Keycloak

This page sets up a production Keycloak realm for Goodnight Check. The Compose stack's `nsc` realm is
a development fixture: it has the same shape (groups, the group-membership mapper, demo users) but it
is not a production configuration. For the generic OIDC/BFF behavior, see
[Authentication](Authentication.md); the environment variables are in
[Configuration → Authentication and sessions](Configuration.md#authentication-and-sessions).

Tested with Keycloak 26.8.

## What Check needs

Check is a confidential OIDC client. It needs:

- a browser-visible realm issuer URL and, if the backend reaches Keycloak on another address, an
  internal discovery URL;
- a confidential client with the standard authorization-code flow and the exact callback URL;
- a claim in the ID token that carries the user's group or role names;
- the three Check roles: `admin`, `operator`, `viewer`. The IdP group names are yours; the
  `OIDC_*_GROUP` values map them to these roles.

The default mapping is a `groups` claim whose values are the IdP group names, mapped by
`OIDC_ADMIN_GROUP`, `OIDC_OPERATOR_GROUP` and `OIDC_VIEWER_GROUP`. This page uses that default.
A realm that puts roles into a `roles` claim works the same way: set `OIDC_ROLES_CLAIM=roles` and
use the IdP role names as the `OIDC_*_GROUP` values.

## 1. Create the realm

1. Sign in to the Keycloak admin console.
2. **Realm settings → Create realm**; name it, for example, `goodnight-check`.
3. Set the browser-visible issuer. The backend's `OIDC_ISSUER` is the realm URL:
   `https://keycloak.example.com/realms/goodnight-check`. Set Keycloak's hostname to the same
   browser-visible URL; behind a reverse proxy, configure the proxy headers as well.
4. If the backend reaches Keycloak at a different address (for example `http://keycloak:8080` in a
   container network), keep `OIDC_ISSUER` as the browser-visible URL and set
   `OIDC_DISCOVERY_URL` to the internal realm URL.

Production uses TLS. Set `COOKIE_SECURE=true` (the default) and serve Check over HTTPS; the callback
and the issuer must use the same browser-visible origin.

## 2. Create the groups

Create three groups for the Check roles. Their names are your choice; for example:

- `<your-admin-group>`
- `<your-operator-group>`
- `<your-viewer-group>`

Each name must match the corresponding `OIDC_ADMIN_GROUP`, `OIDC_OPERATOR_GROUP` or
`OIDC_VIEWER_GROUP` value exactly. If your directory already has groups for these roles, use those
names. If you use nested groups, either keep the mapper's **Full group path** off (the claim carries
the last segment) or set the `OIDC_*_GROUP` values to the full path (for example
`/teams/check-admins`).

## 3. Create the users

For each person, **Users → Add user**: username, email, first/last name, email verified as your
policy requires. Set a password under **Credentials**. Then **Groups → Join group** and add the user
to the group you chose for their Check role.

For a first test, create one user per group. A user can be in more than one group; Check stores every
mapped role and the highest one decides access (`admin` ⊃ `operator` ⊃ `viewer`).

## 4. Create the client

**Clients → Create client**:

- Client ID: `gn-check`, or your chosen `OIDC_CLIENT_ID`.
- Client authentication: **On** (confidential client).
- Standard flow: **On**. Direct access grants and service accounts: off unless you need them.
- Valid redirect URIs: the exact `OIDC_REDIRECT_URL`, for example
  `https://check.example.com/api/auth/callback`.
- Web origins: the Check origin, for example `https://check.example.com`.
- Save, then copy the client secret from **Credentials**.

Check sends the scopes in `OIDC_SCOPES`, by default `openid,profile,email`. Add any additional scopes
your realm requires. The group claim is added in the next step.

## 5. Add the groups claim

The claim must be in the ID token, with the group names Check maps. In the client:

1. **Client scopes → `<client-id>-dedicated` → Mappers → Add mapper → By configuration → Group Membership**.
   The dedicated scope belongs to the client, so it is always requested. A separate client scope
   works too if it is assigned as a default scope.
2. Set:
   - Name: `groups`
   - Token Claim Name: `groups`
   - Full group path: **Off** (so the claim is the group name, not the full path)
   - Add to ID token: **On**
   - Add to access token: **On** (optional; Check reads the ID token)
   - Add to userinfo: **On** (optional)
3. Save.

The default `OIDC_ROLES_CLAIM=groups` reads this claim. If your realm already has a `groups` claim
with full paths, keep **Full group path** off or set the `OIDC_*_GROUP` values to those paths.

To inspect the result: **Clients → `gn-check` → Client scopes → Evaluate**, select a user, and open
the generated ID token. The `groups` claim must contain the expected name.

## 6. Configure Check

Set these on the backend; the full list is in
[Configuration](Configuration.md#authentication-and-sessions).

| Variable | Set to |
|---|---|
| `APP_BASE_URL` | `https://check.example.com` |
| `OIDC_ISSUER` | `https://keycloak.example.com/realms/goodnight-check` |
| `OIDC_DISCOVERY_URL` | `http://keycloak:8080/realms/goodnight-check` if the backend uses an internal address; otherwise omit |
| `OIDC_CLIENT_ID` | `gn-check` |
| `OIDC_CLIENT_SECRET` | the client secret from step 4 |
| `OIDC_REDIRECT_URL` | `https://check.example.com/api/auth/callback` (the default is `APP_BASE_URL/api/auth/callback`) |
| `OIDC_SCOPES` | `openid,profile,email` |
| `OIDC_ROLES_CLAIM` | `groups` |
| `OIDC_ADMIN_GROUP` | `<your-admin-group>` from step 2 |
| `OIDC_OPERATOR_GROUP` | `<your-operator-group>` from step 2 |
| `OIDC_VIEWER_GROUP` | `<your-viewer-group>` from step 2 |
| `COOKIE_SECURE` | `true` (default; keep it for HTTPS) |
| `SESSION_TTL` | `12h` default, 15m to 24h |

The built-in defaults for the group values are `admin`, `operator` and `viewer`; set them to your
group names unless your directory uses those names.

Restart the backend after changing the environment. Keep `APP_BASE_URL`, `OIDC_ISSUER` and the
registered redirect URI on the same browser-visible origin; `localhost` and `127.0.0.1` are not
interchangeable.

## 7. Verify

1. Open Check at `APP_BASE_URL` and sign in as each test user.
2. Check the role: signing in as the admin user shows the admin navigation (for example **Admin**);
   an operator can create scans and change configuration; a viewer has read-only access.
   `GET /api/auth/me` returns the mapped roles for the session.
3. In Keycloak, the **Evaluate** view shows the `groups` claim; if its value does not match the
   `OIDC_*_GROUP` value (for example `/teams/check-admins` while the env has `check-admins`), fix
   **Full group path** or the `OIDC_*_GROUP` values.
4. A role change is read at the next login. To cut a live session short, an admin can revoke it under
   **Admin → Sessions**; see
   [Authentication → Session revocation](Authentication.md#session-revocation-and-privilege-revocation-latency).

The Compose development realm (`deploy/keycloak/realm-nsc.json`) uses this same client shape with
the demo group names `admin`, `operator`, `viewer` (an example, not a requirement), the
group-membership mapper with the full path off, and demo users `admin`/`operator`/`viewer` with
the username as password. It is useful for trying the steps; do not use its credentials in
production.

## Troubleshooting

- **Login loop, or the callback fails:** `APP_BASE_URL`, `OIDC_ISSUER` and the registered redirect
  URI must use the same browser-visible origin. Use `OIDC_DISCOVERY_URL` only for internal metadata.
  See [Troubleshooting](Troubleshooting.md).
- **Signed in with no role:** the `groups` claim is missing or the names do not match. Check the
  client's Group Membership mapper, that the user is in the mapped group, and that the claim value
  matches the `OIDC_*_GROUP` value exactly (for example, `/teams/check-admins` vs `check-admins`).
- **`401`/`403` after login:** the session maps roles at login. Check `/api/auth/me`, the claim, and
  the role-gated page; a changed group takes effect at the next login.
- **Token has no groups claim:** the mapper is on a client scope that is not assigned as a default
  scope, or it is not added to the ID token. Use the client's dedicated scope or assign the scope.
- **The user cannot sign in:** the client is confidential, the secret matches `OIDC_CLIENT_SECRET`,
  the user is enabled, and the realm's login settings allow the flow.

## Production notes

- Keep Keycloak and Check on TLS; the session cookie is `Secure` by default.
- The browser-visible issuer is part of token validation. Changing the Keycloak hostname requires
  the same change in `OIDC_ISSUER`, and users sign in again; live Check sessions last until
  `SESSION_TTL` or revocation.
- Use a dedicated realm and client for Check; do not reuse the development realm.
- Assign the least role that works; the Check admin role controls users, sessions, scanner nodes and
  settings.
- Role membership is snapshotted at login. Treat group removal as a trigger to revoke the user's
  live Check sessions; see
  [Authentication](Authentication.md#session-revocation-and-privilege-revocation-latency).
