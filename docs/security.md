[← Documentation](../README.md#documentation) · Previous: [Kubernetes](kubernetes.md) · Next: [Agent API →](api.md)

# Security, sign-in and audit log

## Hardening

- **Connected agents** open no port (`listen` is off by default when `dashboard.url` is set). Each agent has its own revocable credential; the enrollment token is only used once. Put the dashboard behind HTTPS (`tls_cert`/`tls_key`, or a reverse proxy).
- **Direct agents' API**: requests need `Authorization: Bearer <token>`. `/healthz` is the only endpoint that doesn't. Set `tls_cert`/`tls_key`, or keep the agent on a private network.
- **Dashboard sign-in**: SSO (OIDC) and/or local accounts, with sessions in signed `HttpOnly`/`SameSite` cookies. Every API call is authorized on the server by role. See [Sign-in, roles and audit log](#sign-in-roles-and-audit-log).
- **Browser hardening**: a strict Content-Security-Policy that allows only the dashboard's own scripts (no inline scripts), so injected HTML cannot run code. `X-Frame-Options: DENY` and `nosniff` are set, and write requests need an `X-Requested-With` header, which blocks CSRF.
- **Secrets**: keep webhook URLs and tokens in environment variables (`${VAR}`), not in the rules repository. Audit entries mask webhook URLs.
- **Dependencies**: three, all widely used (`go-oidc`, `golang.org/x/oauth2`, `golang.org/x/crypto`), plus `yaml.v3`. The web UI is React; its npm packages (React, plus Vite and TypeScript to build it) are only used at build time, and the result is static files embedded in the dashboard binary. `govulncheck ./...` is clean when built with Go 1.27.3 or later (pinned in `go.mod`).


## Sign-in, roles and audit log

**Signing in.** Choose any combination of these in `dashboard.yaml`:

```yaml
auth:
  # Single sign-on with any OpenID Connect provider: Okta, Entra ID (Azure AD), Google, Keycloak, Auth0...
  oidc:
    name: Okta                                   # shown on the sign-in button
    issuer: https://example.okta.com/oauth2/default
    client_id: 0oa1b2c3d4
    client_secret: ${OIDC_CLIENT_SECRET}
    redirect_url: https://grepalert.example.com/auth/callback
    groups_claim: groups                         # the ID-token claim listing the user's groups
    allowed_domains: [example.com]               # optional
  admins: ["group:platform-admins"]              # bootstrap admins: emails, usernames, or group:<IdP group>
  # Built-in local admin, e.g. for break-glass access when SSO is down
  username: root
  password: ${GREPALERT_ROOT_PASSWORD}
  session_ttl: 12h
```

- **SSO** uses the authorization-code flow with PKCE, `state` and `nonce`. The dashboard server exchanges the code and verifies the ID token (signature, issuer, audience, expiry). The browser only receives a session cookie (`HttpOnly`, `SameSite=Lax`, `Secure` over HTTPS) and never sees an SSO token.
- **Local accounts** can be created under **Users & access**, for teams without SSO. Passwords are bcrypt-hashed and must be at least 12 characters. Changing or deleting an account ends its sessions.
- **Brute-force protection:** 10 failed sign-ins from one address within 5 minutes block further tries for a while.
- **Scripts and CI** can call the API with HTTP Basic and a local account.
- **With no sign-in configured**, the dashboard is open to anyone and shows a warning. This is for local demos only.

**Roles.** Grant roles under **Users & access**, to a user (email for SSO, username for local) or to an identity-provider group, for all groups or for one group:

| Role | Can |
|---|---|
| **viewer** | See the groups and agents in scope: status, rules, events, alert history, silences |
| **editor** | Also edit and sync those groups' rules, dry-run them, roll back, steer staged rollouts, edit their agents' local rules, push to agents, and create or end silences |
| **admin** | Everything, always for all groups: agents, groups, enrollment, settings, users and access, audit log |

For example, *group:db-team → editor on group db* lets the database team manage their own alert rules and see nothing else. Users see only what their roles cover, and every API call is checked on the server; the UI hiding a button is just a convenience. Role changes apply on the next request; nobody needs to sign in again.

**Audit log.** Every change is recorded with who, when, from which IP, what, the result, and a diff for rules and settings changes:
- **Covered:** sign-ins (including failures), agents (add, enroll, revoke), groups, rules (edited, or synced from git, with the actor `git`), silences, settings, enrollment tokens, users and role bindings.
- **Refused attempts** are recorded too.
- **Storage:** an append-only JSON-lines file (`audit_file`, default `audit.log` next to the data file, mode `0600`). It rotates at 20 MB, keeping 5 old files.
- **Viewing:** admins can browse and filter it under **Audit log**, or download it with **Export** for a SIEM.

**Signing out** of an SSO session also ends the session at the identity provider (OpenID Connect RP-initiated logout), so the next person at the browser has to sign in again.

**When the dashboard reaches the identity provider by another address** than browsers do, set `discovery_url`. This is common in Docker or Kubernetes: browsers use the public `issuer`, and the dashboard fetches keys and tokens through the internal address.

```yaml
  oidc:
    issuer: https://sso.example.com/realms/ops         # what browsers use; must match the tokens' "iss"
    discovery_url: http://keycloak:8080/realms/ops     # where the dashboard fetches the discovery document
```

**Try SSO with Keycloak.** [examples/sso](../examples/sso/compose.yaml) runs a complete stack:
- Keycloak with Postgres and an imported realm (users, groups, the dashboard's client)
- the dashboard
- two agents that enroll themselves and join their groups by label
- a log generator
- a webhook sink

A setup job creates the groups and role bindings.

```bash
cd examples/sso && docker compose up -d --build
```

| URL | What |
|---|---|
| http://localhost:9420 | dashboard: **Sign in with Keycloak** |
| http://localhost:8180 | Keycloak admin console (`admin` / `KEYCLOAK_ADMIN_PASSWORD` from `.env`) |
| http://localhost:9629 | alerts received by the webhook sink |

The demo users' passwords are in [`examples/sso/.env`](../examples/sso/.env); they are generated test values for localhost only.

| User | Keycloak group | What they get |
|---|---|---|
| `ops-admin` | `grepalert-admins` | admin (through `admins: ["group:grepalert-admins"]`), including the audit log |
| `alice` | `db-team` | editor of group **db**; sees only `db-01` |
| `carol` | `web-team` | editor of **web**, plus viewer of **db** (a binding for her user) |
| `bob` | none | signs in, sees "No access yet" until someone grants a role |
