# Downstream console fork

This is a downstream fork of `github.com/minio/console` v1.7.6, the last
community release with the full console: SSO provider selection on login plus
the admin screens. MinIO's downstream release line embeds it through a
`replace` directive.

## Provenance

The upstream repository (`minio/console`, later `minio/object-browser`) is no
longer available on GitHub. The first commit of this repository is the
unmodified module source of `github.com/minio/console v1.7.6`, taken from the
Go module proxy. The compiled web UI in `web-app/build` is used as shipped.
It cannot be rebuilt from verified sources, because its design-system
dependency `github.com/minio/mds` is gone too.

## Changes

### Login CSRF fix for SSO

In v1.7.6 the OAuth `state` is HMAC-signed but not tied to the browser. An
attacker could get a victim's browser to complete the attacker's own IDP login
and end up signed in to the attacker's account. The fix (`api/user_login_sso.go`)
works like this:

- `GET /api/v1/login` now links each provider to `oauth_login?idp=<name>`
  instead of straight to the IDP.
- `GET /oauth_login?idp=<name>` generates the IDP login URL, stores its
  `state` in a short-lived `idp-state` cookie (HttpOnly, SameSite=Lax), and
  redirects to the IDP.
- `POST /api/v1/login/oauth2/auth`, called by the shipped `/oauth_callback`
  page, rejects any `state` that does not match the cookie (constant-time
  comparison), and clears the cookie after a successful login.

- If the console is opened under a different host than the provider's
  callback URL (for example `localhost` vs `127.0.0.1`, or a hostname vs
  `MINIO_BROWSER_REDIRECT_URL`), `/oauth_login` first redirects once to the
  same endpoint on the callback's origin. The host-only state cookie is then
  set where the callback will read it.
- A rejected callback returns 400 for a missing code/state and 401 for a state
  mismatch.

The fix is server-side only. The shipped login page already follows the
redirect links with a top-level navigation.

Regression tests are in `api/user_login_sso_test.go`. The missing-cookie and
mismatched-cookie cases fail if the check is removed.

#### Limits

- The binding protects against cross-site attackers. An attacker who can
  set cookies for the console's host could plant both the state cookie and a
  session cookie anyway: someone controlling a sibling subdomain, or a network
  attacker when the console is served over plain HTTP.
- One SSO login can be in flight per browser. Starting a second login, or
  taking more than 10 minutes at the IDP, makes the first one fail with a
  "start the login again" message.
- This does **not** cover a separate login-CSRF path inherited from upstream:
  `handleSPA` (`api/configure_console.go`) creates a session from
  `?sts=&sts_a=&sts_s=` query parameters on any page load, without
  validating them. It exists for operator embedding.
