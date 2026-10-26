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

The fix is server-side only. The shipped login page already follows the
redirect links with a top-level navigation.

Regression tests are in `api/user_login_sso_test.go`. The missing-cookie and
mismatched-cookie cases fail if the check is removed.
