// This file is part of MinIO Console Server
// Copyright (c) 2021 MinIO, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package api

import (
	"crypto/subtle"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/minio/console/models"
	"github.com/minio/console/pkg/auth"
	"github.com/minio/console/pkg/auth/idp/oauth2"
)

// Login CSRF protection for SSO logins. The login page links each provider to
// oauth2LoginPath, which binds the OAuth state to the browser with a
// short-lived cookie before redirecting to the IDP. The callback API
// (POST /api/v1/login/oauth2/auth) only accepts a state matching that cookie,
// so a code obtained by someone else cannot be completed in this browser.
const (
	oauth2LoginPath    = "/oauth_login"
	oauth2CallbackPath = "/oauth_callback"
	oauth2HopParam     = "hop"
	oauth2StateCookie  = "idp-state"
	oauth2StateMaxAge  = 600 // seconds a login attempt may take at the IDP
)

var (
	errMissingOauth2Params   = errors.New("missing code or state")
	errOauth2StateMismatch   = errors.New("login state does not match this browser, please start the login again")
	errUnknownOauth2Provider = errors.New("unknown identity provider")
)

// oauth2LoginStartURL returns the path, relative to the console base, that
// starts a login with the named provider.
func oauth2LoginStartURL(idpName string) string {
	return oauth2LoginPath[1:] + "?idp=" + url.QueryEscape(idpName)
}

func newOauth2StateCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Path:     "/",
		Name:     oauth2StateCookie,
		Value:    value,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   len(GlobalPublicCerts) > 0,
		// The cookie is checked on the callback page's same-origin request;
		// Lax keeps it off cross-site subresource requests.
		SameSite: http.SameSiteLaxMode,
	}
}

// checkOauth2StateCookie verifies that state was issued to this browser.
func checkOauth2StateCookie(r *http.Request, state string) error {
	c, err := r.Cookie(oauth2StateCookie)
	if err != nil || c.Value == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) != 1 {
		return errOauth2StateMismatch
	}
	return nil
}

// oauth2CallbackError reports a rejected callback as a client error; the
// message is shown on the login callback page.
func oauth2CallbackError(code int, err error) *CodedAPIError {
	LogError("rejected SSO login callback: %v", err)
	return &CodedAPIError{Code: code, APIError: &models.APIError{Message: err.Error(), DetailedMessage: err.Error()}}
}

// serveOauth2LoginStart redirects the browser to the selected IDP.
func serveOauth2LoginStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	idpName := r.URL.Query().Get("idp")
	providerCfg, ok := GlobalMinIOConfig.OpenIDProviders[idpName]
	if !ok {
		renderOauth2Error(w, http.StatusBadRequest, errUnknownOauth2Provider.Error())
		return
	}
	// The state cookie is host-only, so it must be set on the host the IDP
	// will send the browser back to. If the user is browsing the console under
	// another host name, restart the login on the callback's origin first.
	if bounce := oauth2LoginOnCallbackOrigin(providerCfg, r); bounce != "" {
		http.Redirect(w, r, bounce, http.StatusFound)
		return
	}
	oauth2Client, err := providerCfg.GetOauth2Provider(idpName, nil, r, GetConsoleHTTPClient(getClientIP(r)))
	if err != nil {
		LogError("error contacting identity provider %s: %v", idpName, err)
		renderOauth2Error(w, http.StatusBadGateway, "the identity provider could not be reached")
		return
	}
	identityProvider := auth.IdentityProvider{
		KeyFunc: providerCfg.GetStateKeyFunc(),
		Client:  oauth2Client,
	}
	loginURL := identityProvider.GenerateLoginURL()
	u, err := url.Parse(loginURL)
	if err != nil || u.Query().Get("state") == "" {
		renderOauth2Error(w, http.StatusInternalServerError, "could not build the identity provider login URL")
		return
	}
	http.SetCookie(w, newOauth2StateCookie(u.Query().Get("state"), oauth2StateMaxAge))
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// oauth2LoginOnCallbackOrigin returns the login start URL on the origin of the
// provider's callback when the request arrived on a different host, or "" when
// no hop is needed. The hop is taken at most once, so a proxy that rewrites the
// Host header cannot cause a redirect loop.
func oauth2LoginOnCallbackOrigin(providerCfg oauth2.ProviderConfig, r *http.Request) string {
	if providerCfg.RedirectCallbackDynamic || r.URL.Query().Get(oauth2HopParam) != "" {
		return ""
	}
	callback, err := url.Parse(providerCfg.RedirectCallback)
	if err != nil || callback.Host == "" || strings.EqualFold(callback.Host, r.Host) {
		return ""
	}
	start := *callback
	start.Path = strings.TrimSuffix(callback.Path, oauth2CallbackPath) + oauth2LoginPath
	q := url.Values{}
	q.Set("idp", r.URL.Query().Get("idp"))
	q.Set(oauth2HopParam, "1")
	start.RawQuery = q.Encode()
	start.Fragment = ""
	return start.String()
}

var oauth2ErrorPage = template.Must(template.New("sso-error").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>MinIO Console - Login failed</title></head>
<body style="font-family:sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem">
<h1 style="font-size:1.25rem">Login with SSO failed</h1>
<p>{{.Message}}</p>
<p><a href="{{.LoginURL}}">Back to login</a></p>
</body></html>
`))

func renderOauth2Error(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = oauth2ErrorPage.Execute(w, struct{ Message, LoginURL string }{message, getSubPath() + "login"})
}
