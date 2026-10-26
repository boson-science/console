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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	authApi "github.com/minio/console/api/operations/auth"
	"github.com/minio/console/models"
	"github.com/minio/console/pkg/auth/idp/oauth2"
	"github.com/stretchr/testify/assert"
)

// newDiscoveryServer serves a minimal OpenID discovery document whose
// authorization endpoint is <server>/authorize.
func newDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(oauth2.DiscoveryDoc{
			Issuer:                 srv.URL,
			AuthEndpoint:           srv.URL + "/authorize",
			TokenEndpoint:          srv.URL + "/token",
			ResponseTypesSupported: []string{"code"},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testProviderConfig(discoveryURL, displayName string) oauth2.ProviderConfig {
	return oauth2.ProviderConfig{
		URL:              discoveryURL,
		DisplayName:      displayName,
		ClientID:         "console",
		ClientSecret:     "secret",
		HMACSalt:         "salt",
		HMACPassphrase:   "passphrase",
		RedirectCallback: "https://console.example.com/oauth_callback",
		RoleArn:          "arn:minio:iam:::role/test",
	}
}

func loginDetailParams() authApi.LoginDetailParams {
	return authApi.LoginDetailParams{HTTPRequest: httptest.NewRequest(http.MethodGet, "/api/v1/login", nil)}
}

func Test_getLoginDetailsResponse(t *testing.T) {
	t.Run("no providers falls back to form", func(t *testing.T) {
		ld, err := getLoginDetailsResponse(loginDetailParams(), oauth2.OpenIDPCfg{})
		assert.Nil(t, err)
		assert.Equal(t, models.LoginDetailsLoginStrategyForm, ld.LoginStrategy)
		assert.Empty(t, ld.RedirectRules)
	})

	t.Run("each provider becomes a redirect rule", func(t *testing.T) {
		providers := oauth2.OpenIDPCfg{
			"authentik": testProviderConfig(newDiscoveryServer(t).URL, "Authentik"),
			"other":     testProviderConfig(newDiscoveryServer(t).URL, ""),
		}

		ld, err := getLoginDetailsResponse(loginDetailParams(), providers)
		assert.Nil(t, err)
		assert.Equal(t, models.LoginDetailsLoginStrategyRedirect, ld.LoginStrategy)
		assert.Len(t, ld.RedirectRules, 2)

		byRedirect := map[string]*models.RedirectRule{}
		for _, rule := range ld.RedirectRules {
			assert.Equal(t, "iam", rule.ServiceType)
			byRedirect[rule.Redirect] = rule
		}
		assert.Equal(t, "Authentik", byRedirect["oauth_login?idp=authentik"].DisplayName)
		assert.Equal(t, "Login with SSO (other)", byRedirect["oauth_login?idp=other"].DisplayName)
	})

	t.Run("unreachable provider is skipped", func(t *testing.T) {
		authentik := newDiscoveryServer(t)
		dead := httptest.NewServer(http.NotFoundHandler())
		dead.Close()
		providers := oauth2.OpenIDPCfg{
			"authentik": testProviderConfig(authentik.URL, "Authentik"),
			"dead":      testProviderConfig(dead.URL, "Dead"),
		}

		ld, err := getLoginDetailsResponse(loginDetailParams(), providers)
		assert.Nil(t, err)
		assert.Equal(t, models.LoginDetailsLoginStrategyRedirect, ld.LoginStrategy)
		assert.Len(t, ld.RedirectRules, 1)
		assert.Equal(t, "Authentik", ld.RedirectRules[0].DisplayName)
	})

	t.Run("all providers unreachable falls back to form", func(t *testing.T) {
		dead := httptest.NewServer(http.NotFoundHandler())
		dead.Close()
		ld, err := getLoginDetailsResponse(loginDetailParams(), oauth2.OpenIDPCfg{
			"dead": testProviderConfig(dead.URL, "Dead"),
		})
		assert.Nil(t, err)
		assert.Equal(t, models.LoginDetailsLoginStrategyForm, ld.LoginStrategy)
		assert.Empty(t, ld.RedirectRules)
	})
}

func encodeOauth2State(idpName string) string {
	raw, _ := json.Marshal(oauth2.LoginURLParams{State: "s", IDPName: idpName})
	return base64.StdEncoding.EncodeToString(raw)
}

func Test_getLoginOauth2AuthResponse(t *testing.T) {
	params := func(state, cookie string) authApi.LoginOauth2AuthParams {
		code := "code"
		r := httptest.NewRequest(http.MethodPost, "/api/v1/login/oauth2/auth", nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: oauth2StateCookie, Value: cookie})
		}
		return authApi.LoginOauth2AuthParams{
			HTTPRequest: r,
			Body:        &models.LoginOauth2AuthRequest{Code: &code, State: &state},
		}
	}
	providers := oauth2.OpenIDPCfg{"authentik": testProviderConfig(newDiscoveryServer(t).URL, "Authentik")}
	valid := encodeOauth2State("authentik")

	tests := []struct {
		name      string
		params    authApi.LoginOauth2AuthParams
		providers oauth2.OpenIDPCfg
		wantErr   string // substring of the detailed error; "" means any error
		wantCode  int    // 0 means any status
	}{
		{"no providers configured", params(valid, valid), oauth2.OpenIDPCfg{}, "", 0},
		{"missing body", authApi.LoginOauth2AuthParams{HTTPRequest: httptest.NewRequest(http.MethodPost, "/", nil)}, providers, errMissingOauth2Params.Error(), http.StatusBadRequest},
		// login CSRF: a valid state without the browser-bound cookie is rejected
		{"missing state cookie", params(valid, ""), providers, errOauth2StateMismatch.Error(), http.StatusUnauthorized},
		{"state cookie from another login", params(valid, encodeOauth2State("other")), providers, errOauth2StateMismatch.Error(), http.StatusUnauthorized},
		{"state is not base64", params("%%%", "%%%"), providers, "", 0},
		{"unknown provider in state", params(encodeOauth2State("nope"), encodeOauth2State("nope")), providers, "does not exist", 0},
		{"state HMAC rejected by provider", params(valid, valid), providers, "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getLoginOauth2AuthResponse(tt.params, tt.providers)
			if !assert.NotNil(t, err) {
				return
			}
			if tt.wantErr != "" {
				assert.Contains(t, err.APIError.DetailedMessage, tt.wantErr)
			}
			if tt.wantCode != 0 {
				assert.Equal(t, tt.wantCode, err.Code)
			}
		})
	}
}

func withProviders(t *testing.T, providers oauth2.OpenIDPCfg) {
	t.Helper()
	saved := GlobalMinIOConfig
	GlobalMinIOConfig.OpenIDProviders = providers
	t.Cleanup(func() { GlobalMinIOConfig = saved })
}

func Test_serveOauth2LoginStart(t *testing.T) {
	idp := newDiscoveryServer(t)
	withProviders(t, oauth2.OpenIDPCfg{"authentik": testProviderConfig(idp.URL, "Authentik")})

	t.Run("redirects to the selected provider and binds state", func(t *testing.T) {
		w := httptest.NewRecorder()
		serveOauth2LoginStart(w, httptest.NewRequest(http.MethodGet, oauth2LoginPath+"?idp=authentik", nil))
		assert.Equal(t, http.StatusFound, w.Code)

		loc, err := url.Parse(w.Header().Get("Location"))
		assert.NoError(t, err)
		assert.Equal(t, idp.URL+"/authorize", loc.Scheme+"://"+loc.Host+loc.Path)
		assert.Equal(t, "https://console.example.com/oauth_callback", loc.Query().Get("redirect_uri"))

		state := loc.Query().Get("state")
		raw, err := base64.StdEncoding.DecodeString(state)
		assert.NoError(t, err)
		var lp oauth2.LoginURLParams
		assert.NoError(t, json.Unmarshal(raw, &lp))
		assert.Equal(t, "authentik", lp.IDPName)

		cookies := w.Result().Cookies()
		assert.Len(t, cookies, 1)
		assert.Equal(t, oauth2StateCookie, cookies[0].Name)
		assert.Equal(t, state, cookies[0].Value)
		assert.True(t, cookies[0].HttpOnly)
		assert.Equal(t, http.SameSiteLaxMode, cookies[0].SameSite)
		assert.Equal(t, oauth2StateMaxAge, cookies[0].MaxAge)
	})

	t.Run("unknown provider", func(t *testing.T) {
		w := httptest.NewRecorder()
		serveOauth2LoginStart(w, httptest.NewRequest(http.MethodGet, oauth2LoginPath+"?idp=nope", nil))
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Empty(t, w.Result().Cookies())
	})

	t.Run("only GET", func(t *testing.T) {
		w := httptest.NewRecorder()
		serveOauth2LoginStart(w, httptest.NewRequest(http.MethodPost, oauth2LoginPath+"?idp=authentik", nil))
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}
