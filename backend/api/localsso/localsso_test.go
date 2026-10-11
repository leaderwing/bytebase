package localsso

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/labstack/echo/v5"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	"github.com/bytebase/bytebase/backend/component/config"
)

type fakes struct {
	identity    *Identity
	exchangeErr error
	completeErr error
	autoCreate  *bool
}

func newTestService(f *fakes) *Service {
	return &Service{
		cfg:         config.LocalSSOConfig{Issuer: "http://issuer.test/realms/r", ClientID: "bb", ClientSecret: "s", Title: "Keycloak"},
		externalURL: func(context.Context) (string, error) { return "http://bb.test/", nil },
		authorizationEndpoint: func(context.Context) (string, error) {
			return "http://issuer.test/realms/r/protocol/openid-connect/auth", nil
		},
		exchange: func(_ context.Context, redirectURL, code, nonce string) (*Identity, error) {
			if f.exchangeErr != nil {
				return nil, f.exchangeErr
			}
			return f.identity, nil
		},
		complete: func(_ context.Context, _ http.Header, _ *Identity, autoCreate bool) (http.Header, error) {
			if f.autoCreate != nil {
				*f.autoCreate = autoCreate
			}
			if f.completeErr != nil {
				return nil, f.completeErr
			}
			h := http.Header{}
			h.Add("Set-Cookie", "access-token=abc; Path=/")
			return h, nil
		},
	}
}

func serve(s *Service, req *http.Request) *httptest.ResponseRecorder {
	e := echo.New()
	s.RegisterRoutes(e)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func cookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestConfig(t *testing.T) {
	rec := serve(newTestService(&fakes{}), httptest.NewRequest(http.MethodGet, ConfigPath, nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.JSONEq(t, `{"enabled":true,"title":"Keycloak"}`, rec.Body.String())

	disabled := newTestService(&fakes{})
	disabled.cfg = config.LocalSSOConfig{}
	rec = serve(disabled, httptest.NewRequest(http.MethodGet, ConfigPath, nil))
	require.JSONEq(t, `{"enabled":false,"title":""}`, rec.Body.String())

	// Login and callback do not exist while disabled.
	rec = serve(disabled, httptest.NewRequest(http.MethodGet, LoginPath, nil))
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestLoginRedirect(t *testing.T) {
	rec := serve(newTestService(&fakes{}), httptest.NewRequest(http.MethodGet, LoginPath, nil))
	require.Equal(t, http.StatusFound, rec.Code)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "issuer.test", loc.Host)
	q := loc.Query()
	require.Equal(t, "code", q.Get("response_type"))
	require.Equal(t, "bb", q.Get("client_id"))
	require.Equal(t, "http://bb.test"+CallbackPath, q.Get("redirect_uri"))
	require.Equal(t, "openid email profile", q.Get("scope"))

	state, nonce := cookie(rec, stateCookie), cookie(rec, nonceCookie)
	require.NotNil(t, state)
	require.NotNil(t, nonce)
	require.True(t, state.HttpOnly)
	require.Equal(t, state.Value, q.Get("state"))
	require.Equal(t, nonce.Value, q.Get("nonce"))
	require.NotEqual(t, state.Value, nonce.Value)
}

func callback(s *Service, query, stateValue string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, CallbackPath+"?"+query, nil)
	if stateValue != "" {
		req.AddCookie(&http.Cookie{Name: stateCookie, Value: stateValue})
		req.AddCookie(&http.Cookie{Name: nonceCookie, Value: "n"})
	}
	return serve(s, req)
}

func TestCallbackSuccess(t *testing.T) {
	autoCreate := false
	s := newTestService(&fakes{identity: &Identity{Email: "a@example.com", EmailVerified: true}, autoCreate: &autoCreate})
	s.cfg.AutoCreate = true
	rec := callback(s, "code=c&state=st", "st")
	require.Equal(t, http.StatusFound, rec.Code)
	require.Equal(t, "/", rec.Header().Get("Location"))
	require.NotNil(t, cookie(rec, "access-token"))
	require.True(t, autoCreate, "AutoCreate must reach the login")
	// The flow cookies are cleared.
	require.Equal(t, -1, cookie(rec, stateCookie).MaxAge)
}

func TestCallbackFailures(t *testing.T) {
	good := &Identity{Email: "a@example.com", EmailVerified: true}
	tests := []struct {
		name  string
		f     *fakes
		query string
		state string
		want  string
	}{
		{"state mismatch", &fakes{identity: good}, "code=c&state=other", "st", "state"},
		{"no cookies", &fakes{identity: good}, "code=c&state=st", "", "state"},
		{"no code", &fakes{identity: good}, "state=st", "st", "state"},
		{"issuer error", &fakes{identity: good}, "error=access_denied&state=st", "st", "denied"},
		{"exchange fails", &fakes{exchangeErr: errors.New("boom")}, "code=c&state=st", "st", "failed"},
		{"no email", &fakes{identity: &Identity{EmailVerified: true}}, "code=c&state=st", "st", "failed"},
		{"email not verified", &fakes{identity: &Identity{Email: "a@example.com"}}, "code=c&state=st", "st", "unverified"},
		{"unknown user", &fakes{identity: good, completeErr: connect.NewError(connect.CodeNotFound, errors.New("none"))}, "code=c&state=st", "st", "not_registered"},
		{"deactivated", &fakes{identity: good, completeErr: connect.NewError(connect.CodePermissionDenied, errors.New("off"))}, "code=c&state=st", "st", "denied"},
		{"internal", &fakes{identity: good, completeErr: connect.NewError(connect.CodeInternal, errors.New("db"))}, "code=c&state=st", "st", "failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := callback(newTestService(tt.f), tt.query, tt.state)
			require.Equal(t, http.StatusFound, rec.Code)
			loc := rec.Header().Get("Location")
			require.True(t, strings.HasPrefix(loc, signInPath+"?sso_error="), loc)
			require.Equal(t, tt.want, strings.TrimPrefix(loc, signInPath+"?sso_error="))
			require.Nil(t, cookie(rec, "access-token"), "no session on failure")
			// The cause is never put in the URL.
			require.NotContains(t, loc, "boom")
		})
	}
}
