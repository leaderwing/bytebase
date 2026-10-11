package localsso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/require"

	"github.com/bytebase/bytebase/backend/component/config"
)

// fakeIssuer is a minimal OIDC provider: discovery, JWKS and a token endpoint
// that signs an ID token with the nonce the test sets.
type fakeIssuer struct {
	*httptest.Server
	key *rsa.PrivateKey

	mu            sync.Mutex
	nonce         string
	email         string
	emailVerified bool
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	f := &fakeIssuer{key: key, email: "Dev.User@Example.com", emailVerified: true}
	mux := http.NewServeMux()
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.URL,
			"authorization_endpoint":                f.URL + "/auth",
			"token_endpoint":                        f.URL + "/token",
			"jwks_uri":                              f.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
		}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		require.Equal(t, "authorization_code", r.PostForm.Get("grant_type"))
		require.Equal(t, "the-code", r.PostForm.Get("code"))
		f.mu.Lock()
		defer f.mu.Unlock()
		signer, err := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "k1"}},
			(&jose.SignerOptions{}).WithType("JWT"),
		)
		require.NoError(t, err)
		raw, err := jwt.Signed(signer).Claims(jwt.Claims{
			Issuer:   f.URL,
			Subject:  "u1",
			Audience: jwt.Audience{"bb"},
			Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		}).Claims(map[string]any{
			"nonce":          f.nonce,
			"email":          f.email,
			"email_verified": f.emailVerified,
			"name":           "Dev User",
		}).Serialize()
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer", "id_token": raw, "expires_in": 3600,
		})
	})
	return f
}

// TestRealIssuerRoundTrip drives the production exchange path (discovery, code
// exchange, ID token signature and nonce check) against the fake issuer.
func TestRealIssuerRoundTrip(t *testing.T) {
	issuer := newFakeIssuer(t)
	var got *Identity
	s := NewService(
		config.LocalSSOConfig{Issuer: issuer.URL, ClientID: "bb", ClientSecret: "s", Title: "Fake", AutoCreate: true},
		func(context.Context) (string, error) { return "http://bb.test", nil },
		func(_ context.Context, _ http.Header, identity *Identity, _ bool) (http.Header, error) {
			got = identity
			h := http.Header{}
			h.Add("Set-Cookie", "access-token=abc; Path=/")
			return h, nil
		},
	)
	e := echo.New()
	s.RegisterRoutes(e)

	// Step 1: /login redirects to the issuer's discovered authorize endpoint.
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, LoginPath, nil))
	require.Equal(t, http.StatusFound, rec.Code)
	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, issuer.URL+"/auth", loc.Scheme+"://"+loc.Host+loc.Path)
	state, nonce := loc.Query().Get("state"), loc.Query().Get("nonce")
	require.NotEmpty(t, state)

	call := func(nonceInToken string) *httptest.ResponseRecorder {
		issuer.mu.Lock()
		issuer.nonce = nonceInToken
		issuer.mu.Unlock()
		req := httptest.NewRequest(http.MethodGet, CallbackPath+"?code=the-code&state="+state, nil)
		req.AddCookie(&http.Cookie{Name: stateCookie, Value: state})
		req.AddCookie(&http.Cookie{Name: nonceCookie, Value: nonce})
		r := httptest.NewRecorder()
		e.ServeHTTP(r, req)
		return r
	}

	// Step 2: matching nonce signs in with the issuer's claims.
	rec = call(nonce)
	require.Equal(t, "/", rec.Header().Get("Location"), rec.Header().Get("Location"))
	require.NotNil(t, got)
	require.Equal(t, "Dev.User@Example.com", got.Email)
	require.Equal(t, "Dev User", got.DisplayName)
	require.True(t, got.EmailVerified)

	// A replayed or foreign ID token (wrong nonce) is rejected.
	got = nil
	rec = call("someone-elses-nonce")
	require.Equal(t, signInPath+"?sso_error=failed", rec.Header().Get("Location"))
	require.Nil(t, got)

	// An unverified email is rejected.
	issuer.mu.Lock()
	issuer.emailVerified = false
	issuer.mu.Unlock()
	rec = call(nonce)
	require.Equal(t, signInPath+"?sso_error=unverified", rec.Header().Get("Location"))
	require.Nil(t, got)
}
