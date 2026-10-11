// Package localsso is a dev/test OIDC single sign-on login (for example
// Keycloak) configured by server flags. It authenticates the user against the
// issuer and then hands the verified identity to the regular session issuing
// code, so it adds no new way to mint a session.
package localsso

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/labstack/echo/v5"
	"github.com/pkg/errors"

	"github.com/bytebase/bytebase/backend/common"
	"github.com/bytebase/bytebase/backend/common/log"
	"github.com/bytebase/bytebase/backend/component/config"
	storepb "github.com/bytebase/bytebase/backend/generated-go/store"
	"github.com/bytebase/bytebase/backend/plugin/idp/oidc"
)

const (
	// ConfigPath tells the login page whether to show the SSO button.
	ConfigPath = "/api/local-sso/config"
	// LoginPath starts the authorization code flow.
	LoginPath = "/api/local-sso/login"
	// CallbackPath is the redirect URI to register at the issuer.
	CallbackPath = "/api/local-sso/callback"

	stateCookie = "bb_local_sso_state"
	nonceCookie = "bb_local_sso_nonce"
	cookieTTL   = 10 * time.Minute

	// signInPath is where failures are sent back to.
	signInPath = "/auth/signin"
)

// Identity is what the issuer vouches for.
type Identity struct {
	Email       string
	DisplayName string
	// EmailVerified is false only when the issuer says so explicitly.
	EmailVerified bool
}

// Service serves the SSO routes. The collaborators are fields so the flow can
// be tested without an issuer or a database.
type Service struct {
	cfg config.LocalSSOConfig
	// externalURL is the public base URL of this server.
	externalURL func(ctx context.Context) (string, error)
	// authorizationEndpoint is the issuer's authorize URL.
	authorizationEndpoint func(ctx context.Context) (string, error)
	// exchange trades the code for a verified identity.
	exchange func(ctx context.Context, redirectURL, code, nonce string) (*Identity, error)
	// complete signs the identity in and returns the response headers
	// (session cookies) to send to the browser.
	complete func(ctx context.Context, requestHeader http.Header, identity *Identity, autoCreate bool) (http.Header, error)
}

// NewService wires the real issuer client. externalURL and complete come from
// the server.
func NewService(
	cfg config.LocalSSOConfig,
	externalURL func(ctx context.Context) (string, error),
	complete func(ctx context.Context, requestHeader http.Header, identity *Identity, autoCreate bool) (http.Header, error),
) *Service {
	oidcConfig := &storepb.OIDCIdentityProviderConfig{
		Issuer:        cfg.Issuer,
		ClientId:      cfg.ClientID,
		ClientSecret:  cfg.ClientSecret,
		Scopes:        []string{"openid", "email", "profile"},
		FieldMapping:  &storepb.FieldMapping{Identifier: "email", DisplayName: "name"},
		SkipTlsVerify: cfg.SkipTLSVerify,
	}
	return &Service{
		cfg:         cfg,
		externalURL: externalURL,
		authorizationEndpoint: func(_ context.Context) (string, error) {
			doc, err := oidc.GetOpenIDConfiguration(cfg.Issuer, cfg.SkipTLSVerify)
			if err != nil {
				return "", err
			}
			if doc.AuthorizationEndpoint == "" {
				return "", errors.New("issuer has no authorization_endpoint")
			}
			return doc.AuthorizationEndpoint, nil
		},
		exchange: func(ctx context.Context, redirectURL, code, nonce string) (*Identity, error) {
			provider, err := oidc.NewIdentityProvider(ctx, oidcConfig)
			if err != nil {
				return nil, err
			}
			token, err := provider.ExchangeToken(ctx, redirectURL, code)
			if err != nil {
				return nil, err
			}
			info, claims, err := provider.UserInfo(ctx, token, nonce)
			if err != nil {
				return nil, err
			}
			verified := true
			if v, ok := claims["email_verified"].(bool); ok {
				verified = v
			}
			return &Identity{Email: info.Identifier, DisplayName: info.DisplayName, EmailVerified: verified}, nil
		},
		complete: complete,
	}
}

// RegisterRoutes adds the SSO routes to e. Nothing is registered when SSO is
// not configured.
func (s *Service) RegisterRoutes(e *echo.Echo) {
	e.GET(ConfigPath, s.handleConfig)
	if !s.cfg.Enabled() {
		return
	}
	e.GET(LoginPath, s.handleLogin)
	e.GET(CallbackPath, s.handleCallback)
}

func (s *Service) handleConfig(c *echo.Context) error {
	return c.JSON(http.StatusOK, map[string]any{
		"enabled": s.cfg.Enabled(),
		"title":   s.cfg.Title,
	})
}

func (s *Service) redirectURL(ctx context.Context) (string, error) {
	base, err := s.externalURL(ctx)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(base, "/") + CallbackPath, nil
}

func (s *Service) handleLogin(c *echo.Context) error {
	ctx := c.Request().Context()
	redirect, err := s.redirectURL(ctx)
	if err != nil {
		return failure(c, "failed", errors.Wrap(err, "resolve redirect URL"))
	}
	endpoint, err := s.authorizationEndpoint(ctx)
	if err != nil {
		return failure(c, "failed", errors.Wrap(err, "discover issuer"))
	}
	state, err := common.RandomString(32)
	if err != nil {
		return failure(c, "failed", err)
	}
	nonce, err := common.RandomString(32)
	if err != nil {
		return failure(c, "failed", err)
	}
	secure := strings.HasPrefix(redirect, "https")
	setFlowCookie(c, stateCookie, state, secure)
	setFlowCookie(c, nonceCookie, nonce, secure)

	target, err := url.Parse(endpoint)
	if err != nil {
		return failure(c, "failed", errors.Wrap(err, "parse authorization endpoint"))
	}
	q := target.Query()
	q.Set("response_type", "code")
	q.Set("client_id", s.cfg.ClientID)
	q.Set("redirect_uri", redirect)
	q.Set("scope", "openid email profile")
	q.Set("state", state)
	q.Set("nonce", nonce)
	target.RawQuery = q.Encode()
	return c.Redirect(http.StatusFound, target.String())
}

func (s *Service) handleCallback(c *echo.Context) error {
	ctx := c.Request().Context()
	req := c.Request()

	stateC, errState := req.Cookie(stateCookie)
	nonceC, errNonce := req.Cookie(nonceCookie)
	secure := req.TLS != nil || strings.HasPrefix(strings.ToLower(req.Header.Get("X-Forwarded-Proto")), "https")
	// The flow cookies are single-use.
	clearFlowCookie(c, stateCookie, secure)
	clearFlowCookie(c, nonceCookie, secure)

	if idpErr := req.URL.Query().Get("error"); idpErr != "" {
		return failure(c, "denied", errors.Errorf("issuer returned error %q", idpErr))
	}
	state := req.URL.Query().Get("state")
	code := req.URL.Query().Get("code")
	if errState != nil || errNonce != nil || state == "" || code == "" || state != stateC.Value {
		return failure(c, "state", errors.New("missing or mismatched state"))
	}

	redirect, err := s.redirectURL(ctx)
	if err != nil {
		return failure(c, "failed", errors.Wrap(err, "resolve redirect URL"))
	}
	identity, err := s.exchange(ctx, redirect, code, nonceC.Value)
	if err != nil {
		return failure(c, "failed", errors.Wrap(err, "exchange code"))
	}
	if identity.Email == "" {
		return failure(c, "failed", errors.New("issuer returned no email"))
	}
	if !identity.EmailVerified {
		return failure(c, "unverified", errors.Errorf("email %q is not verified at the issuer", identity.Email))
	}

	header, err := s.complete(ctx, req.Header, identity, s.cfg.AutoCreate)
	if err != nil {
		switch connect.CodeOf(err) {
		case connect.CodeNotFound:
			return failure(c, "not_registered", err)
		case connect.CodePermissionDenied, connect.CodeUnauthenticated, connect.CodeFailedPrecondition:
			return failure(c, "denied", err)
		default:
			return failure(c, "failed", err)
		}
	}
	for _, v := range header.Values("Set-Cookie") {
		c.Response().Header().Add("Set-Cookie", v)
	}
	return c.Redirect(http.StatusFound, "/")
}

// failure logs the cause and sends the browser back to the sign-in page with a
// short code, never the cause itself.
func failure(c *echo.Context, code string, cause error) error {
	slog.Warn("local sso login failed", slog.String("code", code), log.BBError(cause))
	return c.Redirect(http.StatusFound, signInPath+"?sso_error="+url.QueryEscape(code))
}

func setFlowCookie(c *echo.Context, name, value string, secure bool) {
	http.SetCookie(c.Response(), &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     CallbackPath,
		MaxAge:   int(cookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearFlowCookie(c *echo.Context, name string, secure bool) {
	http.SetCookie(c.Response(), &http.Cookie{
		Name:     name,
		Path:     CallbackPath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}
