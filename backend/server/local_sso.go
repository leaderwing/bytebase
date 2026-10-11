package server

import (
	"context"
	"net/http"

	"github.com/bytebase/bytebase/backend/api/localsso"
	apiv1 "github.com/bytebase/bytebase/backend/api/v1"
	"github.com/bytebase/bytebase/backend/component/config"
	"github.com/bytebase/bytebase/backend/component/iam"
	"github.com/bytebase/bytebase/backend/enterprise"
	"github.com/bytebase/bytebase/backend/store"
	"github.com/bytebase/bytebase/backend/utils"
)

// newLocalSSO wires the dev/test OIDC login to the regular session issuing code.
func newLocalSSO(stores *store.Store, secret string, licenseService *enterprise.LicenseService, profile *config.Profile, iamManager *iam.Manager) *localsso.Service {
	authService := apiv1.NewAuthService(stores, secret, licenseService, profile, iamManager)
	return localsso.NewService(
		profile.LocalSSO,
		func(ctx context.Context) (string, error) {
			return utils.GetDiscoveryExternalURL(ctx, stores, profile)
		},
		func(ctx context.Context, requestHeader http.Header, identity *localsso.Identity, autoCreate bool) (http.Header, error) {
			return authService.LocalSSOLogin(ctx, requestHeader, identity.Email, identity.DisplayName, autoCreate)
		},
	)
}
