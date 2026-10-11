package v1

import (
	"context"
	"net/http"
	"strings"

	"connectrpc.com/connect"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"

	"github.com/bytebase/bytebase/backend/common"
	storepb "github.com/bytebase/bytebase/backend/generated-go/store"
	v1pb "github.com/bytebase/bytebase/backend/generated-go/v1"
	"github.com/bytebase/bytebase/backend/store"
)

// LocalSSOLogin signs in a user whose identity the dev/test local SSO flow has
// already verified at the OIDC issuer, and returns the response headers that
// carry the web session cookies.
//
// It only issues the session; it does not decide who the issuer is. A known
// user is signed in as is. An unknown email is rejected with CodeNotFound
// unless autoCreate is set. Deactivated users are rejected, never revived.
// Self-hosted only: the SaaS workspace choice is not modelled.
func (s *AuthService) LocalSSOLogin(ctx context.Context, requestHeader http.Header, rawEmail, displayName string, autoCreate bool) (http.Header, error) {
	if s.profile.SaaS {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("local SSO is not supported on SaaS"))
	}
	// The email comes from the issuer, so it has to be converted to lower-case.
	email := strings.ToLower(strings.TrimSpace(rawEmail))
	if err := common.ValidateEmail(email); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.Wrapf(err, "invalid email %q", rawEmail))
	}
	workspaceID, err := s.store.GetWorkspaceID(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.Wrap(err, "failed to get workspace"))
	}

	user, err := s.store.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.Wrapf(err, "failed to get user %s", email))
	}
	if user == nil {
		if !autoCreate {
			return nil, connect.NewError(connect.CodeNotFound, errors.Errorf("no user with email %q", email))
		}
		if err := validateEmailWithDomains(ctx, s.licenseService, s.store, workspaceID, email, false); err != nil {
			return nil, err
		}
		if err := userCountGuard(ctx, s.store, s.licenseService, workspaceID, nil, s.profile.SaaS); err != nil {
			return nil, err
		}
		user, err = s.createLocalSSOUser(ctx, workspaceID, email, displayName)
		if err != nil {
			return nil, err
		}
	}
	if user.MemberDeleted {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("user has been deactivated"))
	}
	if user.Type != storepb.PrincipalType_END_USER {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("only users can use web login"))
	}

	loginWorkspaceID, err := s.resolveWorkspaceForLogin(ctx, user, "")
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.Wrap(err, "failed to resolve workspace"))
	}
	if loginWorkspaceID == "" {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.Errorf("user %s is not a member of any workspace", email))
	}
	// Domain restrictions and similar post-auth checks, as the regular login does.
	if _, err := s.validateLoginPermissions(ctx, user, loginWorkspaceID, &v1pb.LoginRequest{IdpName: "local-sso"}); err != nil {
		return nil, err
	}
	token, err := s.generateLoginToken(ctx, user, loginWorkspaceID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.Wrap(err, "failed to generate access token"))
	}
	resp, err := s.finalizeLogin(ctx, requestHeader, true, user, token, loginWorkspaceID, false)
	if err != nil {
		return nil, err
	}
	return resp.Header(), nil
}

func (s *AuthService) createLocalSSOUser(ctx context.Context, workspaceID, email, displayName string) (*store.UserMessage, error) {
	// SSO users never use a password; store an unguessable one like the IdP flow.
	password, err := common.RandomString(20)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate random password"))
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to generate password hash"))
	}
	if displayName == "" {
		displayName = email
	}
	user, err := s.store.CreateUser(ctx, &store.UserMessage{
		Name:         displayName,
		Email:        email,
		Type:         storepb.PrincipalType_END_USER,
		PasswordHash: string(passwordHash),
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.Wrap(err, "failed to create user"))
	}
	if _, err := s.store.PatchWorkspaceIamPolicy(ctx, &store.PatchIamPolicyMessage{
		Workspace: workspaceID,
		Member:    common.FormatUserEmail(email),
		Roles:     []string{common.FormatRole(store.WorkspaceMemberRole)},
	}); err != nil {
		return nil, connect.NewError(connect.CodeInternal, errors.Wrap(err, "failed to add user to workspace"))
	}
	return user, nil
}
