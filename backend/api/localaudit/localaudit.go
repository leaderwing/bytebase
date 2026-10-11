// Package localaudit serves a read-only HTTP view of the local audit log to workspace admins.
package localaudit

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/pkg/errors"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/bytebase/bytebase/backend/api/auth"
	"github.com/bytebase/bytebase/backend/common"
	"github.com/bytebase/bytebase/backend/component/bus"
	"github.com/bytebase/bytebase/backend/component/config"
	"github.com/bytebase/bytebase/backend/enterprise"
	"github.com/bytebase/bytebase/backend/store"
	"github.com/bytebase/bytebase/backend/utils"
)

const (
	// Path is the route of the search endpoint.
	Path         = "/api/local-audit-logs"
	defaultLimit = 50
	maxLimit     = 1000
)

// Service answers Path. Authentication, the admin check and the query are
// fields so the request handling can be tested without tokens or a database.
type Service struct {
	authenticate func(ctx context.Context, token string) (*store.UserMessage, string, error)
	isAdmin      func(ctx context.Context, user *store.UserMessage, workspaceID string) (bool, error)
	search       func(ctx context.Context, find *store.LocalAuditLogFind) ([]*store.LocalAuditLog, error)
}

// NewService returns a Service backed by the real token check, IAM policy and store.
func NewService(stores *store.Store, secret string, licenseService *enterprise.LicenseService, b *bus.Bus, profile *config.Profile) *Service {
	authInterceptor := auth.New(stores, secret, licenseService, b, profile)
	return &Service{
		authenticate: func(ctx context.Context, token string) (*store.UserMessage, string, error) {
			user, workspaceID, _, err := authInterceptor.AuthenticateToken(ctx, token)
			return user, workspaceID, err
		},
		isAdmin: func(ctx context.Context, user *store.UserMessage, workspaceID string) (bool, error) {
			policy, err := stores.GetWorkspaceIamPolicy(ctx, workspaceID)
			if err != nil {
				return false, err
			}
			roles := utils.GetUserFormattedRolesMap(ctx, stores, workspaceID, user, policy.Policy)
			return roles[common.FormatRole(store.WorkspaceAdminRole)], nil
		},
		search: stores.SearchLocalAuditLogs,
	}
}

// RegisterRoutes adds the search endpoint to e.
func (s *Service) RegisterRoutes(e *echo.Echo) {
	e.GET(Path, s.handleSearch)
}

type logEntry struct {
	Name       string          `json:"name"`
	Workspace  string          `json:"workspace"`
	CreateTime time.Time       `json:"createTime"`
	Log        json.RawMessage `json:"log"`
}

type searchResponse struct {
	Logs []logEntry `json:"logs"`
	// NextOffset is set when more rows may follow; pass it as offset.
	NextOffset *int `json:"nextOffset,omitempty"`
}

func (s *Service) handleSearch(c *echo.Context) error {
	ctx := c.Request().Context()

	token, err := auth.GetTokenFromHeaders(c.Request().Header)
	if err != nil || token == "" {
		return echo.NewHTTPError(http.StatusUnauthorized, "missing access token")
	}
	user, workspaceID, err := s.authenticate(ctx, token)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, err.Error())
	}
	admin, err := s.isAdmin(ctx, user, workspaceID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to check permission")
	}
	if !admin {
		return echo.NewHTTPError(http.StatusForbidden, "only workspace admins can read the local audit log")
	}

	find, err := parseFind(c, workspaceID)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	// One extra row tells whether another page follows.
	limit := *find.Limit
	fetch := limit + 1
	find.Limit = &fetch
	rows, err := s.search(ctx, find)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to search local audit logs")
	}

	resp := searchResponse{Logs: []logEntry{}}
	if len(rows) > limit {
		rows = rows[:limit]
		next := *find.Offset + limit
		resp.NextOffset = &next
	}
	for _, r := range rows {
		raw, err := protojson.Marshal(r.Payload)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "failed to encode a log row")
		}
		resp.Logs = append(resp.Logs, logEntry{Name: r.ResourceID, Workspace: r.Workspace, CreateTime: r.CreatedAt, Log: raw})
	}
	return c.JSON(http.StatusOK, resp)
}

// parseFind reads filter, limit, offset and order. The search is always pinned
// to the caller's workspace.
func parseFind(c *echo.Context, workspaceID string) (*store.LocalAuditLogFind, error) {
	limit, err := intParam(c, "limit", defaultLimit)
	if err != nil {
		return nil, err
	}
	if limit < 1 || limit > maxLimit {
		return nil, errors.Errorf("limit must be between 1 and %d", maxLimit)
	}
	offset, err := intParam(c, "offset", 0)
	if err != nil {
		return nil, err
	}
	if offset < 0 {
		return nil, errors.New("offset must not be negative")
	}
	filterQ, err := store.GetSearchAuditLogsFilter(c.QueryParam("filter"))
	if err != nil {
		return nil, errors.Wrap(err, "invalid filter")
	}
	find := &store.LocalAuditLogFind{Workspace: workspaceID, FilterQ: filterQ, Limit: &limit, Offset: &offset}
	switch c.QueryParam("order") {
	case "", "desc":
	case "asc":
		find.Ascending = true
	default:
		return nil, errors.New(`order must be "asc" or "desc"`)
	}
	return find, nil
}

func intParam(c *echo.Context, name string, def int) (int, error) {
	v := c.QueryParam(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, errors.Errorf("%s must be an integer", name)
	}
	return n, nil
}
