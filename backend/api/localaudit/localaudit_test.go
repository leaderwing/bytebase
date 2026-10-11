package localaudit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"

	storepb "github.com/bytebase/bytebase/backend/generated-go/store"
	"github.com/bytebase/bytebase/backend/store"
)

type fakeBackend struct {
	rows     []*store.LocalAuditLog
	lastFind *store.LocalAuditLogFind
}

func (f *fakeBackend) service(admin bool) *Service {
	return &Service{
		authenticate: func(_ context.Context, token string) (*store.UserMessage, string, error) {
			if token != "good" {
				return nil, "", errors.New("invalid access token")
			}
			return &store.UserMessage{Email: "a@example.com"}, "w1", nil
		},
		isAdmin: func(context.Context, *store.UserMessage, string) (bool, error) { return admin, nil },
		search: func(_ context.Context, find *store.LocalAuditLogFind) ([]*store.LocalAuditLog, error) {
			f.lastFind = find
			end := min(*find.Offset+*find.Limit, len(f.rows))
			if *find.Offset >= len(f.rows) {
				return nil, nil
			}
			return f.rows[*find.Offset:end], nil
		},
	}
}

func rows(n int) []*store.LocalAuditLog {
	var out []*store.LocalAuditLog
	for i := 0; i < n; i++ {
		out = append(out, &store.LocalAuditLog{
			ResourceID: fmt.Sprintf("r%d", i),
			Workspace:  "w1",
			CreatedAt:  time.Unix(int64(1000+i), 0).UTC(),
			Payload:    &storepb.AuditLog{Method: "/bytebase.v1.SQLService/Query", User: "users/a@example.com"},
		})
	}
	return out
}

func do(t *testing.T, s *Service, target, token string) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	s.RegisterRoutes(e)
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func TestSearchAuthorization(t *testing.T) {
	t.Parallel()
	f := &fakeBackend{rows: rows(3)}

	require.Equal(t, http.StatusUnauthorized, do(t, f.service(true), Path, "").Code)
	require.Equal(t, http.StatusUnauthorized, do(t, f.service(true), Path, "bad").Code)
	require.Equal(t, http.StatusForbidden, do(t, f.service(false), Path, "good").Code)
	require.Nil(t, f.lastFind, "no query may run before the admin check passes")
	require.Equal(t, http.StatusOK, do(t, f.service(true), Path, "good").Code)
}

func TestSearchIsPinnedToCallerWorkspace(t *testing.T) {
	t.Parallel()
	f := &fakeBackend{rows: rows(1)}
	rec := do(t, f.service(true), Path+"?filter="+`method%20%3D%3D%20%22x%22`, "good")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "w1", f.lastFind.Workspace)
	require.NotNil(t, f.lastFind.FilterQ)
}

func TestSearchPaging(t *testing.T) {
	t.Parallel()
	f := &fakeBackend{rows: rows(5)}
	s := f.service(true)

	type page struct {
		Logs       []logEntry `json:"logs"`
		NextOffset *int       `json:"nextOffset"`
	}
	get := func(target string) page {
		rec := do(t, s, target, "good")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		var p page
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &p))
		return p
	}

	p1 := get(Path + "?limit=2")
	require.Len(t, p1.Logs, 2)
	require.NotNil(t, p1.NextOffset)
	require.Equal(t, 2, *p1.NextOffset)

	p2 := get(fmt.Sprintf("%s?limit=2&offset=%d", Path, *p1.NextOffset))
	require.Len(t, p2.Logs, 2)
	require.Equal(t, "r2", p2.Logs[0].Name)

	p3 := get(Path + "?limit=2&offset=4")
	require.Len(t, p3.Logs, 1)
	require.Nil(t, p3.NextOffset)

	var payload struct {
		Method string `json:"method"`
	}
	require.NoError(t, json.Unmarshal(p1.Logs[0].Log, &payload))
	require.Equal(t, "/bytebase.v1.SQLService/Query", payload.Method)
}

func TestSearchRejectsBadParameters(t *testing.T) {
	t.Parallel()
	f := &fakeBackend{rows: rows(1)}
	s := f.service(true)
	for _, target := range []string{
		Path + "?limit=0",
		Path + "?limit=1001",
		Path + "?limit=abc",
		Path + "?offset=-1",
		Path + "?order=sideways",
		Path + "?filter=" + `bogus%20%3D%3D%20%22x%22`,
	} {
		require.Equal(t, http.StatusBadRequest, do(t, s, target, "good").Code, target)
	}
}
