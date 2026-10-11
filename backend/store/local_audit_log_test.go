package store_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/bytebase/bytebase/backend/common/testcontainer"
	storepb "github.com/bytebase/bytebase/backend/generated-go/store"
	"github.com/bytebase/bytebase/backend/store"
)

func TestLocalAuditLog(t *testing.T) {
	t.Parallel()
	db, stores, _ := testcontainer.NewMetadataDB(t)
	testLocalAuditLog(t, db, stores)
}

func testLocalAuditLog(t *testing.T, db *sql.DB, stores *store.Store) {
	t.Helper()
	ctx := context.Background()
	_, err := db.ExecContext(ctx, `
		INSERT INTO workspace (resource_id) VALUES ('w1'), ('w2');
	`)
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		require.NoError(t, stores.CreateLocalAuditLog(ctx, "w1", &storepb.AuditLog{
			Method: "/bytebase.v1.SQLService/Query",
			User:   fmt.Sprintf("users/u%d@example.com", i%2),
		}))
	}
	require.NoError(t, stores.CreateLocalAuditLog(ctx, "w2", &storepb.AuditLog{Method: "/bytebase.v1.SQLService/Export"}))

	t.Run("scoped to workspace", func(t *testing.T) {
		logs, err := stores.SearchLocalAuditLogs(ctx, &store.LocalAuditLogFind{Workspace: "w1"})
		require.NoError(t, err)
		require.Len(t, logs, 5)
		other, err := stores.SearchLocalAuditLogs(ctx, &store.LocalAuditLogFind{Workspace: "w2"})
		require.NoError(t, err)
		require.Len(t, other, 1)
		require.Equal(t, "/bytebase.v1.SQLService/Export", other[0].Payload.Method)
	})

	t.Run("filter by actor", func(t *testing.T) {
		filterQ, err := store.GetSearchAuditLogsFilter(`actor == "users/u0@example.com"`)
		require.NoError(t, err)
		logs, err := stores.SearchLocalAuditLogs(ctx, &store.LocalAuditLogFind{Workspace: "w1", FilterQ: filterQ})
		require.NoError(t, err)
		require.Len(t, logs, 3)
	})

	t.Run("paging returns every row once", func(t *testing.T) {
		seen := map[string]bool{}
		limit := 2
		for offset := 0; offset < 6; offset += limit {
			o := offset
			logs, err := stores.SearchLocalAuditLogs(ctx, &store.LocalAuditLogFind{Workspace: "w1", Limit: &limit, Offset: &o})
			require.NoError(t, err)
			for _, l := range logs {
				require.False(t, seen[l.ResourceID], "duplicate %s", l.ResourceID)
				seen[l.ResourceID] = true
			}
		}
		require.Len(t, seen, 5)
	})

	t.Run("delete removes only rows older than the cutoff, in batches", func(t *testing.T) {
		_, err := db.ExecContext(ctx, `UPDATE local_audit_log SET created_at = now() - interval '100 days' WHERE workspace = 'w1' AND payload->>'user' = 'users/u0@example.com'`)
		require.NoError(t, err)
		cutoff := time.Now().AddDate(0, 0, -90)

		n, err := stores.DeleteLocalAuditLogsBefore(ctx, cutoff, 2)
		require.NoError(t, err)
		require.EqualValues(t, 2, n)
		n, err = stores.DeleteLocalAuditLogsBefore(ctx, cutoff, 2)
		require.NoError(t, err)
		require.EqualValues(t, 1, n)

		logs, err := stores.SearchLocalAuditLogs(ctx, &store.LocalAuditLogFind{})
		require.NoError(t, err)
		require.Len(t, logs, 3)
	})
}
