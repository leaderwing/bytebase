package store

import (
	"context"
	"strings"
	"time"

	"github.com/pkg/errors"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/bytebase/bytebase/backend/common"
	storepb "github.com/bytebase/bytebase/backend/generated-go/store"
	"github.com/bytebase/bytebase/backend/store/qb"
)

// LocalAuditLog is a row of local_audit_log, the self-managed audit trail kept
// apart from audit_log.
type LocalAuditLog struct {
	ResourceID string
	Workspace  string
	CreatedAt  time.Time
	Payload    *storepb.AuditLog
}

// LocalAuditLogFind filters SearchLocalAuditLogs. FilterQ takes the same
// predicates as GetSearchAuditLogsFilter, because both tables share one payload.
type LocalAuditLogFind struct {
	Workspace string
	FilterQ   *qb.Query
	Limit     *int
	Offset    *int
	// Ascending orders by created_at ASC; the default is newest first.
	Ascending bool
}

// CreateLocalAuditLog appends one row to local_audit_log.
func (s *Store) CreateLocalAuditLog(ctx context.Context, workspace string, payload *storepb.AuditLog) error {
	p, err := protojson.Marshal(payload)
	if err != nil {
		return errors.Wrapf(err, "failed to marshal payload")
	}
	sql, args, err := qb.Q().Space("INSERT INTO local_audit_log (workspace, payload) VALUES (?, ?)", workspace, p).ToSQL()
	if err != nil {
		return errors.Wrapf(err, "failed to build sql")
	}
	if _, err := s.GetDB().ExecContext(ctx, sql, args...); err != nil {
		return errors.Wrapf(err, "failed to create local audit log")
	}
	return nil
}

// SearchLocalAuditLogs lists rows in a total order: created_at is not unique,
// so resource_id, the primary key, breaks ties for offset paging.
func (s *Store) SearchLocalAuditLogs(ctx context.Context, find *LocalAuditLogFind) ([]*LocalAuditLog, error) {
	q := qb.Q().Space("SELECT resource_id, workspace, created_at, payload FROM local_audit_log WHERE TRUE")
	if find.Workspace != "" {
		q.And("workspace = ?", find.Workspace)
	}
	if find.FilterQ != nil {
		q.And("?", find.FilterQ)
	}
	order := "DESC"
	if find.Ascending {
		order = "ASC"
	}
	q.Space(strings.Join([]string{"ORDER BY created_at", order + ",", "resource_id", order}, " "))
	if v := find.Limit; v != nil {
		q.Space("LIMIT ?", *v)
	}
	if v := find.Offset; v != nil {
		q.Space("OFFSET ?", *v)
	}
	sql, args, err := q.ToSQL()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to build sql")
	}

	rows, err := s.GetDB().QueryContext(ctx, sql, args...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to query context")
	}
	defer rows.Close()

	var logs []*LocalAuditLog
	for rows.Next() {
		l := &LocalAuditLog{Payload: &storepb.AuditLog{}}
		var payload []byte
		if err := rows.Scan(&l.ResourceID, &l.Workspace, &l.CreatedAt, &payload); err != nil {
			return nil, errors.Wrapf(err, "failed to scan")
		}
		if err := common.ProtojsonUnmarshaler.Unmarshal(payload, l.Payload); err != nil {
			return nil, errors.Wrapf(err, "failed to unmarshal payload")
		}
		logs = append(logs, l)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Wrapf(err, "failed to query")
	}
	return logs, nil
}

// DeleteLocalAuditLogsBefore removes at most limit rows older than cutoff, in
// every workspace, and returns how many it removed. Callers loop until it
// returns less than limit so one pass never holds a long delete.
func (s *Store) DeleteLocalAuditLogsBefore(ctx context.Context, cutoff time.Time, limit int) (int64, error) {
	sql, args, err := qb.Q().Space(`
		DELETE FROM local_audit_log
		WHERE resource_id IN (
			SELECT resource_id FROM local_audit_log
			WHERE created_at < ?
			ORDER BY created_at, resource_id
			LIMIT ?
		)`, cutoff, limit).ToSQL()
	if err != nil {
		return 0, errors.Wrapf(err, "failed to build sql")
	}
	result, err := s.GetDB().ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, errors.Wrapf(err, "failed to delete local audit logs")
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, errors.Wrapf(err, "failed to read rows affected")
	}
	return n, nil
}
