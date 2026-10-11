-- Self-managed audit trail with its own retention, kept apart from audit_log.
-- Same row shape as audit_log; payload is AuditLog (proto/store/store/audit_log.proto).
CREATE TABLE local_audit_log (
    resource_id text PRIMARY KEY DEFAULT gen_random_uuid()::text,
    workspace text NOT NULL REFERENCES workspace(resource_id),
    created_at timestamptz NOT NULL DEFAULT now(),
    payload jsonb NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_local_audit_log_workspace_created_at ON local_audit_log(workspace, created_at DESC);
CREATE INDEX idx_local_audit_log_payload_method ON local_audit_log((payload->>'method'));
CREATE INDEX idx_local_audit_log_payload_resource ON local_audit_log((payload->>'resource'));
CREATE INDEX idx_local_audit_log_payload_user ON local_audit_log((payload->>'user'));
