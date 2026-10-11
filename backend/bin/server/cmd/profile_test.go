package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolveProfileRejectsNegativeLocalAuditLogRetention(t *testing.T) {
	prevDir, prevDays := flags.dataDir, flags.localAuditLogRetentionDays
	t.Cleanup(func() { flags.dataDir, flags.localAuditLogRetentionDays = prevDir, prevDays })

	flags.dataDir = t.TempDir()
	flags.localAuditLogRetentionDays = -1
	_, err := resolveProfile()
	require.ErrorContains(t, err, "local-audit-log-retention-days")

	flags.localAuditLogRetentionDays = 0
	profile, err := resolveProfile()
	require.NoError(t, err)
	require.Equal(t, 0, profile.LocalAuditLogRetentionDays)
}
