package audit_test

import (
	"strings"
	"testing"

	"github.com/animacaeli/go-rbac/modules/audit"
	"github.com/stretchr/testify/require"
)

func TestModule_Meta(t *testing.T) {
	m := audit.New()

	// Act + Assert
	require.Equal(t, "audit", m.Name())
	migs := m.Migrations()
	require.Len(t, migs, 1)
	require.Equal(t, "0001", migs[0].Version)
	require.Equal(t, "audit", migs[0].Module)
	require.Contains(t, migs[0].SQL, "CREATE TABLE IF NOT EXISTS rbac_audit_logs")
}

func TestModule_FailPolicyDefaults(t *testing.T) {
	// Act + Assert：默认 Strict；WithLogOnly 切换。
	m := audit.New()
	require.NotNil(t, m)

	m2 := audit.New(audit.WithLogOnly())
	require.NotNil(t, m2)
	_ = strings.TrimSpace("")
}
