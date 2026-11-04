package migrations

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPlan_CoreFirstThenModuleRegistrationOrder(t *testing.T) {
	// Arrange
	all := []Migration{
		{Module: "datascope", Version: "0001", Name: "scopes"},
		{Module: "core", Version: "0002", Name: "second"},
		{Module: "tenant", Version: "0001", Name: "tenant"},
		{Module: "core", Version: "0001", Name: "first"},
		{Module: "datascope", Version: "0002", Name: "more"},
	}

	// Act
	plan := Plan(all)

	// Assert
	var got []string
	for _, m := range plan {
		got = append(got, m.ID())
	}
	assert.Equal(t, []string{
		"core/0001",
		"core/0002",
		"datascope/0001",
		"datascope/0002",
		"tenant/0001",
	}, got)
}

func TestPlan_DuplicateMigrationId_Panics(t *testing.T) {
	// Arrange
	all := []Migration{
		{Module: "core", Version: "0001", Name: "a"},
		{Module: "core", Version: "0001", Name: "b"},
	}

	// Act + Assert
	require.Panics(t, func() { Plan(all) })
}
