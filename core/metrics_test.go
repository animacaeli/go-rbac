package core_test

import (
	"testing"

	"github.com/animacaeli/go-rbac/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCountingMetrics_CountersAndSnapshot(t *testing.T) {
	// Arrange
	m := core.NewCountingMetrics()

	// Act
	m.DenialsInc("unauthenticated")
	m.DenialsInc("unauthenticated")
	m.DenialsInc("forbidden")
	m.AuthorizeObserved(true, 0)
	m.AuthorizeObserved(false, 0)
	snap := m.Snapshot()

	// Assert
	require.Equal(t, int64(2), snap.Denials["unauthenticated"])
	assert.Equal(t, int64(1), snap.Denials["forbidden"])
	assert.Equal(t, int64(1), snap.CacheHits)
	assert.Equal(t, int64(1), snap.CacheMisses)
	assert.Equal(t, int64(2), snap.TotalRequests)
}
