package datascope

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScope_OrderingAndWider(t *testing.T) {
	// Assert：数值序即宽度序（§2.8 合并语义 = 取最宽）。
	require.True(t, ScopeSelf < ScopeDepartment)
	require.True(t, ScopeDepartment < ScopeDepartmentAndChildren)
	require.True(t, ScopeDepartmentAndChildren < ScopeAll)

	assert.Equal(t, ScopeSelf, Wider(ScopeSelf, ScopeSelf))
	assert.Equal(t, ScopeAll, Wider(ScopeAll, ScopeSelf))
	assert.Equal(t, ScopeDepartmentAndChildren, Wider(ScopeDepartment, ScopeDepartmentAndChildren))
	assert.Equal(t, ScopeDepartmentAndChildren, Wider(ScopeDepartmentAndChildren, ScopeDepartment))
}

func TestScope_Valid(t *testing.T) {
	assert.True(t, ScopeSelf.Valid())
	assert.True(t, ScopeAll.Valid())
	assert.False(t, Scope(0).Valid())
	assert.False(t, Scope(5).Valid())
}

func TestScope_String(t *testing.T) {
	assert.Equal(t, "SELF", ScopeSelf.String())
	assert.Equal(t, "DEPARTMENT", ScopeDepartment.String())
	assert.Equal(t, "DEPARTMENT_AND_CHILDREN", ScopeDepartmentAndChildren.String())
	assert.Equal(t, "ALL", ScopeAll.String())
}
