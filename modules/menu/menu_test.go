package menu

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildTree_ParentPromotionAndOrdering(t *testing.T) {
	// Arrange：父不可见时子节点提升为根；同级按 Sort、再按 ID 排序。
	visible := map[uint64]*Node{
		10: {Menu: Menu{ID: 10, ParentID: 1, Sort: 2, Code: "child_b"}},
		11: {Menu: Menu{ID: 11, ParentID: 1, Sort: 1, Code: "child_a"}},
		12: {Menu: Menu{ID: 12, ParentID: 10, Sort: 0, Code: "grandchild"}},
		13: {Menu: Menu{ID: 13, ParentID: 0, Sort: 5, Code: "root_b"}},
		14: {Menu: Menu{ID: 14, ParentID: 0, Sort: 1, Code: "root_a"}},
	}

	// Act
	roots := buildTree(visible)

	// Assert：父（id=1）不可见 → 两个子节点提升为根；同级按 Sort 再按 ID。
	// 排序：(S1,id11)child_a < (S1,id14)root_a < (S2,id10)child_b < (S5,id13)root_b。
	require.Len(t, roots, 4)
	assert.Equal(t, []string{"child_a", "root_a", "child_b", "root_b"},
		[]string{roots[0].Code, roots[1].Code, roots[2].Code, roots[3].Code})
	require.Len(t, roots[2].Children, 1)
	assert.Equal(t, "grandchild", roots[2].Children[0].Code)
}
