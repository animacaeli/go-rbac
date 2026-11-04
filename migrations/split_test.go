package migrations

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitStatements_PlainScript_SplitsOnSemicolon(t *testing.T) {
	// Arrange
	script := "CREATE TABLE a (id INT);\nINSERT INTO a VALUES (1);\n"

	// Act
	stmts := splitStatements(script)

	// Assert
	require.Len(t, stmts, 2)
	assert.Equal(t, "CREATE TABLE a (id INT)", stmts[0])
	assert.Equal(t, "INSERT INTO a VALUES (1)", stmts[1])
}

func TestSplitStatements_LineAndBlockComments_Dropped(t *testing.T) {
	// Arrange
	script := `-- leading comment
CREATE TABLE a (id INT); -- trailing comment
/* block
   comment */
INSERT INTO a VALUES (1);`

	// Act
	stmts := splitStatements(script)

	// Assert
	require.Len(t, stmts, 2)
	assert.Equal(t, "CREATE TABLE a (id INT)", stmts[0])
	assert.Equal(t, "INSERT INTO a VALUES (1)", stmts[1])
}

func TestSplitStatements_SemicolonInsideString_NotSplit(t *testing.T) {
	// Arrange
	script := `INSERT INTO t VALUES ('a;b', "c;d", ` + "`e;f`" + `); UPDATE t SET x = 1;`

	// Act
	stmts := splitStatements(script)

	// Assert
	require.Len(t, stmts, 2)
	assert.Contains(t, stmts[0], "'a;b'")
	assert.Contains(t, stmts[0], `"c;d"`)
	assert.Contains(t, stmts[0], "`e;f`")
	assert.Equal(t, "UPDATE t SET x = 1", stmts[1])
}

func TestSplitStatements_EscapedQuoteInString_Kept(t *testing.T) {
	// Arrange
	script := `INSERT INTO t VALUES ('it\'s;fine');`

	// Act
	stmts := splitStatements(script)

	// Assert
	require.Len(t, stmts, 1)
	assert.Equal(t, `INSERT INTO t VALUES ('it\'s;fine')`, stmts[0])
}

func TestSplitStatements_EmptyAndCommentOnly_Dropped(t *testing.T) {
	// Arrange
	script := "-- only a comment\n;\n  ;\n/* another */"

	// Act
	stmts := splitStatements(script)

	// Assert
	assert.Empty(t, stmts)
}

func TestCoreMigrations_EmbeddedAndParsable(t *testing.T) {
	// Act
	core := Core()

	// Assert
	require.NotEmpty(t, core, "core migrations must be embedded")
	for _, m := range core {
		assert.Equal(t, CoreModule, m.Module)
		assert.NotEmpty(t, m.Version)
		assert.NotEmpty(t, m.Name)
		assert.NotEmpty(t, splitStatements(m.SQL), "migration %s must contain statements", m.ID())
	}
	// §5.2 五张核心表必须全部出现在初始迁移中。
	var tables []string
	tables = append(tables, splitStatements(core[0].SQL)...)
	joined := ""
	for _, s := range tables {
		joined += s
	}
	for _, table := range []string{
		"rbac_roles", "rbac_permissions", "rbac_user_roles",
		"rbac_role_permissions", "rbac_user_grants",
	} {
		assert.Contains(t, joined, "CREATE TABLE IF NOT EXISTS "+table)
	}
}
