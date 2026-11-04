package migrations

import "strings"

// splitStatements 将 SQL 脚本按语句拆分：以分号为终止符，
// 忽略 `--` 行注释、`/* */` 块注释以及引号内（'...'、"..."、`...`）的分号。
// 空语句与纯注释会被丢弃。
func splitStatements(script string) []string {
	var (
		stmts []string
		cur   strings.Builder
		flush = func() {
			if s := strings.TrimSpace(cur.String()); s != "" {
				stmts = append(stmts, s)
			}
			cur.Reset()
		}
	)

	rs := []byte(script)
	for i := 0; i < len(rs); {
		c := rs[i]
		switch {
		case c == '\'' || c == '"' || c == '`':
			// 引号字符串：原样搬运，转义符成对跳过（反引号内无转义）
			quote := c
			cur.WriteByte(c)
			i++
			for i < len(rs) {
				if rs[i] == '\\' && quote != '`' && i+1 < len(rs) {
					cur.WriteByte(rs[i])
					cur.WriteByte(rs[i+1])
					i += 2
					continue
				}
				cur.WriteByte(rs[i])
				if rs[i] == quote {
					i++
					break
				}
				i++
			}
		case c == '-' && i+1 < len(rs) && rs[i+1] == '-':
			// 行注释：整行丢弃（保留换行，便于错误定位时报行号近似）
			for i < len(rs) && rs[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(rs) && rs[i+1] == '*':
			// 块注释：丢弃
			i += 2
			for i+1 < len(rs) && !(rs[i] == '*' && rs[i+1] == '/') {
				i++
			}
			i += 2
			if i > len(rs) {
				i = len(rs)
			}
		case c == ';':
			flush()
			i++
		default:
			cur.WriteByte(c)
			i++
		}
	}
	flush()
	return stmts
}
