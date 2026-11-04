package migrations

// Migration 描述一个版本化迁移单元。
//
// Module 用于排序与隔离：核心模块恒为 "core"，扩展模块使用自己的模块名
// （Module Registry 注册顺序决定执行顺序，§3.3）。
type Migration struct {
	Module  string
	Version string // 数字字符串，同一模块内按字典序（即零填充数字）升序执行
	Name    string
	SQL     string // 完整 SQL 脚本，可含多条语句（由执行器拆分逐条执行）
}

// ID 返回 module/version 唯一标识。
func (m Migration) ID() string { return m.Module + "/" + m.Version }
