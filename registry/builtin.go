package registry

// BuiltinPermissions 返回库内置管理权限码（§4.7），用于保护 RBAC 管理接口。
// 由 rbac.New 自动并入注册中心，随 SyncPermissions 同步至数据库。
// 普通管理员不得授予他人 rbac:* 权限，除非自身持有（§2.2 授权者约束）。
//
// 注：§4.7 原文为 rbac:user:assign-role，连字符不符合 §2.2/§2.3 冻结的
// 权限码字符集（小写字母、数字、下划线、冒号），此处规范化为 assign_role。
func BuiltinPermissions() []PermissionDef {
	const module = "rbac"
	return []PermissionDef{
		{Code: "rbac:role:list", Name: "角色查询", Module: module, Description: "查询角色列表与详情"},
		{Code: "rbac:role:create", Name: "创建角色", Module: module, Description: "创建角色"},
		{Code: "rbac:role:update", Name: "修改角色", Module: module, Description: "修改角色展示信息"},
		{Code: "rbac:role:delete", Name: "删除角色", Module: module, Description: "删除未被使用的角色"},
		{Code: "rbac:role:assign", Name: "角色权限分配", Module: module, Description: "为角色分配权限"},
		{Code: "rbac:user:assign_role", Name: "用户角色分配", Module: module, Description: "为用户分配或回收角色"},
		{Code: "rbac:grant:create", Name: "用户额外授权", Module: module, Description: "向用户授予额外权限"},
		{Code: "rbac:grant:revoke", Name: "撤销额外授权", Module: module, Description: "撤销用户额外权限"},
		{Code: "rbac:permission:sync", Name: "权限同步与清理", Module: module, Description: "执行权限注册同步与废弃清理"},
		{Code: "rbac:audit:read", Name: "审计查询", Module: module, Description: "查询权限审计记录（Audit 模块，Phase 2）"},
	}
}
