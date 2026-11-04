// Package registry 实现权限资源注册中心（§2.3）。
//
// 权限资源由业务开发人员在代码中声明，应用启动时同步至数据库。
// 权限码格式：`模块:操作`（或 `模块:子模块:操作`），仅小写字母、数字、
// 下划线、冒号；v1 按字面匹配，通配符（*）不是合法权限码（§2.2）。
package registry

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/animacaeli/go-rbac/model"
)

var (
	// ErrInvalidPermissionCode 表示权限码不满足格式约束。
	ErrInvalidPermissionCode = errors.New("rbac: invalid permission code")

	// ErrDuplicateRegistration 表示同一权限码以不同定义重复注册。
	ErrDuplicateRegistration = errors.New("rbac: duplicate permission registration")

	// ErrInvalidPermissionDef 表示权限定义的展示元数据非法（名称/模块为空等）。
	ErrInvalidPermissionDef = errors.New("rbac: invalid permission definition")
)

// PermissionDef 是一条权限资源声明。
type PermissionDef struct {
	Code        string
	Name        string
	Module      string
	Description string
}

// New 构造一条权限定义。用法示例（§2.3）：
//
//	permissions := registry.NewRegistry()
//	permissions.Register(
//	    registry.New("user:list", "用户列表", "用户管理"),
//	)
func New(code, name, module string) PermissionDef {
	return PermissionDef{Code: code, Name: name, Module: module}
}

// Registry 是权限注册中心。并发安全；Register 幂等（重复注册相同定义无害）。
type Registry struct {
	mu   sync.RWMutex
	defs map[string]PermissionDef
}

// NewRegistry 创建空注册中心。
func NewRegistry() *Registry {
	return &Registry{defs: make(map[string]PermissionDef)}
}

// Register 批量注册权限。逐条校验格式与元数据；同一 code 的完全相同定义
// 重复注册视为幂等成功，不同定义则返回 ErrDuplicateRegistration。
func (r *Registry) Register(defs ...PermissionDef) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, def := range defs {
		if err := ValidateCode(def.Code); err != nil {
			return err
		}
		if strings.TrimSpace(def.Name) == "" || len(def.Name) > model.NameMaxLength {
			return fmt.Errorf("%w: name required (1-%d chars), got %q",
				ErrInvalidPermissionDef, model.NameMaxLength, def.Name)
		}
		if strings.TrimSpace(def.Module) == "" || len(def.Module) > model.RoleCodeMaxLength {
			return fmt.Errorf("%w: module required (1-%d chars), got %q",
				ErrInvalidPermissionDef, model.RoleCodeMaxLength, def.Module)
		}
		if len(def.Description) > model.DescMaxLength {
			return fmt.Errorf("%w: description too long (max %d chars)", ErrInvalidPermissionDef, model.DescMaxLength)
		}
		if prev, exists := r.defs[def.Code]; exists && prev != def {
			return fmt.Errorf("%w: %s already registered with a different definition", ErrDuplicateRegistration, def.Code)
		}
		r.defs[def.Code] = def
	}
	return nil
}

// Has 报告权限码是否已注册。
func (r *Registry) Has(code string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.defs[code]
	return ok
}

// Get 返回权限定义。
func (r *Registry) Get(code string) (PermissionDef, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	def, ok := r.defs[code]
	return def, ok
}

// All 返回全部注册定义，按 code 排序（保证同步与校验的确定性）。
func (r *Registry) All() []PermissionDef {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]PermissionDef, 0, len(r.defs))
	for _, def := range r.defs {
		out = append(out, def)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// Codes 返回全部已注册权限码，按字典序排序。
func (r *Registry) Codes() []string {
	all := r.All()
	codes := make([]string, 0, len(all))
	for _, def := range all {
		codes = append(codes, def.Code)
	}
	return codes
}

// ValidateCode 校验权限码格式（§2.2 / §2.3）：
//   - 总长 1..128；至少两段（含一个冒号），段间以冒号分隔
//   - 每段仅 [a-z0-9_]，长度 1..64，不允许空段
//   - 显式拒绝通配符（* 不是合法权限码，按字面匹配）
func ValidateCode(code string) error {
	if code == "" {
		return fmt.Errorf("%w: empty code", ErrInvalidPermissionCode)
	}
	if strings.Contains(code, "*") {
		return fmt.Errorf("%w: wildcard is not a valid permission code (literal match only): %q", ErrInvalidPermissionCode, code)
	}
	if len(code) > model.PermCodeMaxLength {
		return fmt.Errorf("%w: code too long (max %d chars): %q", ErrInvalidPermissionCode, model.PermCodeMaxLength, code)
	}
	parts := strings.Split(code, ":")
	if len(parts) < 2 {
		return fmt.Errorf("%w: want at least 2 colon-separated segments (module:action): %q", ErrInvalidPermissionCode, code)
	}
	for _, p := range parts {
		if p == "" {
			return fmt.Errorf("%w: empty segment in %q", ErrInvalidPermissionCode, code)
		}
		if len(p) > model.RoleCodeMaxLength {
			return fmt.Errorf("%w: segment too long (max %d chars) in %q", ErrInvalidPermissionCode, model.RoleCodeMaxLength, code)
		}
		for _, c := range p {
			if !isCodeChar(c) {
				return fmt.Errorf("%w: segment %q in %q contains illegal character %q (want [a-z0-9_])",
					ErrInvalidPermissionCode, p, code, string(c))
			}
		}
	}
	return nil
}

// isCodeChar 报告字符是否属于权限码合法字符集 [a-z0-9_]。
func isCodeChar(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_'
}
