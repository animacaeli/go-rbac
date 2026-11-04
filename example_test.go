package rbac_test

import (
	"fmt"
	"log"

	"github.com/animacaeli/go-rbac"
	"github.com/animacaeli/go-rbac/registry"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// 演示最小接入装配（§10）：声明权限 → 组装 → 显式迁移与同步 → 超管种子。
// 完整可运行版本见 examples/gin-basic。
func Example() {
	// 1. 声明业务权限（格式：模块:操作，仅小写字母/数字/下划线/冒号）。
	permissions := registry.NewRegistry()
	_ = permissions.Register(
		registry.New("user:list", "用户列表", "用户管理"),
		registry.New("order:export", "导出订单", "订单管理"),
	)

	// 2. 打开数据库连接（DSN 建议 parseTime=true&loc=UTC，§5.1）。
	db, err := gorm.Open(mysql.Open("user:pass@tcp(127.0.0.1:3306)/app?parseTime=true&loc=UTC"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	// 3. 组装（New 无副作用：不迁移、不触库，§4.1）。
	app, err := rbac.New(
		rbac.WithDB(db),
		rbac.WithPermissionRegistry(permissions),
	)
	if err != nil {
		log.Fatal(err)
	}
	_ = app // 后续：app.Migrate / app.SyncPermissions / app.SeedSuperAdmin
}

// 演示启动期权限码交叉校验（§2.6）：路由声明的权限码若未注册，
// 在启动阶段 fail fast，而非运行时永远 403。
func ExampleApp_ValidatePermissionCodes() {
	permissions := registry.NewRegistry()
	_ = permissions.Register(registry.New("user:list", "用户列表", "用户管理"))

	app, err := rbac.New(rbac.WithDB(&gorm.DB{}), rbac.WithPermissionRegistry(permissions))
	if err != nil {
		log.Fatal(err)
	}

	err = app.ValidatePermissionCodes("user:list", "rbac:role:list")
	fmt.Println("registered codes pass:", err == nil)

	err = app.ValidatePermissionCodes("user:lst") // 拼写错误
	fmt.Println("typo caught:", err != nil)
	// Output:
	// registered codes pass: true
	// typo caught: true
}
