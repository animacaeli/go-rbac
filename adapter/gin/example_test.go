package ginadapter_test

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/animacaeli/go-rbac"

	ginadapter "github.com/animacaeli/go-rbac/adapter/gin"
	"github.com/animacaeli/go-rbac/core"
	"github.com/animacaeli/go-rbac/registry"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// resolver 演示业务身份解析器：从已完成认证的可信上下文取 subject_id。
// 生产环境中这里应读取 JWT claims / Session——身份必须来自已认证上下文，
// 绝不可取自未验证的请求参数（§4.2）。
type resolver struct{}

func (resolver) Resolve(ctx context.Context) (core.SubjectID, error) {
	v, ok := ctx.Value(subjectKey{}).(string)
	if !ok || v == "" {
		return "", fmt.Errorf("unauthenticated")
	}
	return core.SubjectID(v), nil
}

type subjectKey struct{}

// 演示路由保护的标准形态（§2.6）：guard 声明权限码，Controller 无感知。
func ExampleNew() {
	permissions := registry.NewRegistry()
	_ = permissions.Register(registry.New("user:list", "用户列表", "用户管理"))

	db, err := gorm.Open(mysql.Open("user:pass@tcp(127.0.0.1:3306)/app?parseTime=true&loc=UTC"), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	app, err := rbac.New(rbac.WithDB(db), rbac.WithPermissionRegistry(permissions))
	if err != nil {
		log.Fatal(err)
	}

	guard := ginadapter.New(app.Authorizer(), resolver{})
	r := gin.Default()
	r.GET("/users", guard.Require("user:list"), func(c *gin.Context) {
		subject, _ := ginadapter.GetSubjectID(c)
		c.JSON(http.StatusOK, gin.H{"for": subject})
	})
	_ = r // r.Run(":8080")
}
