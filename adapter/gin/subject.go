package ginadapter

import (
	"github.com/animacaeli/go-rbac/core"
	"github.com/gin-gonic/gin"
)

// GetSubjectID 从 gin.Context 读取 Guard 解析并写入的主体标识。
// 授权通过的业务处理函数中可由此获得 subject_id（如查询参数过滤）。
func GetSubjectID(c *gin.Context) (core.SubjectID, bool) {
	v, ok := c.Get(SubjectContextKey)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	return core.SubjectID(s), true
}
