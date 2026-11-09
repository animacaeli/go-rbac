package repository_test

import (
	"context"
	"testing"

	"github.com/animacaeli/go-rbac/internal/repository"
	"github.com/stretchr/testify/assert"
)

// 租户域统一小写：库表排序规则大小写不敏感，计数器/缓存域必须与之一致。
func TestTenantScope_CanonicalizesCase(t *testing.T) {
	assert.Equal(t, "default", repository.TenantScope(context.Background()))
	assert.Equal(t, "acme", repository.TenantScope(repository.WithTenant(context.Background(), "Acme")))
	assert.Equal(t, "acme", repository.TenantScope(repository.WithTenant(context.Background(), "acme")))
}
