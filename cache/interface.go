// Package cache 定义权限缓存抽象（§4.5）。
//
// 缓存抽象属于基础模块（§2.1）：没有 Redis 时系统必须正常运行（NoopCache）。
// 缓存 key 的构造规则由 Core 统一负责（§6.1），实现只处理字节。
package cache

import (
	"context"
	"time"
)

// PermissionCache 是权限缓存接口。
//
// Get 返回 (permissions, ok, err)：ok=false 表示未命中（包括空集合未缓存），
// err 非 nil 表示缓存故障——调用方按 §6.6 处理（鉴权路径回源数据库）。
type PermissionCache interface {
	Get(ctx context.Context, key string) (permissions []string, ok bool, err error)

	Set(ctx context.Context, key string, permissions []string, ttl time.Duration) error

	Delete(ctx context.Context, key string) error
}
