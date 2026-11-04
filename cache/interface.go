// Package cache 定义权限缓存抽象（§4.5）。
//
// 缓存抽象属于基础模块（§2.1）：没有 Redis 时系统必须正常运行（NoopCache）。
// 缓存 key 的构造规则由 Core 统一负责（§6.1），实现只处理字节与整数。
package cache

import (
	"context"
	"time"
)

// PermissionCache 是权限缓存接口。
//
// 字符串部分（Get/Set/Delete）承载权限集合（§6.1 的 perm key）；
// 整数部分（GetInt/Incr）承载版本号与全局 epoch 的原子读写（§6.2）。
//
// Get 返回 (permissions, ok, err)：ok=false 表示未命中（包括空集合未缓存），
// err 非 nil 表示缓存故障——调用方按 §6.6 处理（鉴权路径回源数据库）。
type PermissionCache interface {
	Get(ctx context.Context, key string) (permissions []string, ok bool, err error)

	Set(ctx context.Context, key string, permissions []string, ttl time.Duration) error

	Delete(ctx context.Context, key string) error

	// GetInt 读取整数键（版本号 / epoch）。键不存在返回 (0, false, nil)；
	// 仅在基础设施故障时返回 err。
	GetInt(ctx context.Context, key string) (value int64, ok bool, err error)

	// Incr 原子递增整数键并返回新值（键不存在时从 0 递增到 1）。
	// 用于授权变更后的版本号 / epoch 递增（§6.3 失效矩阵）。
	Incr(ctx context.Context, key string) (int64, error)
}
