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

	// SetIntMax 将整数键单调地提升到指定值（Lua 原子比较：仅当当前值
	// 缺失、不可解析或小于新值时写入；旧值永不覆盖新值）。
	//
	// 这是 DB 权威版本号的唯一同步与恢复原语（§6.2）：同步路径提交后
	// 读取权威真值并 SetIntMax；恢复路径同样如此——恢复与更新的并发
	// 乱序不会使副本回退（P0：INCR 相对递增在副本被删后会从 1 重建，
	// 与权威值产生持久偏差且读者无法察觉）。
	SetIntMax(ctx context.Context, key string, value int64) error
}

// IntBatchReader 是 PermissionCache 的可选批量读扩展：授权热路径需要同时读取
// 授权域 epoch、全局 epoch 与主体版本，实现该接口可将三次往返合并为一次
// （Redis MGET）。未实现时 Core 退回逐键 GetInt，语义完全一致。
type IntBatchReader interface {
	// GetInts 批量读取整数键。missing 与 keys 等长：true 表示键存在。
	// 任一键损坏返回错误（调用方按"缓存状态不可信"回退数据库权威值）。
	GetInts(ctx context.Context, keys []string) (values []int64, found []bool, err error)
}
