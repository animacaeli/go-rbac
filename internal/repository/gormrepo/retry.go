package gormrepo

import "github.com/animacaeli/go-rbac/internal/repository"

// 死锁重试（1213）与重复键翻译（1062）的共享实现位于 internal/repository
// （与 tenant 模块共用；本包不再持有独立副本）。
var (
	runWithDeadlockRetry = repository.DeadlockRetry
	translateDuplicate   = repository.TranslateDuplicate
)
