package gormrepo

import (
	"errors"
	"time"

	"github.com/go-sql-driver/mysql"
)

// deadlockRetryAttempts / deadlockBackoff：授权变更管理接口的并发死锁重试参数。
// 背景：REPEATABLE READ 下，Grant 事务按 (subject_id, permission_id) 唯一索引
// 扫描的 next-key 锁，在相邻 subject_id（如 91001 / 91002 的索引条目相邻）
// 并发授权时可能在共享间隙边界上死锁（MySQL 1213）。管理操作低频且事务
// 幂等（重试会重新评估活跃授权状态），有界重试是正确且安全的应对。
const (
	deadlockRetryAttempts = 3
	deadlockBaseBackoff   = 5 * time.Millisecond
)

func isDeadlock(err error) bool {
	var me *mysql.MySQLError
	return errors.As(err, &me) && me.Number == 1213
}

// runWithDeadlockRetry 执行事务体，遇到 MySQL 死锁（1213）时退避重试。
func runWithDeadlockRetry(fn func() error) error {
	var err error
	for attempt := 0; attempt < deadlockRetryAttempts; attempt++ {
		if err = fn(); err == nil {
			return nil
		}
		if !isDeadlock(err) {
			return err
		}
		time.Sleep(deadlockBaseBackoff * time.Duration(attempt+1))
	}
	return err
}

// isDuplicateEntry 报告 MySQL 唯一键冲突（1062）。
func isDuplicateEntry(err error) bool {
	var me *mysql.MySQLError
	return errors.As(err, &me) && me.Number == 1062
}
