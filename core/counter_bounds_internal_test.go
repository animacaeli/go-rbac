package core

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// 生成键边界：主体版本占低 32 位，epoch+global 占高位；越界必须 fail closed，
// 不能静默截断/溢出后命中旧生成键。
func TestValidateCounters_Bounds(t *testing.T) {
	require.NoError(t, validateCounters(counterValues{subjectVersion: 1<<32 - 1}))
	require.ErrorIs(t, validateCounters(counterValues{subjectVersion: 1 << 32}), ErrCounterOverflow)

	require.NoError(t, validateCounters(counterValues{epoch: 1<<31 - 1}))
	require.ErrorIs(t, validateCounters(counterValues{epoch: 1 << 31}), ErrCounterOverflow)
	require.ErrorIs(t, validateCounters(counterValues{epoch: 1 << 30, globalEpoch: 1 << 30}), ErrCounterOverflow)

	require.ErrorIs(t, validateCounters(counterValues{subjectVersion: -1}), ErrCounterOverflow)
	require.ErrorIs(t, validateCounters(counterValues{globalEpoch: -1}), ErrCounterOverflow)

	// 求和溢出绕过（第九轮复审 P2）：先加后判会在 MaxInt64 附近溢出为负数。
	const maxInt64 = int64(^uint64(0) >> 1)
	require.ErrorIs(t, validateCounters(counterValues{epoch: maxInt64, globalEpoch: 1}), ErrCounterOverflow,
		"MaxInt64 + 1 必须拒绝")
	require.NoError(t, validateCounters(counterValues{epoch: maxEpochSum, globalEpoch: 0}),
		"maxEpochSum 本身合法")
	require.ErrorIs(t, validateCounters(counterValues{epoch: maxEpochSum, globalEpoch: 1}), ErrCounterOverflow,
		"maxEpochSum + 1 必须拒绝")
	require.ErrorIs(t, validateCounters(counterValues{epoch: maxInt64, globalEpoch: maxInt64}), ErrCounterOverflow,
		"MaxInt64 + MaxInt64 必须拒绝")
	require.ErrorIs(t, validateCounters(counterValues{globalEpoch: maxInt64}), ErrCounterOverflow,
		"单项超上限必须拒绝")
}
