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
}
