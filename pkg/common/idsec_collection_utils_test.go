package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNilToEmptyMap(t *testing.T) {
	t.Run("nil returns non-nil empty map", func(t *testing.T) {
		var m map[string][]string
		got := NilToEmptyMap(m)
		require.NotNil(t, got)
		require.Equal(t, map[string][]string{}, got)
	})

	t.Run("populated map passes through unchanged", func(t *testing.T) {
		m := map[string][]string{"db": {"role"}}
		require.Equal(t, m, NilToEmptyMap(m))
	})
}

func TestNilToEmptySlice(t *testing.T) {
	t.Run("nil returns non-nil empty slice", func(t *testing.T) {
		var s []string
		got := NilToEmptySlice(s)
		require.NotNil(t, got)
		require.Equal(t, []string{}, got)
	})

	t.Run("populated slice passes through unchanged", func(t *testing.T) {
		s := []string{"a", "b"}
		require.Equal(t, s, NilToEmptySlice(s))
	})
}
