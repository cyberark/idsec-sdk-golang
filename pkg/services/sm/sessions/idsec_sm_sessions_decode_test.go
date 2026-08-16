package sessions

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeSessionsFromResultMap(t *testing.T) {
	t.Parallel()

	t.Run("happy path", func(t *testing.T) {
		t.Parallel()
		resultMap := map[string]interface{}{
			"sessions": []interface{}{
				map[string]interface{}{"session_id": "s1"},
			},
		}
		sessions, err := decodeSessionsFromResultMap(resultMap)
		require.NoError(t, err)
		require.Len(t, sessions, 1)
		require.Equal(t, "s1", sessions[0].SessionID)
	})

	t.Run("missing key", func(t *testing.T) {
		t.Parallel()
		_, err := decodeSessionsFromResultMap(map[string]interface{}{})
		require.Error(t, err)
	})
}
