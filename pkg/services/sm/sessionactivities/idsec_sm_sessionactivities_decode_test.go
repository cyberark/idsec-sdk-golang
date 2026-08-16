package sessionactivities

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeSessionActivitiesFromResultMap(t *testing.T) {
	t.Parallel()

	t.Run("happy path", func(t *testing.T) {
		t.Parallel()
		resultMap := map[string]interface{}{
			"activities": []interface{}{
				map[string]interface{}{"uuid": "a1", "command": "ls"},
			},
		}
		activities, err := decodeSessionActivitiesFromResultMap(resultMap)
		require.NoError(t, err)
		require.Len(t, activities, 1)
		require.Equal(t, "a1", activities[0].UUID)
		require.Equal(t, "ls", activities[0].Command)
	})

	t.Run("missing key", func(t *testing.T) {
		t.Parallel()
		_, err := decodeSessionActivitiesFromResultMap(map[string]interface{}{})
		require.Error(t, err)
	})
}
