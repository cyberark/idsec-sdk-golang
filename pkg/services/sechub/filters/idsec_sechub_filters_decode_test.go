package filters

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeFiltersFromResultMap(t *testing.T) {
	t.Parallel()

	t.Run("happy path", func(t *testing.T) {
		t.Parallel()
		resultMap := map[string]interface{}{
			"filters": []interface{}{
				map[string]interface{}{
					"id":   "f1",
					"type": "PAM_SAFE",
					"data": map[string]interface{}{
						"safe_name": "safe1",
					},
					"created_by": "user1",
				},
			},
		}
		filters, err := decodeFiltersFromResultMap(resultMap)
		require.NoError(t, err)
		require.Len(t, filters, 1)
		require.Equal(t, "f1", filters[0].ID)
		require.Equal(t, "PAM_SAFE", filters[0].Type)
		require.Equal(t, "safe1", filters[0].Data.SafeName)
		require.Equal(t, "user1", filters[0].CreatedBy)
	})

	t.Run("missing key", func(t *testing.T) {
		t.Parallel()
		_, err := decodeFiltersFromResultMap(map[string]interface{}{})
		require.Error(t, err)
	})
}
