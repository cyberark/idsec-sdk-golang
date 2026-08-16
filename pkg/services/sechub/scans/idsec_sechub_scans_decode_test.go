package scans

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeScansFromResultMap(t *testing.T) {
	t.Parallel()

	t.Run("happy path", func(t *testing.T) {
		t.Parallel()
		resultMap := map[string]interface{}{
			"scans": []interface{}{
				map[string]interface{}{
					"id":         "scan-1",
					"status":     "SUCCESS",
					"created_by": "admin",
				},
			},
		}
		scans, err := decodeScansFromResultMap(resultMap)
		require.NoError(t, err)
		require.Len(t, scans, 1)
		require.Equal(t, "scan-1", scans[0].ID)
		require.Equal(t, "SUCCESS", scans[0].Status)
		require.Equal(t, "admin", scans[0].CreatedBy)
	})

	t.Run("missing key", func(t *testing.T) {
		t.Parallel()
		_, err := decodeScansFromResultMap(map[string]interface{}{})
		require.Error(t, err)
	})
}
