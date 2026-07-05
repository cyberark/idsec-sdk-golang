package safes

import (
	"io"
	"strings"
	"testing"
)

func TestParseSafeResponse(t *testing.T) {
	service := &IdsecPCloudSafesService{}

	t.Run("normalizes_safe_url_id", func(t *testing.T) {
		responseBody := io.NopCloser(strings.NewReader(`{
			"safe_url_id": "safe-1",
			"safe_name": "test-safe"
		}`))

		safe, err := service.parseSafeResponse(responseBody)
		if err != nil {
			t.Fatalf("parseSafeResponse returned error: %v", err)
		}
		if safe.SafeID != "safe-1" {
			t.Fatalf("SafeID = %q, want %q", safe.SafeID, "safe-1")
		}
	})

	t.Run("invalid_top_level", func(t *testing.T) {
		responseBody := io.NopCloser(strings.NewReader(`[]`))
		if _, err := service.parseSafeResponse(responseBody); err == nil {
			t.Fatal("parseSafeResponse expected error")
		}
	})
}

func TestSafesListPageFromResultMapInvalidShapes(t *testing.T) {
	tests := []struct {
		name      string
		resultMap map[string]interface{}
	}{
		{
			name: "value_not_array",
			resultMap: map[string]interface{}{
				"value": map[string]interface{}{},
			},
		},
		{
			name: "Safes_not_array",
			resultMap: map[string]interface{}{
				"Safes": map[string]interface{}{},
			},
		},
		{
			name:      "missing_value_and_Safes",
			resultMap: map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := safesListPageFromResultMap(tt.resultMap); err == nil {
				t.Fatal("safesListPageFromResultMap expected error")
			}
		})
	}
}
