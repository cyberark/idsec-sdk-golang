package models

import (
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/require"
)

func TestIdsecSecHubSecretOnboardDataDecode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		input         map[string]interface{}
		wantStatus    string
		wantMessage   string
		wantTimestamp string
	}{
		{
			name: "CANDIDATE",
			input: map[string]interface{}{
				"onboard_data": map[string]interface{}{
					"status": "CANDIDATE",
				},
			},
			wantStatus:    "CANDIDATE",
			wantMessage:   "",
			wantTimestamp: "",
		},
		{
			name: "ONBOARDED",
			input: map[string]interface{}{
				"onboard_data": map[string]interface{}{
					"status":    "ONBOARDED",
					"timestamp": "2026-05-25T00:59:59+00:00",
				},
			},
			wantStatus:    "ONBOARDED",
			wantMessage:   "",
			wantTimestamp: "2026-05-25T00:59:59+00:00",
		},
		{
			name: "NOT_CANDIDATE",
			input: map[string]interface{}{
				"onboard_data": map[string]interface{}{
					"status":  "NOT_CANDIDATE",
					"message": "secret is not eligible",
				},
			},
			wantStatus:    "NOT_CANDIDATE",
			wantMessage:   "secret is not eligible",
			wantTimestamp: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var secret IdsecSecHubSecret
			require.NoError(t, mapstructure.Decode(tt.input, &secret))
			require.Equal(t, tt.wantStatus, secret.OnboardData.Status)
			require.Equal(t, tt.wantMessage, secret.OnboardData.Message)
			require.Equal(t, tt.wantTimestamp, secret.OnboardData.Timestamp)
		})
	}
}
