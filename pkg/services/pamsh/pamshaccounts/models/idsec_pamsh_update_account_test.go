package models

import (
	"reflect"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
)

func normalizeUpdateAccountSerializedPayload(payload map[string]interface{}) {
	if secret, ok := payload["secret"].(string); ok && secret == "" {
		delete(payload, "secret")
	}
}

func TestIdsecPamshUpdateAccount_SerializeJSONCamel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    *IdsecPamshUpdateAccount
		expected map[string]interface{}
	}{
		{
			name: "success_secret_management",
			input: &IdsecPamshUpdateAccount{
				AccountID: "aid-1",
				SecretManagement: &IdsecPamshAccountSecretManagement{
					AutomaticManagementEnabled: true,
					ManualManagementReason:     "reason",
				},
			},
			expected: map[string]interface{}{
				"id": "aid-1",
				"secretManagement": map[string]interface{}{
					"automaticManagementEnabled": true,
					"manualManagementReason":     "reason",
				},
			},
		},
		{
			name: "success_top_level_fields",
			input: &IdsecPamshUpdateAccount{
				AccountID: "aid-2",
				Name:      "updated-name",
				Address:   "10.0.0.2",
			},
			expected: map[string]interface{}{
				"id":      "aid-2",
				"name":    "updated-name",
				"address": "10.0.0.2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := common.SerializeJSONCamel(tt.input)
			if err != nil {
				t.Fatalf("SerializeJSONCamel() error = %v", err)
			}
			normalizeUpdateAccountSerializedPayload(result)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("SerializeJSONCamel() = %#v, want %#v", result, tt.expected)
			}
		})
	}
}
