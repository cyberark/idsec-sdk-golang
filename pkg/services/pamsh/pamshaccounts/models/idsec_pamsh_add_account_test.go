package models

import (
	"reflect"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
)

func normalizeAddAccountSerializedPayload(payload map[string]interface{}) {
	if secret, ok := payload["secret"].(string); ok && secret == "" {
		delete(payload, "secret")
	}
	if safeName, ok := payload["safeName"].(string); ok && safeName == "" {
		delete(payload, "safeName")
	}
}

func TestIdsecPamshAddAccount_SerializeJSONCamel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    *IdsecPamshAddAccount
		expected map[string]interface{}
	}{
		{
			name: "success_full_nested_payload",
			input: &IdsecPamshAddAccount{
				Name:     "opts-account",
				SafeName: "safe-1",
				SecretManagement: &IdsecPamshAccountSecretManagement{
					AutomaticManagementEnabled: true,
					ManualManagementReason:     "manual-reason",
					LastModifiedTime:           12345,
				},
			},
			expected: map[string]interface{}{
				"name":     "opts-account",
				"safeName": "safe-1",
				"secretManagement": map[string]interface{}{
					"automaticManagementEnabled": true,
					"manualManagementReason":     "manual-reason",
					"lastModifiedTime":           float64(12345),
				},
			},
		},
		{
			name: "success_secret_management_only",
			input: &IdsecPamshAddAccount{
				Name:     "secret-only",
				SafeName: "safe-1",
				SecretManagement: &IdsecPamshAccountSecretManagement{
					AutomaticManagementEnabled: true,
					ManualManagementReason:     "reason",
					LastModifiedTime:           99,
				},
			},
			expected: map[string]interface{}{
				"name":     "secret-only",
				"safeName": "safe-1",
				"secretManagement": map[string]interface{}{
					"automaticManagementEnabled": true,
					"manualManagementReason":     "reason",
					"lastModifiedTime":           float64(99),
				},
			},
		},
		{
			name: "edge_nil_nested_blocks",
			input: &IdsecPamshAddAccount{
				Name:     "core-account",
				SafeName: "safe-1",
				Secret:   "s3cr3t",
			},
			expected: map[string]interface{}{
				"name":     "core-account",
				"safeName": "safe-1",
				"secret":   "s3cr3t",
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
			normalizeAddAccountSerializedPayload(result)

			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("SerializeJSONCamel() = %#v, want %#v", result, tt.expected)
			}
		})
	}
}
