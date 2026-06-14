package pamshaccounts

import (
	"reflect"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshaccounts/models"
)

func TestFlattenPamshAccountUpdatePayload(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		payload  map[string]interface{}
		expected map[string]interface{}
	}{
		{
			name: "success_flattens_nested_blocks",
			payload: map[string]interface{}{
				"id":     "aid-1",
				"secret": "hidden",
				"name":   "updated-name",
				"secretManagement": map[string]interface{}{
					"automaticManagementEnabled": true,
					"manualManagementReason":     "reason",
					"lastModifiedTime":           float64(99),
				},
			},
			expected: map[string]interface{}{
				"name": "updated-name",
				"secretManagement/automaticManagementEnabled": true,
				"secretManagement/manualManagementReason":     "reason",
			},
		},
		{
			name: "edge_excludes_account_and_secret_fields",
			payload: map[string]interface{}{
				"id":      "aid-1",
				"secret":  "hidden",
				"address": "10.0.0.1",
			},
			expected: map[string]interface{}{
				"address": "10.0.0.1",
			},
		},
		{
			name: "edge_preserves_top_level_map_fields",
			payload: map[string]interface{}{
				"platformAccountProperties": map[string]interface{}{
					"LogonDomain": "example.com",
				},
			},
			expected: map[string]interface{}{
				"platformAccountProperties": map[string]interface{}{
					"LogonDomain": "example.com",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := flattenPamshAccountUpdatePayload(tt.payload)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("flattenPamshAccountUpdatePayload() = %#v, want %#v", result, tt.expected)
			}
		})
	}
}

func TestBuildPamshAccountPatchOperations_fromUpdateModel(t *testing.T) {
	t.Parallel()

	updateAccount := &accountsmodels.IdsecPamshUpdateAccount{
		AccountID: "aid-patch-opts",
		SecretManagement: &accountsmodels.IdsecPamshAccountSecretManagement{
			AutomaticManagementEnabled: true,
			ManualManagementReason:     "reason",
			LastModifiedTime:           99,
		},
	}

	payload, err := common.SerializeJSONCamel(updateAccount)
	if err != nil {
		t.Fatalf("SerializeJSONCamel() error = %v", err)
	}

	operations := buildPamshAccountPatchOperations(payload)
	paths := patchPaths(operations)

	requiredPaths := []string{
		"secretManagement/automaticManagementEnabled",
		"secretManagement/manualManagementReason",
	}
	for _, path := range requiredPaths {
		if !containsString(paths, path) {
			t.Errorf("buildPamshAccountPatchOperations() missing path %q, got %v", path, paths)
		}
	}

	if containsString(paths, "secretManagement/lastModifiedTime") {
		t.Errorf("buildPamshAccountPatchOperations() must not include read-only path %q, got %v", "secretManagement/lastModifiedTime", paths)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
