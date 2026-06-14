package pamshaccounts

import (
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pamsh/pamshaccounts/models"
)

func TestDecodePamshAccountFromMap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    map[string]interface{}
		expected *accountsmodels.IdsecPamshAccount
	}{
		{
			name: "success_minimal_snake_map",
			input: map[string]interface{}{
				"id":        "aid-1",
				"name":      "acct",
				"user_name": "admin",
				"safe_name": "MySafe",
			},
			expected: &accountsmodels.IdsecPamshAccount{
				AccountID: "aid-1",
				Name:      "acct",
				Username:  "admin",
				SafeName:  "MySafe",
			},
		},
		{
			name: "success_nested_secret_management",
			input: map[string]interface{}{
				"id":   "aid-2",
				"name": "acct",
				"secret_management": map[string]interface{}{
					"automatic_management_enabled": true,
					"manual_management_reason":     "reason",
					"last_modified_time":           float64(99),
				},
			},
			expected: &accountsmodels.IdsecPamshAccount{
				AccountID: "aid-2",
				Name:      "acct",
				SecretManagement: &accountsmodels.IdsecPamshAccountSecretManagement{
					AutomaticManagementEnabled: true,
					ManualManagementReason:     "reason",
					LastModifiedTime:           99,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			account, err := decodePamshAccountFromMap(tt.input)
			require.NoError(t, err)
			require.NotNil(t, account)
			if !reflect.DeepEqual(tt.expected, account) {
				t.Errorf("Expected %+v, got %+v", tt.expected, account)
			}
		})
	}
}

func TestDecodePamshAccountFromMap_success_full_pvwa_camel_json(t *testing.T) {
	t.Parallel()

	const rawJSON = `{
		"id": "6_24",
		"name": "acct",
		"safeName": "MySafe",
		"userName": "admin",
		"secretManagement": {
			"automaticManagementEnabled": true,
			"manualManagementReason": "Reason text",
			"lastModifiedTime": 99
		}
	}`

	result, err := common.DeserializeJSONSnake(io.NopCloser(strings.NewReader(rawJSON)))
	require.NoError(t, err)
	accountMap, ok := result.(map[string]interface{})
	require.True(t, ok)

	account, err := decodePamshAccountFromMap(accountMap)
	require.NoError(t, err)
	require.Equal(t, "6_24", account.AccountID)
	require.Equal(t, "acct", account.Name)
	require.Equal(t, "MySafe", account.SafeName)
	require.Equal(t, "admin", account.Username)
	require.NotNil(t, account.SecretManagement)
	require.True(t, account.SecretManagement.AutomaticManagementEnabled)
	require.Equal(t, "Reason text", account.SecretManagement.ManualManagementReason)
	require.Equal(t, 99, account.SecretManagement.LastModifiedTime)
}
