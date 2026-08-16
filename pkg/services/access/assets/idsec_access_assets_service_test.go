package assets

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	assetsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/access/assets/models"
)

func TestServiceConfig(t *testing.T) {
	t.Parallel()
	service := &IdsecAccessAssetsService{}
	config := service.ServiceConfig()
	assert.Equal(t, "access-assets", config.ServiceName)
	assert.Equal(t, []string{"isp"}, config.RequiredAuthenticatorNames)
}

func TestIdsecAccessAssetsListAssets_QueryParams(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    *assetsmodels.IdsecAccessAssetsListAssetsRequest
		expected map[string]string
	}{
		{
			name:     "nil_input_returns_empty_query",
			input:    nil,
			expected: map[string]string{},
		},
		{
			name:     "empty_filter_returns_empty_query",
			input:    &assetsmodels.IdsecAccessAssetsListAssetsRequest{},
			expected: map[string]string{},
		},
		{
			name: "recents_only_true",
			input: &assetsmodels.IdsecAccessAssetsListAssetsRequest{
				RecentsOnly: true,
			},
			expected: map[string]string{
				"recents_only": "true",
			},
		},
		{
			name: "favorites_only_true",
			input: &assetsmodels.IdsecAccessAssetsListAssetsRequest{
				FavoritesOnly: true,
			},
			expected: map[string]string{
				"favorites_only": "true",
			},
		},
		{
			name: "access_method_filter",
			input: &assetsmodels.IdsecAccessAssetsListAssetsRequest{
				AccessMethod: "vaulted",
			},
			expected: map[string]string{
				"access_method": "vaulted",
			},
		},
		{
			name: "limit_set",
			input: &assetsmodels.IdsecAccessAssetsListAssetsRequest{
				Limit: 50,
			},
			expected: map[string]string{
				"limit": "50",
			},
		},
		{
			name: "sort_set",
			input: &assetsmodels.IdsecAccessAssetsListAssetsRequest{
				Sort: "address.asc",
			},
			expected: map[string]string{
				"sort": "address.asc",
			},
		},
		{
			name: "search_set",
			input: &assetsmodels.IdsecAccessAssetsListAssetsRequest{
				Search: "address contains 10.0.0",
			},
			expected: map[string]string{
				"search": "address contains 10.0.0",
			},
		},
		{
			name: "all_params_set",
			input: &assetsmodels.IdsecAccessAssetsListAssetsRequest{
				RecentsOnly:   true,
				FavoritesOnly: true,
				AccessMethod:  "vaulted",
				Limit:         50,
				Sort:          "address.asc",
				Search:        "address contains 10.0.0",
			},
			expected: map[string]string{
				"recents_only":   "true",
				"favorites_only": "true",
				"access_method":  "vaulted",
				"limit":          "50",
				"sort":           "address.asc",
				"search":         "address contains 10.0.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			query := buildListQuery(tt.input)
			assert.Equal(t, tt.expected, query)
		})
	}
}

func TestIdsecAccessAssetsSecretResponse_SecretPointer(t *testing.T) {
	t.Parallel()

	secretValue := "s3cr3t"
	tests := []struct {
		name           string
		response       assetsmodels.IdsecAccessAssetsSecretResponse
		expectNil      bool
		expectedSecret string
	}{
		{
			name:      "nil_secret_when_not_set",
			response:  assetsmodels.IdsecAccessAssetsSecretResponse{AssetID: "asset-001"},
			expectNil: true,
		},
		{
			name: "non_nil_secret_when_set",
			response: assetsmodels.IdsecAccessAssetsSecretResponse{
				AssetID: "asset-001",
				Secret:  &secretValue,
			},
			expectNil:      false,
			expectedSecret: secretValue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if tt.expectNil {
				assert.Nil(t, tt.response.Secret)
			} else {
				require.NotNil(t, tt.response.Secret)
				assert.Equal(t, tt.expectedSecret, *tt.response.Secret)
			}
		})
	}
}

func TestIdsecAccessAssetsSecretRequest_Validation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		request *assetsmodels.IdsecAccessAssetsSecretRequest
	}{
		{
			name: "required_fields_only",
			request: &assetsmodels.IdsecAccessAssetsSecretRequest{
				AssetID: "asset-001",
			},
		},
		{
			name: "with_optional_reason",
			request: &assetsmodels.IdsecAccessAssetsSecretRequest{
				AssetID: "asset-001",
				Reason:  "Break-glass troubleshooting",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.NotEmpty(t, tt.request.AssetID)
		})
	}
}
