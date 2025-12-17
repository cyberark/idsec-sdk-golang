package azure

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	azuremodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/azure/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

func TestTfIdentityParams_Success(t *testing.T) {
	// Mock response for GET /api/azure/identity_params
	// Note: The API returns the identity info directly (not wrapped in "identity_info")
	responseJSON := `{
		"dpa": {
			"identity_user_id": "user-123",
			"identity_app_id": "app-456",
			"identity_app_issuer": "https://issuer.example.com",
			"identity_app_audience": "api://default"
		},
		"sca": {
			"identity_user_id": "user-789",
			"identity_app_id": "app-012",
			"identity_app_issuer": "https://issuer.example.com",
			"identity_app_audience": "api://default"
		}
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == "/api/azure/identity-params"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupAzureService(client)

	// Call TfIdentityParams
	result, err := service.TfIdentityParams(&azuremodels.TfIdsecCCEAzureGetIdentityParams{})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.IdentityParams)
	require.Contains(t, result.IdentityParams, "dpa")
	require.Contains(t, result.IdentityParams, "sca")

	// Verify DPA identity info
	dpaInfo := result.IdentityParams["dpa"]
	require.Equal(t, "user-123", dpaInfo.IdentityUserID)
	require.Equal(t, "app-456", dpaInfo.IdentityAppID)
	require.Equal(t, "https://issuer.example.com", dpaInfo.IdentityAppIssuer)
	require.Equal(t, "api://default", dpaInfo.IdentityAppAudience)

	// Verify SCA identity info
	scaInfo := result.IdentityParams["sca"]
	require.Equal(t, "user-789", scaInfo.IdentityUserID)
	require.Equal(t, "app-012", scaInfo.IdentityAppID)
}

func TestTfIdentityParams_EmptyResult(t *testing.T) {
	// Note: The API returns the identity info directly (not wrapped in "identity_info")
	responseJSON := `{}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == "/api/azure/identity-params"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupAzureService(client)

	// Call TfIdentityParams
	result, err := service.TfIdentityParams(&azuremodels.TfIdsecCCEAzureGetIdentityParams{})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.IdentityParams)
	require.Len(t, result.IdentityParams, 0)
}

func TestTfIdentityParams_SingleService(t *testing.T) {
	// Note: The API returns the identity info directly (not wrapped in "identity_info")
	responseJSON := `{
		"dpa": {
			"identity_user_id": "user-123",
			"identity_app_id": "app-456",
			"identity_app_issuer": "https://issuer.example.com",
			"identity_app_audience": "api://default"
		}
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == "/api/azure/identity-params"
			},
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupAzureService(client)

	// Call TfIdentityParams
	result, err := service.TfIdentityParams(&azuremodels.TfIdsecCCEAzureGetIdentityParams{})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.IdentityParams)
	require.Len(t, result.IdentityParams, 1)
	require.Contains(t, result.IdentityParams, "dpa")
}

func TestTfIdentityParams_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupAzureService(client)
		_, err := service.TfIdentityParams(&azuremodels.TfIdsecCCEAzureGetIdentityParams{})
		return err
	})
}
