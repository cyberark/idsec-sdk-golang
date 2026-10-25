package azure

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	azuremodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/azure/models"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

const servicesDataResponseTemplate = `{
	"id": "ws-123",
	"onboardingType": "terraform_provider",
	"region": "us-east-1",
	"status": "Completely added",
	"entraId": "12345678-1234-1234-1234-123456789012",
	"cceVersion": "1.0.0",
	"cceAvailableVersions": ["1.1.0"],
	"upgradeAvailable": true,
	"services": ["dpa", "sca"],
	"servicesData": [
		{
			"name": "dpa",
			"status": "Completely added",
			"errors": [],
			"version": "1.2.0",
			"availableVersions": ["1.3.0"],
			"properties": [{"name": "cce_broken_role", "value": true}]
		},
		{
			"name": "sca",
			"status": "Deploying resources",
			"errors": ["warning"],
			"version": "2.0.0"
		}
	]
}`

func requireServicesData(t *testing.T, data []ccemodels.IdsecCCEOnboardedService) {
	t.Helper()
	require.Len(t, data, 2)

	require.Equal(t, "dpa", data[0].Name)
	require.Equal(t, "Completely added", data[0].Status)
	require.Equal(t, "1.2.0", data[0].Version)
	require.Equal(t, []string{"1.3.0"}, data[0].AvailableVersions)
	require.NotNil(t, data[0].Properties)
	require.Len(t, *data[0].Properties, 1)
	require.NotNil(t, (*data[0].Properties)[0].Value.BoolValue)
	require.True(t, *(*data[0].Properties)[0].Value.BoolValue)

	require.Equal(t, "sca", data[1].Name)
	require.Equal(t, "Deploying resources", data[1].Status)
	require.Equal(t, "2.0.0", data[1].Version)
	require.Equal(t, []string{"warning"}, data[1].Errors)
	require.Empty(t, data[1].AvailableVersions, "available_versions must stay empty when the API omits it")
}

func requireUpgradeInfo(t *testing.T, cceAvailableVersions []string, upgradeAvailable *bool) {
	t.Helper()
	require.Equal(t, []string{"1.1.0"}, cceAvailableVersions)
	require.NotNil(t, upgradeAvailable)
	require.True(t, *upgradeAvailable)
}

func mockGET(t *testing.T, path, body string) (*IdsecCCEAzureService, func()) {
	t.Helper()
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && r.URL.Path == path
			},
			StatusCode:   http.StatusOK,
			ResponseBody: body,
		},
	})
	return setupAzureService(client), cleanup
}

func TestTfEntraDatasource_ServicesData(t *testing.T) {
	service, cleanup := mockGET(t, "/api/azure/manual/entra/ws-123", servicesDataResponseTemplate)
	defer cleanup()

	result, err := service.TfEntraDatasource(&azuremodels.TfIdsecCCEAzureGetEntra{ID: "ws-123"})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "ws-123", result.ID)
	require.Equal(t, "12345678-1234-1234-1234-123456789012", result.EntraID)
	require.Equal(t, "1.0.0", result.CCEVersion)
	requireServicesData(t, result.ServicesData)
	requireUpgradeInfo(t, result.CCEAvailableVersions, result.UpgradeAvailable)
}

func TestTfManagementGroupDatasource_ServicesData(t *testing.T) {
	service, cleanup := mockGET(t, "/api/azure/manual/mgmtgroup/ws-123", servicesDataResponseTemplate)
	defer cleanup()

	result, err := service.TfManagementGroupDatasource(&azuremodels.TfIdsecCCEAzureGetManagementGroup{ID: "ws-123"})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "ws-123", result.ID)
	require.Equal(t, "1.0.0", result.CCEVersion)
	requireServicesData(t, result.ServicesData)
	requireUpgradeInfo(t, result.CCEAvailableVersions, result.UpgradeAvailable)
}

func TestTfSubscriptionDatasource_ServicesData(t *testing.T) {
	service, cleanup := mockGET(t, "/api/azure/manual/subscription/ws-123", servicesDataResponseTemplate)
	defer cleanup()

	result, err := service.TfSubscriptionDatasource(&azuremodels.TfIdsecCCEAzureGetSubscription{ID: "ws-123"})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "ws-123", result.ID)
	require.Equal(t, "1.0.0", result.CCEVersion)
	requireServicesData(t, result.ServicesData)
	requireUpgradeInfo(t, result.CCEAvailableVersions, result.UpgradeAvailable)
}

func TestDatasources_NullAvailableVersionsAndNoServicesData(t *testing.T) {
	body := `{
		"id": "ws-123",
		"onboardingType": "standard",
		"status": "Completely added",
		"entraId": "12345678-1234-1234-1234-123456789012",
		"cceAvailableVersions": null,
		"upgradeAvailable": null,
		"servicesData": [{"name": "dpa", "status": "Completely added", "errors": [], "version": "1.0.0", "availableVersions": null}]
	}`
	service, cleanup := mockGET(t, "/api/azure/manual/entra/ws-123", body)
	defer cleanup()

	result, err := service.TfEntraDatasource(&azuremodels.TfIdsecCCEAzureGetEntra{ID: "ws-123"})
	require.NoError(t, err)
	require.Len(t, result.ServicesData, 1)
	require.Nil(t, result.ServicesData[0].AvailableVersions)
	require.Equal(t, "1.0.0", result.ServicesData[0].Version)
	require.Nil(t, result.CCEAvailableVersions)
	require.Nil(t, result.UpgradeAvailable, "upgradeAvailable must stay nil for non-top-level workspaces")

	// A response without servicesData still decodes, leaving the list empty.
	service2, cleanup2 := mockGET(t, "/api/azure/manual/entra/ws-123", `{"id": "ws-123", "entraId": "e"}`)
	defer cleanup2()
	result2, err := service2.TfEntraDatasource(&azuremodels.TfIdsecCCEAzureGetEntra{ID: "ws-123"})
	require.NoError(t, err)
	require.Empty(t, result2.ServicesData)
}

func TestEntraDatasource_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		_, err := setupAzureService(client).TfEntraDatasource(&azuremodels.TfIdsecCCEAzureGetEntra{ID: "ws-123"})
		return err
	})
}

func TestManagementGroupDatasource_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		_, err := setupAzureService(client).TfManagementGroupDatasource(&azuremodels.TfIdsecCCEAzureGetManagementGroup{ID: "ws-123"})
		return err
	})
}

func TestSubscriptionDatasource_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		_, err := setupAzureService(client).TfSubscriptionDatasource(&azuremodels.TfIdsecCCEAzureGetSubscription{ID: "ws-123"})
		return err
	})
}
