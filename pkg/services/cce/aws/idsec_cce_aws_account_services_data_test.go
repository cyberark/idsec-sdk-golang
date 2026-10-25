package aws

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	awsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/aws/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

func TestTfAccountDatasource_ServicesData(t *testing.T) {
	responseJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"status": "Completely added",
		"cceVersion": "0.1.0",
		"cceAvailableVersions": ["0.2.0"],
		"upgradeAvailable": true,
		"services": ["dpa", "sca"],
		"servicesData": [
			{
				"name": "dpa",
				"status": "Completely added",
				"errors": [],
				"version": "1.2.0",
				"availableVersions": ["1.3.0"],
				"properties": [{"name": "cce_broken_role", "value": false}]
			},
			{
				"name": "sca",
				"status": "Deploying resources",
				"errors": ["warning"],
				"version": "2.0.0"
			}
		]
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	result, err := setupAWSService(client).TfAccountDatasource(&awsmodels.TfIdsecCCEAWSGetAccount{ID: "1111aaaa2222bbbb3333cccc"})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "123456789012", result.AccountID)
	require.Equal(t, "0.1.0", result.CCEVersion)
	require.Equal(t, []string{"dpa", "sca"}, result.ServiceNames)
	require.Equal(t, []string{"0.2.0"}, result.CCEAvailableVersions)
	require.NotNil(t, result.UpgradeAvailable)
	require.True(t, *result.UpgradeAvailable)

	require.Len(t, result.ServicesData, 2)
	require.Equal(t, "dpa", result.ServicesData[0].Name)
	require.Equal(t, "Completely added", result.ServicesData[0].Status)
	require.Equal(t, "1.2.0", result.ServicesData[0].Version)
	require.Equal(t, []string{"1.3.0"}, result.ServicesData[0].AvailableVersions)
	require.NotNil(t, result.ServicesData[0].Properties)
	require.NotNil(t, (*result.ServicesData[0].Properties)[0].Value.BoolValue)
	require.False(t, *(*result.ServicesData[0].Properties)[0].Value.BoolValue)

	require.Equal(t, "sca", result.ServicesData[1].Name)
	require.Equal(t, "2.0.0", result.ServicesData[1].Version)
	require.Empty(t, result.ServicesData[1].AvailableVersions)
}

func TestTfAccountDatasource_NoServicesData(t *testing.T) {
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return r.Method == "GET" },
			StatusCode:   http.StatusOK,
			ResponseBody: `{"id": "acc-1", "accountId": "123456789012"}`,
		},
	})
	defer cleanup()

	result, err := setupAWSService(client).TfAccountDatasource(&awsmodels.TfIdsecCCEAWSGetAccount{ID: "acc-1"})

	require.NoError(t, err)
	require.Empty(t, result.ServicesData)
	require.Nil(t, result.CCEAvailableVersions)
	require.Nil(t, result.UpgradeAvailable)
}

func TestAccountDatasource_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		_, err := setupAWSService(client).TfAccountDatasource(&awsmodels.TfIdsecCCEAWSGetAccount{ID: "acc-1"})
		return err
	})
}
