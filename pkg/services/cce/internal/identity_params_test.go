package internal

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
)

func TestParseIdentityParamsResponse_MultipleServices(t *testing.T) {
	body := []byte(`{
		"tenantId": "tenant-abc-123",
		"cds": {
			"identity_user_id": "cds-user",
			"identity_app_id": "cds-app",
			"identity_app_issuer": "https://issuer.example.com/cds",
			"identity_app_audience": "api://cds-audience"
		},
		"dpa": {
			"identity_user_id": "dpa-user",
			"identity_app_id": "dpa-app",
			"identity_app_issuer": "https://issuer.example.com/dpa",
			"identity_app_audience": "api://dpa-audience"
		}
	}`)

	result, err := ParseIdentityParamsResponse(body, common.GlobalLogger)
	require.NoError(t, err)
	require.Equal(t, "tenant-abc-123", result.TenantID)
	require.Len(t, result.IdentityParams, 2)

	require.Equal(t, ccemodels.IdsecCCEWorkloadFederation{
		IdentityUserID:      "cds-user",
		IdentityAppID:       "cds-app",
		IdentityAppIssuer:   "https://issuer.example.com/cds",
		IdentityAppAudience: "api://cds-audience",
	}, result.IdentityParams["cds"])

	require.Equal(t, ccemodels.IdsecCCEWorkloadFederation{
		IdentityUserID:      "dpa-user",
		IdentityAppID:       "dpa-app",
		IdentityAppIssuer:   "https://issuer.example.com/dpa",
		IdentityAppAudience: "api://dpa-audience",
	}, result.IdentityParams["dpa"])
}

func TestParseIdentityParamsResponse_SingleService(t *testing.T) {
	body := []byte(`{
		"tenantId": "single-tenant",
		"cloud_onboarding": {
			"identity_user_id": "onboard-user",
			"identity_app_id": "onboard-app",
			"identity_app_issuer": "https://issuer.example.com/onboard",
			"identity_app_audience": "api://onboard-audience"
		}
	}`)

	result, err := ParseIdentityParamsResponse(body, common.GlobalLogger)
	require.NoError(t, err)
	require.Equal(t, "single-tenant", result.TenantID)
	require.Len(t, result.IdentityParams, 1)
	require.Contains(t, result.IdentityParams, "cloud_onboarding")
}

func TestParseIdentityParamsResponse_EmptyServices(t *testing.T) {
	body := []byte(`{
		"tenantId": "empty-tenant"
	}`)

	result, err := ParseIdentityParamsResponse(body, common.GlobalLogger)
	require.NoError(t, err)
	require.Equal(t, "empty-tenant", result.TenantID)
	require.Empty(t, result.IdentityParams)
}

func TestParseIdentityParamsResponse_MissingTenantId(t *testing.T) {
	body := []byte(`{
		"cds": {
			"identity_user_id": "cds-user",
			"identity_app_id": "cds-app",
			"identity_app_issuer": "https://issuer.example.com/cds",
			"identity_app_audience": "api://cds-audience"
		}
	}`)

	result, err := ParseIdentityParamsResponse(body, common.GlobalLogger)
	require.NoError(t, err)
	require.Equal(t, "", result.TenantID)
	require.Len(t, result.IdentityParams, 1)
}

func TestParseIdentityParamsResponse_InvalidJSON(t *testing.T) {
	body := []byte(`not valid json`)

	result, err := ParseIdentityParamsResponse(body, common.GlobalLogger)
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "failed to unmarshal identity parameters")
}

func TestParseIdentityParamsResponse_EmptyBody(t *testing.T) {
	body := []byte(`{}`)

	result, err := ParseIdentityParamsResponse(body, common.GlobalLogger)
	require.NoError(t, err)
	require.Equal(t, "", result.TenantID)
	require.Empty(t, result.IdentityParams)
}

func TestParseIdentityParamsResponse_MalformedServiceEntry(t *testing.T) {
	body := []byte(`{
		"tenantId": "tenant-123",
		"good_service": {
			"identity_user_id": "user-1",
			"identity_app_id": "app-1",
			"identity_app_issuer": "https://issuer.example.com",
			"identity_app_audience": "api://audience"
		},
		"bad_service": "not-an-object"
	}`)

	result, err := ParseIdentityParamsResponse(body, common.GlobalLogger)
	require.NoError(t, err)
	require.Equal(t, "tenant-123", result.TenantID)
	require.Len(t, result.IdentityParams, 1)
	require.Contains(t, result.IdentityParams, "good_service")
}

func TestParseIdentityParamsResponse_PartialWIFFields(t *testing.T) {
	body := []byte(`{
		"tenantId": "partial-tenant",
		"sca": {
			"identity_user_id": "sca-user",
			"identity_app_id": "sca-app"
		}
	}`)

	result, err := ParseIdentityParamsResponse(body, common.GlobalLogger)
	require.NoError(t, err)
	require.Equal(t, "partial-tenant", result.TenantID)
	require.Len(t, result.IdentityParams, 1)
	require.Equal(t, "sca-user", result.IdentityParams["sca"].IdentityUserID)
	require.Equal(t, "sca-app", result.IdentityParams["sca"].IdentityAppID)
	require.Equal(t, "", result.IdentityParams["sca"].IdentityAppIssuer)
	require.Equal(t, "", result.IdentityParams["sca"].IdentityAppAudience)
}
