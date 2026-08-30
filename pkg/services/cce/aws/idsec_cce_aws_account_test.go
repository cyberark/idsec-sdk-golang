package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	awsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/aws/models"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

// setupAWSService creates an IdsecCCEAWSService with the given mock ISP client.
func setupAWSService(client *isp.IdsecISPServiceClient) *IdsecCCEAWSService {
	ispBase := &services.IdsecISPBaseService{}
	// Use reflection to set the private client field for testing
	v := reflect.ValueOf(ispBase).Elem()
	clientField := v.FieldByName("client")
	clientField = reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr())).Elem()
	clientField.Set(reflect.ValueOf(client))

	return &IdsecCCEAWSService{
		IdsecBaseService: &services.IdsecBaseService{
			Logger: common.GlobalLogger,
		},
		IdsecISPBaseService: ispBase,
	}
}

func TestTfAddAccount_Success(t *testing.T) {
	region := "us-east-1"
	displayName := "Test Account"
	status := ccemodels.CompletelyAdded

	// First response: POST /api/aws/programmatic/account (create)
	createResponseJSON := `{
		"id": "1111aaaa2222bbbb3333cccc"
	}`

	// Second response: GET /api/aws/programmatic/account/{id} (read)
	readResponseJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"services": ["sca"],
		"servicesData": [
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			}
		],
		"displayName": "Test Account",
		"status": "Completely added"
	}`

	// Setup mock service with multiple responses
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account")
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: createResponseJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: readResponseJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call the TfAddAccount function
	result, err := service.TfAddAccount(&awsmodels.TfIdsecCCEAWSAddAccount{
		AccountID: "123456789012",
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]any{
					"ScaRoleArn": "arn:aws:iam::123456789012:role/SCARole",
				},
			},
		},
	})

	// Assertions - now expects full account details
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "1111aaaa2222bbbb3333cccc", result.ID)
	require.Equal(t, "123456789012", result.AccountID)
	require.Equal(t, ccemodels.TerraformProvider, result.OnboardingType)
	require.Equal(t, region, result.Region)
	require.Equal(t, displayName, result.DisplayName)
	require.Equal(t, status, result.Status)
}

func TestTfAddAccount_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupAWSService(client)
		_, err := service.TfAddAccount(&awsmodels.TfIdsecCCEAWSAddAccount{
			AccountID: "123456789012",
			Services:  []ccemodels.IdsecCCEServiceInput{},
		})
		return err
	})
}

func TestTfAddAccount_EmptyServicesArray_Returns400(t *testing.T) {
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account")
			},
			StatusCode: http.StatusBadRequest,
			ResponseBody: `{
				"attributes": null,
				"code": "400",
				"description": "One or more programmatic values is invalid.",
				"message": "Bad Request"
			}`,
			OnRequest: func(r *http.Request) {
				require.Equal(t, "POST", r.Method)
				require.Contains(t, r.URL.Path, "/api/aws/programmatic/account")
			},
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Attempt to create account with empty services array
	_, err := service.TfAddAccount(&awsmodels.TfIdsecCCEAWSAddAccount{
		AccountID:          "123456789012",
		Services:           []ccemodels.IdsecCCEServiceInput{}, // Empty services array
		AccountDisplayName: "Test Account",
		DeploymentRegion:   "us-east-1",
	})

	// Assertions - should return error for 400 Bad Request
	require.Error(t, err)
	require.Contains(t, err.Error(), "400")
	require.Contains(t, err.Error(), "Bad Request")
}

// firstServiceVersion reads the request body and returns the version of the first
// service in the "services" array of the JSON payload.
func firstServiceVersion(t *testing.T, r *http.Request) string {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	require.NoError(t, err)

	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &payload))

	services, ok := payload["services"].([]interface{})
	require.True(t, ok, "request body must contain a services array")
	require.NotEmpty(t, services)

	service, ok := services[0].(map[string]interface{})
	require.True(t, ok)

	version, _ := service["version"].(string)
	return version
}

func TestTfAddAccount_IncludesServiceVersion(t *testing.T) {
	createResponseJSON := `{"id": "1111aaaa2222bbbb3333cccc"}`
	readResponseJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"services": ["sca"],
		"displayName": "Test Account",
		"status": "Completely added"
	}`

	var capturedVersion string
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/api/aws/programmatic/account")
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: createResponseJSON,
			OnRequest: func(r *http.Request) {
				capturedVersion = firstServiceVersion(t, r)
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: readResponseJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	_, err := service.TfAddAccount(&awsmodels.TfIdsecCCEAWSAddAccount{
		AccountID: "123456789012",
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.SCA,
				Version:     "2.1.0",
				Resources: map[string]any{
					"ScaRoleArn": "arn:aws:iam::123456789012:role/SCARole",
				},
			},
		},
	})

	require.NoError(t, err)
	require.Equal(t, "2.1.0", capturedVersion, "service version must be included in the create account request payload")
}

func TestTfAddAccountServices_IncludesServiceVersion(t *testing.T) {
	var capturedVersion string
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
			OnRequest: func(r *http.Request) {
				capturedVersion = firstServiceVersion(t, r)
			},
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	err := service.TfAddAccountServices(&awsmodels.TfIdsecCCEAWSAddAccountServices{
		ID: "1111aaaa2222bbbb3333cccc",
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.CDS,
				Version:     "4.0.1",
				Resources: map[string]any{
					"CdsRoleArn": "arn:aws:iam::123456789012:role/CDSRole",
				},
			},
		},
	})

	require.NoError(t, err)
	require.Equal(t, "4.0.1", capturedVersion, "service version must be included in the add services request payload")
}

// TestTfUpdateAccount_RequestsAccountByID is a regression guard for the empty-ID
// update bug. The Terraform provider (v0.5.0, PR #197) began stripping computed
// attributes from the update payload; the CCE account resource declared "id" as
// computed but did not preserve it via ImportID, so TfUpdateAccount received an
// empty ID and issued `GET /api/aws/programmatic/account/` (no id) which the
// tenant rejects with a generic 403. This test locks the SDK contract: the update
// flow must fetch the account by its real onboarding id, never the bare
// collection path.
func TestTfUpdateAccount_RequestsAccountByID(t *testing.T) {
	const onboardingID = "1111aaaa2222bbbb3333cccc"
	accountJSON := `{
		"id": "` + onboardingID + `",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"services": ["dpa"],
		"status": "Completely added"
	}`

	var gotPaths []string
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			// The update flow now upserts the desired services through the add/update-services
			// endpoint; accept it so the flow reaches the get-details reads under assertion.
			Matcher: func(r *http.Request) bool {
				return r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/account/"+onboardingID+"/services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: accountJSON,
			OnRequest: func(r *http.Request) {
				gotPaths = append(gotPaths, r.URL.Path)
			},
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Desired services == current services, so no service is removed; the flow still
	// performs the get-details reads (the ones that 403'd on empty id) under assertion.
	_, err := service.TfUpdateAccount(&awsmodels.TfIdsecCCEAWSUpdateAccount{
		ID: onboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{ServiceName: ccemodels.DPA, Resources: map[string]any{}},
		},
	})

	require.NoError(t, err)
	require.NotEmpty(t, gotPaths, "update must fetch account details at least once")
	for _, p := range gotPaths {
		require.Falsef(t, strings.HasSuffix(p, "/account/"),
			"update requested the bare collection path %q (empty id -> 403 regression)", p)
		require.Truef(t, strings.HasSuffix(p, "/account/"+onboardingID),
			"update must request the account by its onboarding id, got %q", p)
	}
}

// TestTfUpdateAccount_UpsertsChangedServiceInput is a regression guard for two related bugs:
//  1. the original "silent no-op on version change": TfUpdateAccount used to send only the
//     service names that were new, so bumping the version of an already-onboarded service
//     produced a green apply with no API call and no server change; and
//  2. the follow-up "501 on unchanged service": naively re-sending the full desired list makes
//     the API reject already-onboarded services that are not an upgrade (e.g. dpa) with a 501,
//     because the add/update-services endpoint only supports adding new services or upgrading a
//     version - not re-submitting an unchanged service.
//
// So the update must send only new services and version-changed services: here dpa is unchanged
// (0.0.3 -> 0.0.3) and must be omitted, while sca is upgraded (0.0.3 -> 0.0.6) and must be sent.
func TestTfUpdateAccount_UpsertsChangedServiceInput(t *testing.T) {
	const onboardingID = "1111aaaa2222bbbb3333cccc"
	// dpa and sca are already onboarded at 0.0.3; the desired input keeps dpa at 0.0.3 and bumps sca to 0.0.6.
	accountJSON := `{
		"id": "` + onboardingID + `",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"services": ["dpa", "sca"],
		"servicesData": [
			{"name": "dpa", "version": "0.0.3", "status": "Completely added", "errors": []},
			{"name": "sca", "version": "0.0.3", "status": "Completely added", "errors": []}
		],
		"status": "Completely added"
	}`

	var postBody string
	var postCount, deleteCount int
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == http.MethodPost &&
					strings.HasSuffix(r.URL.Path, "/account/"+onboardingID+"/services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
			OnRequest: func(r *http.Request) {
				postCount++
				body, _ := io.ReadAll(r.Body)
				postBody = string(body)
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == http.MethodDelete &&
					strings.HasSuffix(r.URL.Path, "/account/"+onboardingID+"/services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
			OnRequest:    func(r *http.Request) { deleteCount++ },
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: accountJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	_, err := service.TfUpdateAccount(&awsmodels.TfIdsecCCEAWSUpdateAccount{
		ID: onboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{ServiceName: ccemodels.DPA, Version: "0.0.3", Resources: map[string]any{}},
			{ServiceName: ccemodels.SCA, Version: "0.0.6", Resources: map[string]any{}},
		},
	})

	require.NoError(t, err)
	require.Equal(t, 1, postCount,
		"a version change on one service must trigger exactly one add/update-services call")
	require.Contains(t, postBody, `"serviceName":"sca"`, "the upgraded service (sca) must be sent")
	require.Contains(t, postBody, `"version":"0.0.6"`, "the new sca version must be sent")
	require.NotContains(t, postBody, `"serviceName":"dpa"`,
		"the unchanged service (dpa) must NOT be sent, or the API rejects the request with 501")
	require.Zero(t, deleteCount,
		"a version change on an existing service must not delete any service")
}

// TestTfUpdateAccount_SendsResourceChange verifies that a resources-only change (same version) on an
// already-onboarded standalone-account service is detected and sent, while a service whose resources did
// not change is omitted (so the endpoint does not reject it with a 501 for a non-upgrade-enabled service).
func TestTfUpdateAccount_SendsResourceChange(t *testing.T) {
	const onboardingID = "1111aaaa2222bbbb3333cccc"
	// dpa and sca are onboarded at 0.0.3; the GET exposes their currently-deployed resources under "parameters".
	accountJSON := `{
		"id": "` + onboardingID + `",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"services": ["dpa", "sca"],
		"servicesData": [
			{"name": "dpa", "version": "0.0.3", "status": "Completely added", "errors": []},
			{"name": "sca", "version": "0.0.3", "status": "Completely added", "errors": []}
		],
		"parameters": {
			"dpa": {"DpaRoleArn": "arn:aws:iam::123456789012:role/DpaRole"},
			"sca": {"ScaRoleArn": "arn:aws:iam::123456789012:role/ScaRoleOld"}
		},
		"status": "Completely added"
	}`

	var postBody string
	var postCount, deleteCount int
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == http.MethodPost &&
					strings.HasSuffix(r.URL.Path, "/account/"+onboardingID+"/services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
			OnRequest: func(r *http.Request) {
				postCount++
				body, _ := io.ReadAll(r.Body)
				postBody = string(body)
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == http.MethodDelete &&
					strings.HasSuffix(r.URL.Path, "/account/"+onboardingID+"/services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
			OnRequest:    func(r *http.Request) { deleteCount++ },
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: accountJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	_, err := service.TfUpdateAccount(&awsmodels.TfIdsecCCEAWSUpdateAccount{
		ID: onboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			// dpa: unchanged resources -> must be omitted.
			{ServiceName: ccemodels.DPA, Version: "0.0.3", Resources: map[string]any{"DpaRoleArn": "arn:aws:iam::123456789012:role/DpaRole"}},
			// sca: resources changed (same version) -> must be sent.
			{ServiceName: ccemodels.SCA, Version: "0.0.3", Resources: map[string]any{"ScaRoleArn": "arn:aws:iam::123456789012:role/ScaRoleNew"}},
		},
	})

	require.NoError(t, err)
	require.Equal(t, 1, postCount, "a resources change on one service must trigger exactly one add/update-services call")
	require.Contains(t, postBody, `"serviceName":"sca"`, "the changed service (sca) must be sent")
	require.Contains(t, postBody, "ScaRoleNew", "the new sca resource value must be sent")
	require.NotContains(t, postBody, `"serviceName":"dpa"`,
		"the unchanged service (dpa) must NOT be sent, or the API may reject the request with 501")
	require.Zero(t, deleteCount, "a resources change on an existing service must not delete any service")
}

// TestTfUpdateAccount_OnboardedServiceWithoutVersionIsNotResent guards a subtle 501 regression:
// whether a service is "already onboarded" must be decided by the authoritative "services" name
// list, NOT by the presence of a version in "servicesData". The API frequently omits the version
// for an onboarded service; if onboarding were keyed off the version map, such a service would be
// misclassified as NEW and re-sent to the add/update-services endpoint, which rejects an
// already-onboarded, non-upgrade service with 501 FEATURE_NOT_IMPLEMENTED.
//
// Here dpa is onboarded but has no version in servicesData, and the desired input leaves it
// unchanged (no version), so it must NOT be sent; sca is brand-new and must be sent.
func TestTfUpdateAccount_OnboardedServiceWithoutVersionIsNotResent(t *testing.T) {
	const onboardingID = "1111aaaa2222bbbb3333cccc"
	// dpa is onboarded but its servicesData entry carries no version (as the API often returns);
	// sca is not onboarded at all.
	accountJSON := `{
		"id": "` + onboardingID + `",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"services": ["dpa"],
		"servicesData": [
			{"name": "dpa", "status": "Completely added", "errors": []}
		],
		"status": "Completely added"
	}`

	var postBody string
	var postCount, deleteCount int
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == http.MethodPost &&
					strings.HasSuffix(r.URL.Path, "/account/"+onboardingID+"/services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
			OnRequest: func(r *http.Request) {
				postCount++
				body, _ := io.ReadAll(r.Body)
				postBody = string(body)
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == http.MethodDelete &&
					strings.HasSuffix(r.URL.Path, "/account/"+onboardingID+"/services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
			OnRequest:    func(r *http.Request) { deleteCount++ },
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: accountJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	_, err := service.TfUpdateAccount(&awsmodels.TfIdsecCCEAWSUpdateAccount{
		ID: onboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{ServiceName: ccemodels.DPA, Resources: map[string]any{}},
			{ServiceName: ccemodels.SCA, Resources: map[string]any{}},
		},
	})

	require.NoError(t, err)
	require.Equal(t, 1, postCount,
		"only the brand-new service (sca) should trigger an add/update-services call")
	require.Contains(t, postBody, `"serviceName":"sca"`, "the new service (sca) must be sent")
	require.NotContains(t, postBody, `"serviceName":"dpa"`,
		"an onboarded service without a reported version must NOT be re-sent, or the API rejects it with 501")
	require.Zero(t, deleteCount,
		"no desired service was dropped, so nothing must be removed")
}

// TestDeleteAccountServices_SendsOnboardingType verifies the delete-services request
// carries onboarding_type=terraform_provider so the API can enforce that the account
// was onboarded via Terraform. The remove-services endpoint reads onboarding_type from
// the single-value queryStringParameters and ignores the API-Gateway-mirrored copy in
// multiValueQueryStringParameters.
func TestDeleteAccountServices_SendsOnboardingType(t *testing.T) {
	const onboardingID = "1111aaaa2222bbbb3333cccc"

	var gotQuery map[string][]string
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == http.MethodDelete &&
					strings.HasSuffix(r.URL.Path, "/account/"+onboardingID+"/services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
			OnRequest: func(r *http.Request) {
				gotQuery = r.URL.Query()
			},
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	err := service.DeleteAccountServices(&awsmodels.TfIdsecCCEAWSDeleteAccountServices{
		ID:           onboardingID,
		ServiceNames: []string{"dpa"},
	})

	require.NoError(t, err)
	require.Equal(t, []string{"dpa"}, gotQuery["services_names"],
		"delete-services must send the services to remove via services_names")
	require.Equal(t, []string{ccemodels.TerraformProvider}, gotQuery["onboarding_type"],
		"delete-services must send onboarding_type=terraform_provider so the API enforces the Terraform onboarding type")
}

func TestAccount_Success(t *testing.T) {
	region := "us-east-1"
	displayName := "Test Account"
	status := ccemodels.CompletelyAdded

	responseJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"parameters": {
			"dummy_two": {
				"CobTableArn": "arn:aws:dynamodb::123456789012:table/table_name"
			},
			"dummy": {}
		},
		"servicesData": [
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			}
		],
		"displayName": "Test Account",
		"status": "Completely added"
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

	service := setupAWSService(client)

	// Call the Account function
	result, err := service.TfAccount(&awsmodels.TfIdsecCCEAWSGetAccount{
		ID: "1111aaaa2222bbbb3333cccc",
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)

	// Build expected struct
	expected := &awsmodels.TfIdsecCCEAWSAccount{
		ID:             "1111aaaa2222bbbb3333cccc",
		AccountID:      "123456789012",
		OnboardingType: ccemodels.TerraformProvider,
		Region:         region,
		// Parameters will be populated by mapstructure from JSON, keys are converted to snake_case
		Parameters: map[string]map[string]interface{}{
			"dummy_two": {
				"cob_table_arn": "arn:aws:dynamodb::123456789012:table/table_name",
			},
			"dummy": {},
		},
		DisplayName: displayName,
		Status:      status,
	}

	// Compare structs
	require.Equal(t, expected, result)
}

func TestAccount_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupAWSService(client)
		_, err := service.TfAccount(&awsmodels.TfIdsecCCEAWSGetAccount{
			ID: "acc-789",
		})
		return err
	})
}

func TestDeleteAccount_Success(t *testing.T) {
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "DELETE" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call the TfDeleteAccount function
	err := service.TfDeleteAccount(&awsmodels.TfIdsecCCEAWSDeleteAccount{
		ID: "1111aaaa2222bbbb3333cccc",
	})

	// Assertions
	require.NoError(t, err)
}

func TestDeleteAccount_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupAWSService(client)
		return service.TfDeleteAccount(&awsmodels.TfIdsecCCEAWSDeleteAccount{
			ID: "acc-789",
		})
	})
}

func TestUpdateAccount_AddService_Success(t *testing.T) {
	region := "us-east-1"
	displayName := "Test Account"
	status := ccemodels.CompletelyAdded

	// First response: GET current account with only DPA
	currentAccountJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"services": ["sca"],
		"servicesData": [
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			}
		],
		"displayName": "Test Account",
		"status": "Completely added"
	}`

	// Second response: POST add CDS service
	addServicesResponse := `{}`

	// Third response: GET updated account with SCA and CDS
	updatedAccountJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"services": ["sca", "cds"],
		"servicesData": [
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			},
			{
				"name": "cds",
				"status": "Completely added",
				"errors": []
			}
		],
		"displayName": "Test Account",
		"status": "Completely added"
	}`

	getCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				// Match first GET request to account endpoint
				if r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc") && getCallCount == 0 {
					getCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusOK,
			ResponseBody: currentAccountJSON, // First GET returns current state
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match POST to services endpoint
				return r.Method == "POST" && strings.Contains(r.URL.Path, "services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: addServicesResponse,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match subsequent GET requests
				return r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc") && getCallCount > 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: updatedAccountJSON, // Second GET returns updated state
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call UpdateAccount to add CEM service
	result, err := service.TfUpdateAccount(&awsmodels.TfIdsecCCEAWSUpdateAccount{
		ID: "1111aaaa2222bbbb3333cccc",
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]any{
					"ScaRoleArn": "arn:aws:iam::123456789012:role/SCARole",
				},
			},
			{
				ServiceName: ccemodels.CDS,
				Resources: map[string]any{
					"CdsRoleArn": "arn:aws:iam::123456789012:role/CDSRole",
				},
			},
		},
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "1111aaaa2222bbbb3333cccc", result.ID)
	require.Equal(t, "123456789012", result.AccountID)
	require.Equal(t, region, result.Region)
	require.Equal(t, displayName, result.DisplayName)
	require.Equal(t, status, result.Status)
}

func TestUpdateAccount_RemoveService_Success(t *testing.T) {
	region := "us-east-1"
	displayName := "Test Account"
	status := ccemodels.CompletelyAdded

	// First response: GET current account with SCA and CDS
	currentAccountJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"services": ["sca", "cds"],
		"servicesData": [
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			},
			{
				"name": "cds",
				"status": "Completely added",
				"errors": []
			}
		],
		"displayName": "Test Account",
		"status": "Completely added"
	}`

	// Second response: DELETE CDS service
	deleteServicesResponse := `{}`

	// Third response: GET updated account with only DPA
	updatedAccountJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"services": ["sca"],
		"servicesData": [
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			}
		],
		"displayName": "Test Account",
		"status": "Completely added"
	}`

	getCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				// Match first GET request
				if r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc") && getCallCount == 0 {
					getCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusOK,
			ResponseBody: currentAccountJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match POST to add services endpoint (ServiceNames is nil, so UpdateAccount will try to add)
				return r.Method == "POST" && strings.Contains(r.URL.Path, "services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match DELETE to services endpoint
				return r.Method == "DELETE" && strings.Contains(r.URL.Path, "services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: deleteServicesResponse,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match subsequent GET requests
				return r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc") && getCallCount > 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: updatedAccountJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call UpdateAccount to remove CEM service
	result, err := service.TfUpdateAccount(&awsmodels.TfIdsecCCEAWSUpdateAccount{
		ID: "1111aaaa2222bbbb3333cccc",
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]any{
					"ScaRoleArn": "arn:aws:iam::123456789012:role/SCARole",
				},
			},
		},
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "1111aaaa2222bbbb3333cccc", result.ID)
	require.Equal(t, region, result.Region)
	require.Equal(t, displayName, result.DisplayName)
	require.Equal(t, status, result.Status)
}

func TestUpdateAccount_AddAndRemoveServices_Success(t *testing.T) {
	region := "us-east-1"
	displayName := "Test Account"
	status := ccemodels.CompletelyAdded

	// First response: GET current account with SCA and CDS
	currentAccountJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"services": ["sca", "cds"],
		"servicesData": [
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			},
			{
				"name": "cds",
				"status": "Completely added",
				"errors": []
			}
		],
		"displayName": "Test Account",
		"status": "Completely added"
	}`

	// Second response: POST add SCA service
	addServicesResponse := `{}`

	// Third response: DELETE CDS service
	deleteServicesResponse := `{}`

	// Fourth response: GET updated account with CDS and SCA
	updatedAccountJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"services": ["cds", "sca"],
		"servicesData": [
			{
				"name": "cds",
				"status": "Completely added",
				"errors": []
			},
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			}
		],
		"displayName": "Test Account",
		"status": "Completely added"
	}`

	getCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				// Match first GET request
				if r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc") && getCallCount == 0 {
					getCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusOK,
			ResponseBody: currentAccountJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match POST to services endpoint
				return r.Method == "POST" && strings.Contains(r.URL.Path, "services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: addServicesResponse,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match DELETE to services endpoint
				return r.Method == "DELETE" && strings.Contains(r.URL.Path, "services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: deleteServicesResponse,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match subsequent GET requests
				return r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc") && getCallCount > 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: updatedAccountJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call UpdateAccount to add SCA and remove CEM
	result, err := service.TfUpdateAccount(&awsmodels.TfIdsecCCEAWSUpdateAccount{
		ID: "1111aaaa2222bbbb3333cccc",
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.CDS,
				Resources: map[string]any{
					"CdsRoleArn": "arn:aws:iam::123456789012:role/CDSRole",
				},
			},
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]any{
					"ScaRoleArn": "arn:aws:iam::123456789012:role/SCARole",
				},
			},
		},
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "1111aaaa2222bbbb3333cccc", result.ID)

	require.Equal(t, region, result.Region)
	require.Equal(t, displayName, result.DisplayName)
	require.Equal(t, status, result.Status)
}

func TestUpdateAccount_NoChanges_Success(t *testing.T) {
	region := "us-east-1"
	displayName := "Test Account"
	status := ccemodels.CompletelyAdded

	// First response: GET current account
	currentAccountJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "terraform_provider",
		"region": "us-east-1",
		"services": ["sca"],
		"servicesData": [
			{
				"name": "sca",
				"status": "Completely added",
				"errors": []
			}
		],
		"displayName": "Test Account",
		"status": "Completely added"
	}`

	// Since ServiceNames is nil, UpdateAccount will try to add services
	// Second response: POST to add services endpoint
	addServicesResponse := `{}`
	// Third response: GET account again (no add/remove operations)
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				// Match first GET request
				return r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: currentAccountJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match POST to add services endpoint (ServiceNames is nil, so UpdateAccount will try to add)
				return r.Method == "POST" && strings.Contains(r.URL.Path, "services")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: addServicesResponse,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match subsequent GET requests
				return r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: currentAccountJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call UpdateAccount with same services (no changes)
	result, err := service.TfUpdateAccount(&awsmodels.TfIdsecCCEAWSUpdateAccount{
		ID: "1111aaaa2222bbbb3333cccc",
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]any{
					"ScaRoleArn": "arn:aws:iam::123456789012:role/SCARole",
				},
			},
		},
	})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "1111aaaa2222bbbb3333cccc", result.ID)
	// ServiceNames is populated by Deserialize method in TfAccount

	require.Equal(t, region, result.Region)
	require.Equal(t, displayName, result.DisplayName)
	require.Equal(t, status, result.Status)
}

func TestUpdateAccount_ErrorPropagation(t *testing.T) {
	// Test error when getting current account fails
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return true // Match any request
			},
			StatusCode:   http.StatusNotFound,
			ResponseBody: `{"error": "account not found"}`,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	_, err := service.TfUpdateAccount(&awsmodels.TfIdsecCCEAWSUpdateAccount{
		ID: "nonexistent",
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.SCA,
				Resources:   map[string]any{},
			},
		},
	})
	require.Error(t, err)
}

func TestUpdateAccount_EmptyServicesArray_Returns400(t *testing.T) {
	// First response: GET current account with 1 service (DPA)
	currentAccountJSON := `{
		"id": "1111aaaa2222bbbb3333cccc",
		"accountId": "123456789012",
		"onboardingType": "programmatic",
		"region": "us-east-1",
		"services": ["dpa"],
		"servicesData": [
			{
				"name": "dpa",
				"status": "Completely added",
				"errors": []
			}
		],
		"displayName": "Test Account",
		"status": "Completely added"
	}`

	// ServiceNames is populated by Deserialize, so UpdateAccount will detect current services
	// and try to remove them, which should return a 400 error
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				// Match GET request to fetch current account
				return r.Method == "GET" && strings.Contains(r.URL.Path, "1111aaaa2222bbbb3333cccc")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: currentAccountJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				// Match DELETE request to remove services (will fail with 400)
				return r.Method == "DELETE" && strings.Contains(r.URL.Path, "services")
			},
			StatusCode: http.StatusBadRequest,
			ResponseBody: `{
				"code": "400",
				"message": "Bad Request",
				"description": "An account must have at least one service. If you want to remove the service, you must remove the account instead. Use the remove account API.",
				"attributes": null
			}`,
			OnRequest: func(r *http.Request) {
				require.Equal(t, "DELETE", r.Method)
				require.Contains(t, r.URL.Path, "services")
			},
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Attempt to update account with empty services array
	// and try to delete them, which should return a 400 error
	_, err := service.TfUpdateAccount(&awsmodels.TfIdsecCCEAWSUpdateAccount{
		ID:       "1111aaaa2222bbbb3333cccc",
		Services: []ccemodels.IdsecCCEServiceInput{}, // Empty services array
	})

	// Assertions - should return error for 400 Bad Request
	require.Error(t, err)
	require.Contains(t, err.Error(), "400")
	require.Contains(t, err.Error(), "Bad Request")
}
