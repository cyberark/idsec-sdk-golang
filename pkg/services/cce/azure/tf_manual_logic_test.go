package azure

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	azuremodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/azure/models"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

// captureFirstServiceVersion returns a callback that captures the version of
// the first service in the request body's "services" array.
// Safe to use inside OnRequest (no testify calls in the HTTP handler goroutine).
func captureFirstServiceVersion(version *string) func(*http.Request) {
	return func(r *http.Request) {
		var payload map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		if services, ok := payload["services"].([]interface{}); ok && len(services) > 0 {
			if svc, ok := services[0].(map[string]interface{}); ok {
				*version, _ = svc["version"].(string)
			}
		}
	}
}

// captureCCEVersion returns a callback that captures the cceVersion from the request body.
// Safe to use inside OnRequest (no testify calls in the HTTP handler goroutine).
func captureCCEVersion(version *string) func(*http.Request) {
	return func(r *http.Request) {
		var payload map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		if v, ok := payload["cceVersion"].(string); ok {
			*version = v
		}
	}
}

// azureUpdateEntity describes one Azure manual-onboarding entity whose update flow goes through
// the shared UpdateServicesWithReconcile logic.
type azureUpdateEntity struct {
	name    string
	getPath string
	update  func(service *IdsecCCEAzureService, id string, services []ccemodels.IdsecCCEServiceInput, cceVersion *string) error
}

var azureUpdateEntities = []azureUpdateEntity{
	{
		name:    "entra",
		getPath: pathManualEntraGetURL,
		update: func(service *IdsecCCEAzureService, id string, services []ccemodels.IdsecCCEServiceInput, cceVersion *string) error {
			_, err := service.TfUpdateEntra(&azuremodels.TfIdsecCCEAzureUpdateEntra{ID: id, Services: services, CCEVersion: cceVersion})
			return err
		},
	},
	{
		name:    "management_group",
		getPath: pathManualMgmtGroupGetURL,
		update: func(service *IdsecCCEAzureService, id string, services []ccemodels.IdsecCCEServiceInput, cceVersion *string) error {
			_, err := service.TfUpdateManagementGroup(&azuremodels.TfIdsecCCEAzureUpdateManagementGroup{ID: id, Services: services, CCEVersion: cceVersion})
			return err
		},
	},
	{
		name:    "subscription",
		getPath: pathManualSubscriptionGetURL,
		update: func(service *IdsecCCEAzureService, id string, services []ccemodels.IdsecCCEServiceInput, cceVersion *string) error {
			_, err := service.TfUpdateSubscription(&azuremodels.TfIdsecCCEAzureUpdateSubscription{ID: id, Services: services, CCEVersion: cceVersion})
			return err
		},
	},
}

// TestTfGetAzureEntities_CCEResourcesDecoded verifies that when the GET response contains
// cceResources, the field is correctly decoded in each entity's response struct.
func TestTfGetAzureEntities_CCEResourcesDecoded(t *testing.T) {
	const onboardingID = "azure-entity-123"
	const appID = "app-uuid-abc"
	responseJSON := `{
		"id": "` + onboardingID + `",
		"onboardingType": "terraform_provider",
		"services": ["dpa"],
		"status": "Completely added",
		"cceResources": {"appId": "` + appID + `"}
	}`

	type entityCase struct {
		name    string
		getPath string
		get     func(*IdsecCCEAzureService) (map[string]interface{}, error)
	}
	entities := []entityCase{
		{
			name:    "entra",
			getPath: pathManualEntraGetURL,
			get: func(s *IdsecCCEAzureService) (map[string]interface{}, error) {
				result, err := s.TfEntra(&azuremodels.TfIdsecCCEAzureGetEntra{ID: onboardingID})
				if result == nil {
					return nil, err
				}
				return result.CCEResources, err
			},
		},
		{
			name:    "management_group",
			getPath: pathManualMgmtGroupGetURL,
			get: func(s *IdsecCCEAzureService) (map[string]interface{}, error) {
				result, err := s.TfManagementGroup(&azuremodels.TfIdsecCCEAzureGetManagementGroup{ID: onboardingID})
				if result == nil {
					return nil, err
				}
				return result.CCEResources, err
			},
		},
		{
			name:    "subscription",
			getPath: pathManualSubscriptionGetURL,
			get: func(s *IdsecCCEAzureService) (map[string]interface{}, error) {
				result, err := s.TfSubscription(&azuremodels.TfIdsecCCEAzureGetSubscription{ID: onboardingID})
				if result == nil {
					return nil, err
				}
				return result.CCEResources, err
			},
		},
	}

	for _, entity := range entities {
		t.Run(entity.name, func(t *testing.T) {
			client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
				{
					Matcher: func(r *http.Request) bool {
						return r.Method == http.MethodGet && r.URL.Path == fmt.Sprintf(entity.getPath, onboardingID)
					},
					StatusCode:   http.StatusOK,
					ResponseBody: responseJSON,
				},
			})
			defer cleanup()

			resources, err := entity.get(setupAzureService(client))
			require.NoError(t, err)
			require.Equal(t, appID, resources["appId"], "cceResources.appId must be decoded from the GET response")
		})
	}
}

// TestTfUpdateAzureEntities_CCEResourcesReachesRequest verifies that a non-nil CCEResources on the
// Update input is forwarded to the add-services POST body for each entity type.
func TestTfUpdateAzureEntities_CCEResourcesReachesRequest(t *testing.T) {
	const onboardingID = "azure-onboarding-123"
	appID := "app-uuid-123"
	cceResources := &map[string]interface{}{"appId": appID}

	// Entity has no services currently deployed, so any service in desired is treated as new.
	currentJSON := `{
		"id": "` + onboardingID + `",
		"onboardingType": "terraform_provider",
		"services": [],
		"servicesData": [],
		"status": "Completely added"
	}`

	type entityCase struct {
		name    string
		getPath string
		update  func(*IdsecCCEAzureService) error
	}
	entities := []entityCase{
		{
			name:    "entra",
			getPath: pathManualEntraGetURL,
			update: func(s *IdsecCCEAzureService) error {
				_, err := s.TfUpdateEntra(&azuremodels.TfIdsecCCEAzureUpdateEntra{
					ID:           onboardingID,
					CCEResources: cceResources,
				})
				return err
			},
		},
		{
			name:    "management_group",
			getPath: pathManualMgmtGroupGetURL,
			update: func(s *IdsecCCEAzureService) error {
				_, err := s.TfUpdateManagementGroup(&azuremodels.TfIdsecCCEAzureUpdateManagementGroup{
					ID:           onboardingID,
					CCEResources: cceResources,
				})
				return err
			},
		},
		{
			name:    "subscription",
			getPath: pathManualSubscriptionGetURL,
			update: func(s *IdsecCCEAzureService) error {
				_, err := s.TfUpdateSubscription(&azuremodels.TfIdsecCCEAzureUpdateSubscription{
					ID:           onboardingID,
					CCEResources: cceResources,
				})
				return err
			},
		},
	}

	for _, entity := range entities {
		t.Run(entity.name, func(t *testing.T) {
			var postBody map[string]interface{}

			client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
				{
					Matcher: func(r *http.Request) bool {
						return r.Method == http.MethodGet && r.URL.Path == fmt.Sprintf(entity.getPath, onboardingID)
					},
					StatusCode:   http.StatusOK,
					ResponseBody: currentJSON,
				},
				{
					Matcher: func(r *http.Request) bool {
						return r.Method == http.MethodPost && r.URL.Path == "/api/azure/manual/"+onboardingID+"/services"
					},
					StatusCode:   http.StatusOK,
					ResponseBody: currentJSON,
					OnRequest: func(r *http.Request) {
						body, _ := io.ReadAll(r.Body)
						_ = json.Unmarshal(body, &postBody)
					},
				},
			})
			defer cleanup()

			err := entity.update(setupAzureService(client))
			require.NoError(t, err)
			require.Contains(t, postBody, "cceResources", "cceResources must be forwarded to the add-services POST body")
			gotResources, _ := postBody["cceResources"].(map[string]interface{})
			require.Equal(t, appID, gotResources["appId"])
		})
	}
}

// TestTfUpdateAzureEntities_CCEVersionSentOnlyWhenChanged is a regression guard for sending an
// unchanged cceVersion along with a service upgrade on Entra, Management Group and Subscription.
//
// The API treats the presence of a cceVersion as a request to upgrade 'cce' and validates it against
// the upgrade feature flag, so echoing it unchanged made an ordinary service upgrade fail with
// 501 FEATURE_NOT_IMPLEMENTED on 'cce'. The Terraform provider (UpdateOnlyModified) passes an
// unchanged cce_version as nil, which must not be sent.
func TestTfUpdateAzureEntities_CCEVersionSentOnlyWhenChanged(t *testing.T) {
	const onboardingID = "azure-onboarding-123"
	// dpa is onboarded at 0.0.3 on CCE 0.0.1.
	currentJSON := `{
		"id": "` + onboardingID + `",
		"onboardingType": "terraform_provider",
		"services": ["dpa"],
		"servicesData": [
			{"name": "dpa", "version": "0.0.3", "status": "Completely added", "errors": []}
		],
		"cceVersion": "0.0.1",
		"status": "Completely added"
	}`

	cases := []struct {
		name               string
		cceVersion         *string
		expectCCEVersion   bool
		expectedCCEVersion string
	}{
		{name: "nil_cce_version_is_omitted", cceVersion: nil, expectCCEVersion: false},
		{name: "empty_cce_version_is_omitted", cceVersion: common.Ptr(""), expectCCEVersion: false},
		{name: "supplied_cce_version_is_sent", cceVersion: common.Ptr("0.1.0"), expectCCEVersion: true, expectedCCEVersion: "0.1.0"},
	}

	for _, entity := range azureUpdateEntities {
		for _, tc := range cases {
			t.Run(entity.name+"/"+tc.name, func(t *testing.T) {
				var postCount int
				var postBody map[string]interface{}
				client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
					{
						Matcher: func(r *http.Request) bool {
							return r.Method == http.MethodGet && r.URL.Path == fmt.Sprintf(entity.getPath, onboardingID)
						},
						StatusCode:   http.StatusOK,
						ResponseBody: currentJSON,
					},
					{
						Matcher: func(r *http.Request) bool {
							return r.Method == http.MethodPost && r.URL.Path == "/api/azure/manual/"+onboardingID+"/services"
						},
						StatusCode:   http.StatusOK,
						ResponseBody: `{}`,
						OnRequest: func(r *http.Request) {
							postCount++
							body, _ := io.ReadAll(r.Body)
							_ = json.Unmarshal(body, &postBody)
						},
					},
				})
				defer cleanup()

				service := setupAzureService(client)

				// dpa upgrades 0.0.3 -> 0.0.4.
				err := entity.update(service, onboardingID, []ccemodels.IdsecCCEServiceInput{
					{ServiceName: ccemodels.DPA, Version: "0.0.4", Resources: map[string]interface{}{}},
				}, tc.cceVersion)

				require.NoError(t, err)
				require.Equal(t, 1, postCount, "the service version upgrade must trigger exactly one add/update-services call")
				require.Len(t, postBody["services"], 1, "the upgraded service must be sent")
				cceVersion, hasCCEVersion := postBody["cceVersion"]
				require.Equal(t, tc.expectCCEVersion, hasCCEVersion, "cceVersion must be sent only when supplied")
				if tc.expectCCEVersion {
					require.Equal(t, tc.expectedCCEVersion, cceVersion)
				}
			})
		}
	}
}
