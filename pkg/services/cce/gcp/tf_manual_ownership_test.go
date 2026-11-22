package gcp

import (
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
	gcpmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/gcp/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

const (
	ownershipOnboardingID = "onboarding-abc123"
	ownershipImportURL    = "/api/manual/" + ownershipOnboardingID + "/import"
	ownershipServicesURL  = "/api/gcp/manual/" + ownershipOnboardingID + "/services"
)

// ownershipTarget abstracts over the Project and organization update flows so both are covered by the same cases.
type ownershipTarget struct {
	name   string
	getURL string
	update func(service *IdsecCCEGCPService, requestedType string) (string, error)
}

// ownershipDesiredServices adds sca to the onboarded dpa, so every successful update issues a service change.
var ownershipDesiredServices = []ccemodels.IdsecCCEServiceInput{
	{ServiceName: ccemodels.DPA, Resources: map[string]interface{}{}},
	{ServiceName: ccemodels.SCA, Resources: map[string]interface{}{}},
}

var ownershipTargets = []ownershipTarget{
	{
		name:   "Project",
		getURL: "/api/gcp/manual/project/" + ownershipOnboardingID,
		update: func(service *IdsecCCEGCPService, requestedType string) (string, error) {
			project, err := service.TfUpdateProject(&gcpmodels.TfIdsecCCEGCPUpdateProject{
				ID: ownershipOnboardingID, Services: ownershipDesiredServices, OnboardingType: requestedType,
			})
			if err != nil {
				return "", err
			}
			return project.OnboardingType, nil
		},
	},
	{
		name:   "Organization",
		getURL: "/api/gcp/manual/organization/" + ownershipOnboardingID,
		update: func(service *IdsecCCEGCPService, requestedType string) (string, error) {
			org, err := service.TfUpdateOrganization(&gcpmodels.TfIdsecCCEGCPUpdateOrganization{
				ID: ownershipOnboardingID, Services: ownershipDesiredServices, OnboardingType: requestedType,
			})
			if err != nil {
				return "", err
			}
			return org.OnboardingType, nil
		},
	},
}

func ownershipRecordJSON(onboardingType string) string {
	return `{"id": "` + ownershipOnboardingID + `", "onboardingType": "` + onboardingType + `", "status": "Completely added", "services": ["dpa"]}`
}

// cceErrorBody mirrors the ApiBasicError body returned by the CCE backend.
func cceErrorBody(code, message, description, appErrorCode string) string {
	return `{"code": "` + code + `", "message": "` + message + `", "description": "` + description + `", "app_error_code": "` + appErrorCode + `"}`
}

// ownershipBackend records the order of the calls made against a mocked onboarding whose first GET reports
// currentType and every later GET reports terraform_provider.
type ownershipBackend struct {
	calls      []string
	importBody []byte
}

func newOwnershipBackend(t *testing.T, target ownershipTarget, currentType string, importStatus int, importResponse string) (*ownershipBackend, *IdsecCCEGCPService) {
	t.Helper()
	backend := &ownershipBackend{}
	getCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == http.MethodGet && r.URL.Path == target.getURL && getCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: ownershipRecordJSON(currentType),
			OnRequest: func(r *http.Request) {
				getCount++
				backend.calls = append(backend.calls, "GET")
			},
		},
		{
			Matcher:      func(r *http.Request) bool { return r.Method == http.MethodGet && r.URL.Path == target.getURL },
			StatusCode:   http.StatusOK,
			ResponseBody: ownershipRecordJSON(ccemodels.TerraformProvider),
			OnRequest:    func(r *http.Request) { backend.calls = append(backend.calls, "GET") },
		},
		{
			Matcher:      func(r *http.Request) bool { return r.Method == http.MethodPost && r.URL.Path == ownershipImportURL },
			StatusCode:   importStatus,
			ResponseBody: importResponse,
			OnRequest: func(r *http.Request) {
				backend.calls = append(backend.calls, "IMPORT")
				backend.importBody, _ = io.ReadAll(r.Body)
			},
		},
		{
			Matcher:      func(r *http.Request) bool { return r.Method == http.MethodPost && r.URL.Path == ownershipServicesURL },
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
			OnRequest:    func(r *http.Request) { backend.calls = append(backend.calls, "ADD_SERVICES") },
		},
	})
	t.Cleanup(cleanup)
	return backend, setupGCPService(client)
}

func TestTfUpdate_ProgrammaticWithOptIn_ConvertsBeforeServiceChanges(t *testing.T) {
	for _, target := range ownershipTargets {
		t.Run(target.name, func(t *testing.T) {
			backend, service := newOwnershipBackend(t, target, ccemodels.Programmatic, http.StatusOK, "")

			onboardingType, err := target.update(service, ccemodels.TerraformProvider)

			require.NoError(t, err)
			require.Equal(t, ccemodels.TerraformProvider, onboardingType)
			require.Equal(t, []string{"GET", "IMPORT", "ADD_SERVICES", "GET"}, backend.calls,
				"the backend rejects service changes on a programmatic onboarding, so it must be converted first")
			require.Empty(t, backend.importBody, "import takes only the onboarding ID in the path")
		})
	}
}

func TestTfUpdate_ProgrammaticWithoutOptIn_IsRejected(t *testing.T) {
	for _, target := range ownershipTargets {
		t.Run(target.name, func(t *testing.T) {
			backend, service := newOwnershipBackend(t, target, ccemodels.Programmatic, http.StatusOK, "")

			_, err := target.update(service, "")

			require.Error(t, err)
			require.ErrorContains(t, err, `set onboarding_type = "terraform_provider"`)
			require.Equal(t, []string{"GET"}, backend.calls, "nothing may change without the explicit opt-in")
		})
	}
}

func TestTfUpdate_NonProgrammatic_SkipsConversion(t *testing.T) {
	cases := []struct {
		name          string
		currentType   string
		requestedType string
	}{
		{name: "TerraformProviderWithOptIn", currentType: ccemodels.TerraformProvider, requestedType: ccemodels.TerraformProvider},
		{name: "TerraformProviderWithoutOptIn", currentType: ccemodels.TerraformProvider, requestedType: ""},
		{name: "StandardLeftToBackend", currentType: "standard", requestedType: ccemodels.TerraformProvider},
	}
	for _, target := range ownershipTargets {
		for _, tc := range cases {
			t.Run(target.name+"_"+tc.name, func(t *testing.T) {
				backend, service := newOwnershipBackend(t, target, tc.currentType, http.StatusOK, "")

				_, err := target.update(service, tc.requestedType)

				require.NoError(t, err)
				require.Equal(t, []string{"GET", "ADD_SERVICES", "GET"}, backend.calls)
			})
		}
	}
}

func TestTfUpdate_ConversionRejected_LeavesServicesUnchanged(t *testing.T) {
	rejections := []struct {
		name        string
		statusCode  int
		description string
	}{
		{name: "IneligibleOnboardingType", statusCode: http.StatusBadRequest, description: "This type is not supported for import."},
		{name: "OngoingDeployment", statusCode: http.StatusBadRequest, description: "Cannot import the onboarding while one of its services is being deployed or removed."},
		{name: "UnknownOnboarding", statusCode: http.StatusNotFound, description: "An onboarding with this ID was not found."},
	}
	for _, target := range ownershipTargets {
		for _, rejection := range rejections {
			t.Run(target.name+"_"+rejection.name, func(t *testing.T) {
				body := cceErrorBody("400", "Bad Request", rejection.description, "BAD_REQUEST")
				backend, service := newOwnershipBackend(t, target, ccemodels.Programmatic, rejection.statusCode, body)

				_, err := target.update(service, ccemodels.TerraformProvider)

				require.Error(t, err)
				require.ErrorContains(t, err, rejection.description)
				apiErr, ok := internal.AsAPIError(err)
				require.True(t, ok, "the backend rejection must be returned as an APIError, got %T", err)
				require.Equal(t, rejection.statusCode, apiErr.StatusCode)
				require.Equal(t, rejection.description, apiErr.Message)
				require.Equal(t, []string{"GET", "IMPORT"}, backend.calls)
			})
		}
	}
}
