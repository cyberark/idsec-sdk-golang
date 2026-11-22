//go:build (e2e && cce) || e2e

package cce

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/gcp"
	gcpmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/gcp/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

const (
	gcpManualURL  = "/api/gcp/manual"
	settleTimeout = 10 * time.Minute
	pollInterval  = 15 * time.Second
	ownershipHint = `set onboarding_type = "terraform_provider"`
)

// inProgressStatuses are the onboarding statuses during which CCE rejects imports, service changes and deletes.
var inProgressStatuses = []string{
	ccemodels.DeployingResources, ccemodels.Removing, ccemodels.WaitingForDeployment, ccemodels.WaitingForConsent,
}

// gcpOnboarding is the part of a GCP project or organization onboarding that the ownership tests check.
type gcpOnboarding struct {
	OnboardingType string
	Status         string
	Services       []string
}

// gcpTarget abstracts over GCP project and organization onboardings so both run the same flow.
type gcpTarget struct {
	name string
	// initialServices are the services the programmatic onboarding is created with.
	initialServices func(t *testing.T) []ccemodels.IdsecCCEServiceInput
	// createBody is the programmatic create request for this target.
	createBody func(t *testing.T, services []ccemodels.IdsecCCEServiceInput) map[string]interface{}
	get        func(svc *gcp.IdsecCCEGCPService, id string) (*gcpOnboarding, error)
	update     func(svc *gcp.IdsecCCEGCPService, id string, services []ccemodels.IdsecCCEServiceInput, onboardingType string) (*gcpOnboarding, error)
	delete     func(svc *gcp.IdsecCCEGCPService, id string) error
}

func requireEnv(t *testing.T, key string) string {
	t.Helper()
	value := os.Getenv(key)
	if value == "" {
		t.Fatalf("%s is not set; it is normally provided by tests/e2e/cce/.env", key)
	}
	return value
}

// dpaService is the dpa service input for the fixed GCP workload identity resources of a hub project.
func dpaService(t *testing.T, projectNumber string) ccemodels.IdsecCCEServiceInput {
	return ccemodels.IdsecCCEServiceInput{
		ServiceName: ccemodels.DPA,
		Version:     "0.0.1",
		Resources: map[string]interface{}{
			"projectNumber":    projectNumber,
			"serviceAccountId": requireEnv(t, "IDSEC_E2E_CCE_GCP_SERVICE_ACCOUNT_ID"),
			"poolId":           requireEnv(t, "IDSEC_E2E_CCE_GCP_POOL_ID"),
			"providerId":       requireEnv(t, "IDSEC_E2E_CCE_GCP_PROVIDER_ID"),
		},
	}
}

var gcpTargets = []gcpTarget{
	{
		name: "Project",
		initialServices: func(t *testing.T) []ccemodels.IdsecCCEServiceInput {
			return []ccemodels.IdsecCCEServiceInput{dpaService(t, requireEnv(t, "IDSEC_E2E_CCE_GCP_PROJECT_NUMBER"))}
		},
		createBody: func(t *testing.T, services []ccemodels.IdsecCCEServiceInput) map[string]interface{} {
			return map[string]interface{}{
				"deploymentType":      "standalone",
				"deploymentProjectId": requireEnv(t, "IDSEC_E2E_CCE_GCP_PROJECT_ID"),
				"organizationId":      requireEnv(t, "IDSEC_E2E_CCE_GCP_PROJECT_ORGANIZATION_ID"),
				"projectNumber":       requireEnv(t, "IDSEC_E2E_CCE_GCP_PROJECT_NUMBER"),
				"services":            services,
			}
		},
		get: func(svc *gcp.IdsecCCEGCPService, id string) (*gcpOnboarding, error) {
			project, err := svc.TfProject(&gcpmodels.TfIdsecCCEGCPGetProject{ID: id})
			if err != nil {
				return nil, err
			}
			return &gcpOnboarding{OnboardingType: project.OnboardingType, Status: project.Status, Services: project.Services}, nil
		},
		update: func(svc *gcp.IdsecCCEGCPService, id string, services []ccemodels.IdsecCCEServiceInput, onboardingType string) (*gcpOnboarding, error) {
			project, err := svc.TfUpdateProject(&gcpmodels.TfIdsecCCEGCPUpdateProject{ID: id, Services: services, OnboardingType: onboardingType})
			if err != nil {
				return nil, err
			}
			return &gcpOnboarding{OnboardingType: project.OnboardingType, Status: project.Status, Services: project.Services}, nil
		},
		delete: func(svc *gcp.IdsecCCEGCPService, id string) error {
			return svc.TfDeleteProject(&gcpmodels.TfIdsecCCEGCPDeleteProject{ID: id})
		},
	},
	{
		name: "Organization",
		initialServices: func(t *testing.T) []ccemodels.IdsecCCEServiceInput {
			return []ccemodels.IdsecCCEServiceInput{dpaService(t, requireEnv(t, "IDSEC_E2E_CCE_GCP_ORG_PROJECT_NUMBER"))}
		},
		createBody: func(t *testing.T, services []ccemodels.IdsecCCEServiceInput) map[string]interface{} {
			deploymentProjectID := requireEnv(t, "IDSEC_E2E_CCE_GCP_ORG_DEPLOYMENT_PROJECT_ID")
			return map[string]interface{}{
				"deploymentType":      "organization",
				"deploymentProjectId": deploymentProjectID,
				"organizationId":      requireEnv(t, "IDSEC_E2E_CCE_GCP_ORGANIZATION_ID"),
				"projectNumber":       requireEnv(t, "IDSEC_E2E_CCE_GCP_ORG_PROJECT_NUMBER"),
				"services":            services,
				"cceResources": map[string]string{
					"workloadIdentityPoolId":     requireEnv(t, "IDSEC_E2E_CCE_GCP_ORG_CCE_POOL_ID"),
					"workloadIdentityProviderId": requireEnv(t, "IDSEC_E2E_CCE_GCP_ORG_CCE_PROVIDER_ID"),
					"targetServiceAccountEmail": fmt.Sprintf("%s@%s.iam.gserviceaccount.com",
						requireEnv(t, "IDSEC_E2E_CCE_GCP_SERVICE_ACCOUNT_ID"), deploymentProjectID),
				},
			}
		},
		get: func(svc *gcp.IdsecCCEGCPService, id string) (*gcpOnboarding, error) {
			org, err := svc.TfOrganization(&gcpmodels.TfIdsecCCEGCPGetOrganization{ID: id})
			if err != nil {
				return nil, err
			}
			return &gcpOnboarding{OnboardingType: org.OnboardingType, Status: org.Status, Services: org.Services}, nil
		},
		update: func(svc *gcp.IdsecCCEGCPService, id string, services []ccemodels.IdsecCCEServiceInput, onboardingType string) (*gcpOnboarding, error) {
			org, err := svc.TfUpdateOrganization(&gcpmodels.TfIdsecCCEGCPUpdateOrganization{ID: id, Services: services, OnboardingType: onboardingType})
			if err != nil {
				return nil, err
			}
			return &gcpOnboarding{OnboardingType: org.OnboardingType, Status: org.Status, Services: org.Services}, nil
		},
		delete: func(svc *gcp.IdsecCCEGCPService, id string) error {
			return svc.TfDeleteOrganization(&gcpmodels.TfIdsecCCEGCPDeleteOrganization{ID: id})
		},
	},
}

// createProgrammaticOnboarding creates a programmatic onboarding through the CCE API directly, since the SDK
// GCP service only creates terraform_provider onboardings. It registers cleanup and waits for the deployment
// to finish, because CCE rejects conversions and service changes while services are being deployed.
func createProgrammaticOnboarding(ctx *framework.TestContext, svc *gcp.IdsecCCEGCPService, target gcpTarget, services []ccemodels.IdsecCCEServiceInput) string {
	t := ctx.T
	t.Helper()

	body := target.createBody(t, services)
	body["onboardingType"] = ccemodels.Programmatic
	response, err := svc.ISPClient().Post(context.Background(), gcpManualURL, body)
	require.NoError(t, err, "programmatic create request failed")
	defer func() { _ = response.Body.Close() }()
	raw, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	require.Truef(t, response.StatusCode >= 200 && response.StatusCode < 300,
		"programmatic create failed: HTTP %d: %s", response.StatusCode, raw)

	var created struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(raw, &created))
	require.NotEmpty(t, created.ID, "programmatic create returned no onboarding ID: %s", raw)
	t.Logf("Created programmatic %s onboarding %s", target.name, created.ID)

	ctx.TrackResourceByType("CCE GCP "+target.name, created.ID, func() error {
		return deleteOnboarding(t, svc, target, created.ID)
	})

	_, err = waitForSettled(t, svc, target, created.ID)
	require.NoError(t, err, "%s %s did not finish deploying", target.name, created.ID)
	return created.ID
}

// waitForSettled polls until the onboarding is no longer deploying or removing and returns its final state.
func waitForSettled(t *testing.T, svc *gcp.IdsecCCEGCPService, target gcpTarget, id string) (*gcpOnboarding, error) {
	var current *gcpOnboarding
	err := framework.WaitForCondition(settleTimeout, pollInterval, func() (bool, error) {
		var err error
		current, err = target.get(svc, id)
		if err != nil {
			return false, err
		}
		t.Logf("%s %s status: %s", target.name, id, current.Status)
		return !slices.Contains(inProgressStatuses, current.Status), nil
	})
	return current, err
}

// deleteOnboarding deletes the onboarding with the delete that matches its type: the SDK delete only accepts
// terraform_provider onboardings, and a failed run may leave the onboarding programmatic. It then waits for
// the removal, so the next run can onboard the same GCP project or organization again.
func deleteOnboarding(t *testing.T, svc *gcp.IdsecCCEGCPService, target gcpTarget, id string) error {
	current, err := waitForSettled(t, svc, target, id)
	if err != nil {
		return err
	}
	if current.OnboardingType == ccemodels.TerraformProvider {
		err = target.delete(svc, id)
	} else {
		err = deleteWithType(svc, id, current.OnboardingType)
	}
	if err != nil {
		return err
	}
	return framework.WaitForCondition(settleTimeout, pollInterval, func() (bool, error) {
		_, err := target.get(svc, id)
		if err == nil {
			return false, nil
		}
		if strings.Contains(err.Error(), "HTTP 404") {
			return true, nil
		}
		return false, err
	})
}

func deleteWithType(svc *gcp.IdsecCCEGCPService, id, onboardingType string) error {
	params := map[string][]string{"onboarding_type": {onboardingType}}
	response, err := svc.ISPClient().Delete(context.Background(), fmt.Sprintf("%s/%s", gcpManualURL, id), nil, params)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		raw, _ := io.ReadAll(response.Body)
		return fmt.Errorf("delete %s onboarding %s: HTTP %d: %s", onboardingType, id, response.StatusCode, raw)
	}
	return nil
}
