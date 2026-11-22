//go:build (e2e && ars) || e2e

package ars

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/ars/requests"
	requestsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/ars/requests/models"
	identityusers "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/users"
	usersmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/users/models"
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
	policyvm "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/vm"
	policyvmmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/vm/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

func arsRequestsService(t *testing.T, ctx *framework.TestContext) *requests.IdsecARSRequestsService {
	t.Helper()
	svc, err := ctx.API.ArsRequests()
	require.NoError(t, err, "Failed to get ARS requests service")
	return svc
}

// listAllRequests drains every page of the given list call.
func listAllRequests(t *testing.T, pages <-chan *requests.IdsecARSAccessRequestsPage, err error) []*requestsmodels.IdsecARSAccessRequest {
	t.Helper()
	require.NoError(t, err, "Failed to list access requests")
	var all []*requestsmodels.IdsecARSAccessRequest
	for page := range pages {
		all = append(all, page.Items...)
	}
	return all
}

// TestARSListRequestForms verifies that request forms are returned for every supported category and request type.
func TestARSListRequestForms(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: ARS List Request Forms")
		svc := arsRequestsService(t, ctx)

		for _, category := range []string{requestsmodels.TargetCategoryVM, requestsmodels.TargetCategoryCloudConsole} {
			for _, requestType := range []string{requestsmodels.RequestTypeOnDemand, requestsmodels.RequestTypeDualControl} {
				forms, err := svc.ListRequestForms(&requestsmodels.IdsecARSListAccessRequestForms{TargetCategory: category, RequestType: requestType})
				require.NoError(t, err, "Failed to list request forms for [%s] [%s]", category, requestType)
				require.NotNil(t, forms)
				t.Logf("Found %d request form(s) for [%s] [%s]", len(forms.RequestForms), category, requestType)
				for _, form := range forms.RequestForms {
					assert.Equal(t, category, string(form.TargetCategory))
					assert.Equal(t, requestType, string(form.RequestType))
					for _, question := range form.RequestForm.Questions {
						assert.NotEmpty(t, question.Key, "Request form question must have a key")
					}
				}
			}
		}
	}, requests.ServiceConfig)
}

// TestARSListGetAndStats verifies that listing, getting and calculating stats of access requests agree with each other.
func TestARSListGetAndStats(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: ARS List, Get and Stats")
		svc := arsRequestsService(t, ctx)

		t.Log("Step 1: Listing all access requests")
		pages, err := svc.List()
		all := listAllRequests(t, pages, err)
		t.Logf("Found %d access request(s)", len(all))
		for _, request := range all {
			require.NotEmpty(t, request.RequestID)
			require.NotEmpty(t, request.RequestState)
		}

		t.Log("Step 2: Calculating access requests stats")
		stats, err := svc.Stats()
		require.NoError(t, err, "Failed to calculate access requests stats")
		assert.Equal(t, len(all), stats.RequestsCount)

		t.Log("Step 3: Listing extended access requests with a page limit")
		pages, err = svc.ListBy(&requestsmodels.IdsecARSFilter{Extended: true, Limit: 1})
		extended := listAllRequests(t, pages, err)
		assert.Len(t, extended, len(all), "Paging with limit 1 must return every access request")
		if len(extended) == 0 {
			t.Log("No access requests on the tenant, skipping get")
			return
		}

		t.Logf("Step 4: Getting access request [%s]", extended[0].RequestID)
		request, err := svc.Get(&requestsmodels.IdsecARSGetAccessRequest{RequestID: extended[0].RequestID})
		require.NoError(t, err, "Failed to get access request")
		assert.Equal(t, extended[0].RequestID, request.RequestID)
		assert.Equal(t, extended[0].TargetCategory, request.TargetCategory)
		assert.NotEmpty(t, request.CreatedAt)
	}, requests.ServiceConfig)
}

// currentUserPrincipal resolves the authenticated e2e ISP user as a policy principal, since ARS only matches
// policies the requester is a principal of.
func currentUserPrincipal(t *testing.T, ctx *framework.TestContext) policycommonmodels.IdsecPolicyPrincipal {
	t.Helper()
	username := os.Getenv("IDSEC_E2E_ISP_USERNAME")
	require.NotEmpty(t, username, "IDSEC_E2E_ISP_USERNAME must be set")
	usersSvc, err := ctx.API.IdentityUsers()
	require.NoError(t, err, "Failed to get Identity users service")
	user, err := usersSvc.Get(&usersmodels.IdsecIdentityGetUser{Username: username})
	require.NoError(t, err, "Failed to get the e2e user [%s]", username)
	return userPrincipal(user)
}

// createApproverPrincipal creates a throwaway Identity user to approve the access request.
func createApproverPrincipal(t *testing.T, ctx *framework.TestContext) policycommonmodels.IdsecPolicyPrincipal {
	t.Helper()
	usersSvc, err := ctx.API.IdentityUsers()
	require.NoError(t, err, "Failed to get Identity users service")
	username := framework.RandomResourceName("e2e-ars-approver")
	user, err := usersSvc.Create(&usersmodels.IdsecIdentityCreateUser{Username: username})
	require.NoError(t, err, "Failed to create approver user [%s]", username)
	ctx.TrackResourceByType("IdentityUser", user.UserID, func() error {
		return usersSvc.Delete(&usersmodels.IdsecIdentityDeleteUser{UserID: user.UserID})
	})
	return userPrincipal(user)
}

func userPrincipal(user *usersmodels.IdsecIdentityUser) policycommonmodels.IdsecPolicyPrincipal {
	sourceDirectoryID := user.Username
	if idx := strings.LastIndex(user.Username, "@"); idx != -1 {
		sourceDirectoryID = user.Username[idx+1:]
	}
	return policycommonmodels.IdsecPolicyPrincipal{
		Type:                policycommonmodels.PrincipalTypeUser,
		ID:                  user.UserID,
		Name:                user.Username,
		SourceDirectoryName: "CyberArk",
		SourceDirectoryID:   sourceDirectoryID,
	}
}

// createDualControlVMPolicy creates an active UAP SIA VM policy granting the requester SSH access to targetFQDN,
// which requires access approval by approver, and registers its deletion.
func createDualControlVMPolicy(
	t *testing.T,
	ctx *framework.TestContext,
	targetFQDN string,
	requester, approver policycommonmodels.IdsecPolicyPrincipal,
) *policyvmmodels.IdsecPolicyVMAccessPolicy {
	t.Helper()
	policySvc, err := ctx.API.PolicyVm()
	require.NoError(t, err, "Failed to get Policy VM service")
	created, err := policySvc.CreatePolicy(&policyvmmodels.IdsecPolicyVMAccessPolicy{
		IdsecPolicyInfraCommonAccessPolicy: policycommonmodels.IdsecPolicyInfraCommonAccessPolicy{
			IdsecPolicyCommonAccessPolicy: policycommonmodels.IdsecPolicyCommonAccessPolicy{
				Metadata: policycommonmodels.IdsecPolicyMetadata{
					Name:        framework.RandomResourceName("e2e-ars-dual-control"),
					Description: "E2E test: ARS dual control VM access requests",
					Status:      &policycommonmodels.IdsecPolicyStatus{Status: policycommonmodels.StatusTypeActive},
					PolicyEntitlement: policycommonmodels.IdsecPolicyEntitlement{
						TargetCategory: commonmodels.CategoryTypeVM,
						LocationType:   commonmodels.WorkspaceTypeFQDNIP,
						PolicyType:     policycommonmodels.PolicyTypeRecurring,
					},
					PolicyTags: []string{},
					TimeZone:   "GMT",
				},
				Principals:               []policycommonmodels.IdsecPolicyPrincipal{requester},
				DelegationClassification: policycommonmodels.DelegationClassificationUnrestricted,
			},
			Conditions: policycommonmodels.IdsecPolicyInfraCommonConditions{
				AccessWindow: policycommonmodels.IdsecPolicyInfraTimeCondition{
					DaysOfTheWeek: []int{0, 1, 2, 3, 4, 5, 6},
					FromHour:      "00:00",
					ToHour:        "23:59",
				},
				MaxSessionDuration: 1,
				IdleTime:           10,
				AccessApproval: &policycommonmodels.IdsecPolicyAccessApprovalCondition{
					Required:  true,
					Approvers: []policycommonmodels.IdsecPolicyPrincipal{approver},
				},
			},
		},
		Targets: policyvmmodels.IdsecPolicyVMPlatformTargets{
			FQDNIPResource: &policyvmmodels.IdsecPolicyVMFQDNIPResource{
				FQDNRules: []policyvmmodels.IdsecPolicyVMFQDNRule{
					{Operator: policyvmmodels.VMFQDNOperatorExactly, ComputernamePattern: targetFQDN},
				},
			},
		},
		Behavior: policyvmmodels.IdsecPolicyVMBehavior{
			SSHProfile: &policyvmmodels.IdsecPolicyVMSSHProfile{Username: "root"},
		},
	})
	require.NoError(t, err, "Failed to create the dual control VM policy, the tenant must allow VM access approval")
	ctx.TrackResourceByType("VMPolicy", created.Metadata.PolicyID, func() error {
		return policySvc.DeletePolicy(&policycommonmodels.IdsecPolicyDeletePolicyRequest{PolicyID: created.Metadata.PolicyID})
	})
	return created
}

// dualControlVMRequestDetails builds the details of a Linux VM dual control request for tomorrow's working hours.
func dualControlVMRequestDetails(targetFQDN string) map[string]interface{} {
	tomorrow := time.Now().UTC().AddDate(0, 0, 1)
	return map[string]interface{}{
		"target_type":      "Linux",
		"target_address":   targetFQDN,
		"reason":           "E2E test",
		"request_date":     tomorrow.Format("2006-01-02"),
		"request_end_date": tomorrow.AddDate(0, 0, 1).Format("2006-01-02"),
		"time_from":        "08:00",
		"time_to":          "17:00",
		"timezone":         "GMT",
		"priority":         "High",
	}
}

// TestARSSubmitAndCancel creates a UAP SIA VM policy that requires access approval, submits a dual control VM
// access request matching it, waits for it to be pending approval, and cancels it.
// It needs a tenant where VM policies can require access approval, like the VM dual control policy e2e tests.
func TestARSSubmitAndCancel(t *testing.T) {
	framework.Run(t, func(ctx *framework.TestContext) {
		framework.LogSection(t, "Test: ARS Submit and Cancel a dual control VM access request")
		svc := arsRequestsService(t, ctx)

		// A random target per run, since ARS caches policy evaluation per target for a few minutes.
		targetFQDN := framework.RandomResourceName("e2e-ars-vm") + ".local.com"

		t.Logf("Step 1: Creating a dual control VM policy for [%s]", targetFQDN)
		policy := createDualControlVMPolicy(t, ctx, targetFQDN, currentUserPrincipal(t, ctx), createApproverPrincipal(t, ctx))
		t.Logf("Created VM policy [%s]", policy.Metadata.PolicyID)

		t.Log("Step 2: Submitting a dual control VM access request and polling until it is pending")
		submitted, err := svc.Submit(&requestsmodels.IdsecARSSubmitAccessRequest{
			TargetCategory: requestsmodels.TargetCategoryVM,
			RequestType:    requestsmodels.RequestTypeDualControl,
			RequestDetails: dualControlVMRequestDetails(targetFQDN),
			Poll:           true,
		})
		if submitted != nil && submitted.RequestID != "" {
			// Registered after the policy, so it runs first: cancel the request if the test stops before canceling it.
			ctx.TrackResourceByType("ARSAccessRequest", submitted.RequestID, func() error {
				current, getErr := svc.Get(&requestsmodels.IdsecARSGetAccessRequest{RequestID: submitted.RequestID})
				if getErr != nil || current.RequestState == requestsmodels.RequestStateFinished || current.RequestState == requestsmodels.RequestStateExpired {
					return getErr
				}
				_, cancelErr := svc.Cancel(&requestsmodels.IdsecARSCancelAccessRequest{RequestID: submitted.RequestID, CancelReason: "E2E cleanup"})
				return cancelErr
			})
		}
		require.NoError(t, err, "Failed to submit access request")
		t.Logf("Access request [%s] is pending", submitted.RequestID)
		assert.Equal(t, requestsmodels.RequestStatePending, submitted.RequestState)
		assert.Equal(t, requestsmodels.RequestResultUnknown, submitted.RequestResult)
		assert.Equal(t, requestsmodels.TargetCategoryVM, submitted.TargetCategory)
		// The policy fields ARS adds once it matches the request to a policy; reaching pending without a match is impossible.
		profiles, ok := submitted.RequestDetails["profiles"].([]interface{})
		assert.True(t, ok && len(profiles) > 0, "ARS must add the matched policy profiles to the request details, got [%v]", submitted.RequestDetails["profiles"])
		assert.NotEmpty(t, submitted.RequestDetails["location_type"], "ARS must add the matched policy location type to the request details")

		t.Logf("Step 3: Canceling access request [%s] and polling until it finishes", submitted.RequestID)
		canceled, err := svc.Cancel(&requestsmodels.IdsecARSCancelAccessRequest{
			RequestID:    submitted.RequestID,
			CancelReason: "E2E test",
			Poll:         true,
		})
		require.NoError(t, err, "Failed to cancel access request")
		assert.Equal(t, requestsmodels.RequestStateFinished, canceled.RequestState)
		assert.Equal(t, requestsmodels.RequestResultCanceled, canceled.RequestResult)

		t.Log("Step 4: Getting the canceled access request")
		request, err := svc.Get(&requestsmodels.IdsecARSGetAccessRequest{RequestID: submitted.RequestID})
		require.NoError(t, err, "Failed to get canceled access request")
		assert.Equal(t, requestsmodels.RequestResultCanceled, request.RequestResult)
		assert.Equal(t, "E2E test", request.FinalizationReason)
	}, requests.ServiceConfig, policyvm.ServiceConfig, identityusers.ServiceConfig)
}
