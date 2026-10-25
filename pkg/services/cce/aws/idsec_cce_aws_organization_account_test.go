package aws

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	awsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/aws/models"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

const (
	// mockAWSAccountID is the test AWS account ID (12 digits) used across all mock responses
	mockAWSAccountID = "123456789012"
	// mockOrganizationOnboardingID is the test organization onboarding ID used across all mock responses
	mockOrganizationOnboardingID = "0000aaaa0000bbbb0000cccc0000dddd"
	// mockAccountOnboardingID is the test account onboarding ID used across all mock responses
	mockAccountOnboardingID = "aaaa1111bbbb2222cccc3333dddd4444"
	// mockOnboardingType is the onboarding type used across all mock responses
	mockOnboardingType = ccemodels.TerraformProvider
	// mockAddAccountResponseJSON represents the response when adding an account to an organization
	mockAddAccountResponseJSON = `{"id": "` + mockAccountOnboardingID + `"}`
	// mockAccountDetailsJSON represents a successful account onboarding response
	mockAccountDetailsJSON = `{
		"id": "` + mockAccountOnboardingID + `",
		"account_id": "` + mockAWSAccountID + `",
		"onboarding_type": "` + mockOnboardingType + `",
		"services": ["dpa"],
		"services_data": [
			{
				"name": "dpa",
				"status": "Completely added",
				"errors": []
			}
		],
		"status": "Completely added"
	}`
)

func TestScanOrganization_Success(t *testing.T) {
	// ScanOrganization returns empty response
	responseJSON := `{}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/organizations/scan")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call ScanOrganization
	result, err := service.ScanOrganization(&awsmodels.IdsecCCEAWSScanOrganization{})

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestScanOrganization_ScanInProgress(t *testing.T) {
	// Mock 409 Conflict response
	responseJSON := `{
		"code": "409",
		"message": "Conflict",
		"description": "A scan is already in progress for the tenant at AWS"
	}`

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/organizations/scan")
			},
			StatusCode:   http.StatusConflict,
			ResponseBody: responseJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Call ScanOrganization
	result, err := service.ScanOrganization(&awsmodels.IdsecCCEAWSScanOrganization{})

	// Assertions
	require.Error(t, err)
	require.Nil(t, result)
	require.Contains(t, err.Error(), "failed to trigger organization scan")
}

func TestScanOrganization_ErrorPropagation(t *testing.T) {
	internal.TestServiceErrorPropagation(t, func(client *isp.IdsecISPServiceClient) error {
		service := setupAWSService(client)
		_, err := service.ScanOrganization(&awsmodels.IdsecCCEAWSScanOrganization{})
		return err
	})
}

func TestAddOrganizationAccountSync_Success(t *testing.T) {
	// Sync version - returns full account details

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/") && strings.Contains(r.URL.Path, "/account")
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: mockAddAccountResponseJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID)
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Create input with sync struct
	input := &awsmodels.IdsecCCEAWSAddOrganizationAccountSync{
		IdsecCCEAWSAddOrganizationAccount: awsmodels.IdsecCCEAWSAddOrganizationAccount{
			ParentOrganizationID: mockOrganizationOnboardingID,
			AccountID:            mockAWSAccountID,
			Services: []ccemodels.IdsecCCEServiceInput{
				{
					ServiceName: ccemodels.DPA,
					Resources: map[string]interface{}{
						"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
					},
				},
			},
		},
	}

	// Call AddOrganizationAccountSync
	account, err := service.TfAddOrganizationAccountSync(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, mockAccountOnboardingID, account.ID)
	require.Equal(t, mockAWSAccountID, account.AccountID)
	require.Equal(t, mockOnboardingType, account.OnboardingType)
}

func TestAddOrganizationAccountSync_NoContentResolvesOnboardingID(t *testing.T) {
	// The add-account endpoint is an idempotent upsert: if the request already matches the account's
	// deployed state (e.g. a retried Create after a previous apply already onboarded it), it answers
	// 204 No Content with no body. The onboarding ID must then be resolved via the workspaces listing
	// so the caller can still fetch full account details and populate the Terraform resource ID.
	workspacesJSON := `{
		"workspaces": [
			{
				"key": "` + mockAccountOnboardingID + `",
				"data": {
					"id": "` + mockAccountOnboardingID + `",
					"platform_id": "` + mockAWSAccountID + `",
					"display_name": "Member Account",
					"type": "aws_account",
					"platform_type": "AWS"
				},
				"leaf": true,
				"parent_id": "` + mockOrganizationOnboardingID + `"
			}
		],
		"page": {
			"page_number": 1,
			"page_size": 100,
			"is_last_page": true,
			"total_records": 1
		}
	}`

	var addAccountCallCount int
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/") && strings.Contains(r.URL.Path, "/account")
			},
			StatusCode:   http.StatusNoContent,
			ResponseBody: "",
			OnRequest:    func(r *http.Request) { addAccountCallCount++ },
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/workspaces")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: workspacesJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID)
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.IdsecCCEAWSAddOrganizationAccountSync{
		IdsecCCEAWSAddOrganizationAccount: awsmodels.IdsecCCEAWSAddOrganizationAccount{
			ParentOrganizationID: mockOrganizationOnboardingID,
			AccountID:            mockAWSAccountID,
			Services: []ccemodels.IdsecCCEServiceInput{
				{
					ServiceName: ccemodels.DPA,
					Resources: map[string]interface{}{
						"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
					},
				},
			},
		},
	}

	account, err := service.TfAddOrganizationAccountSync(input)

	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, mockAccountOnboardingID, account.ID)
	require.Equal(t, mockAWSAccountID, account.AccountID)
	require.Equal(t, 1, addAccountCallCount)
}

func TestAddOrganizationAccountSync_With404AndQuickRetry(t *testing.T) {
	// Test the retry logic with fast intervals
	// This test verifies that the sync function polls Organization endpoint for scan completion

	// completedScanTime must be safely AFTER the scanStartTime the code captures inside the call
	// (time.Now() taken just before triggering the scan). We can't predict how long the initial
	// add-account round-trip and client setup take before that point, so use a comfortably large
	// future offset rather than a tight +1s that a slow first request can overrun (which would make
	// scanTime.After(scanStartTime) never true and time out the poll).
	completedScanTime := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
	oldScanTime := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)

	addAccountCallCount := 0
	scanCallCount := 0
	orgCallCount := 0

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			// Scan endpoint - called once
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/organizations/scan") {
					// Validate request body contains correct AWS organization ID
					bodyBytes, _ := io.ReadAll(r.Body)
					// Restore body for subsequent reads
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					bodyStr := string(bodyBytes)
					// Verify the AWS organization ID (o-123) is passed, not the onboarding ID
					require.Contains(t, bodyStr, `"organizationId":"o-123"`, "Expected scan to be triggered with AWS organization ID 'o-123'")
					return true
				}
				return false
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
			OnRequest: func(r *http.Request) {
				scanCallCount++
			},
		},
		{
			// Organization endpoint - first call returns old timestamp, second returns new
			Matcher: func(r *http.Request) bool {
				if r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID) &&
					!strings.Contains(r.URL.Path, "/account") {
					orgCallCount++
					return orgCallCount == 1
				}
				return false
			},
			StatusCode: http.StatusOK,
			ResponseBody: `{
				"id": "org-123",
				"managementAccountId": "` + mockAWSAccountID + `",
				"organizationId": "o-123",
				"onboardingType": "` + mockOnboardingType + `",
				"lastSuccessfulScan": "` + oldScanTime + `"
			}`,
		},
		{
			// Organization endpoint - subsequent calls return completed scan timestamp
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID) &&
					!strings.Contains(r.URL.Path, "/account") && orgCallCount >= 2
			},
			StatusCode: http.StatusOK,
			ResponseBody: `{
				"id": "org-123",
				"managementAccountId": "` + mockAWSAccountID + `",
				"organizationId": "o-123",
				"onboardingType": "` + mockOnboardingType + `",
				"lastSuccessfulScan": "` + completedScanTime + `"
			}`,
		},
		{
			// First call to add account - returns 404
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/") && strings.Contains(r.URL.Path, "/account") {
					addAccountCallCount++
					return addAccountCallCount == 1
				}
				return false
			},
			StatusCode: http.StatusNotFound,
			ResponseBody: `{
				"code": "404",
				"message": "Account not found"
			}`,
		},
		{
			// Second call to add account - returns success
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/") &&
					strings.Contains(r.URL.Path, "/account") && addAccountCallCount >= 2
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: mockAddAccountResponseJSON,
		},
		{
			// Get account details
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID)
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Configure fast retries for testing (no delay between retries)
	maxRetries := 5
	retryIntervalSeconds := 0

	input := &awsmodels.IdsecCCEAWSAddOrganizationAccountSync{
		IdsecCCEAWSAddOrganizationAccount: awsmodels.IdsecCCEAWSAddOrganizationAccount{
			ParentOrganizationID: mockOrganizationOnboardingID,
			AccountID:            mockAWSAccountID,
			Services: []ccemodels.IdsecCCEServiceInput{
				{
					ServiceName: ccemodels.DPA,
					Resources: map[string]interface{}{
						"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
					},
				},
			},
		},
		ScanProbeMaxRetries:      &maxRetries,
		ScanProbeIntervalSeconds: &retryIntervalSeconds,
	}

	// Call AddOrganizationAccountSync
	account, err := service.TfAddOrganizationAccountSync(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, mockAccountOnboardingID, account.ID)
	require.Equal(t, mockAWSAccountID, account.AccountID)
	require.Equal(t, mockOnboardingType, account.OnboardingType)
	// Verify the flow: scan called once, organization polled multiple times, account added twice
	require.Equal(t, 1, scanCallCount, "Expected exactly 1 scan call")
	require.GreaterOrEqual(t, orgCallCount, 2, "Expected at least 2 organization polls")
	require.Equal(t, 2, addAccountCallCount, "Expected 2 calls to add account (first 404, second success)")
}

func TestAddOrganizationAccountSync_With400ScanInProgress(t *testing.T) {
	// Test handling of 400 "scan is in progress" error
	// This test verifies that when we get 400 scan-in-progress, we poll without triggering a new scan

	// completedScanTime must be safely AFTER the scanStartTime the code captures inside the call
	// (time.Now() taken just before it starts polling). Use a comfortably large future offset rather
	// than a tight +1s that a slow first request can overrun (which would make
	// scanTime.After(scanStartTime) never true and time out the poll).
	completedScanTime := time.Now().Add(1 * time.Hour).Format(time.RFC3339Nano)

	addAccountCallCount := 0
	scanCallCount := 0
	orgCallCount := 0

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			// Scan endpoint - should NOT be called for 400 error
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/organizations/scan")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
			OnRequest: func(r *http.Request) {
				scanCallCount++
			},
		},
		{
			// Organization endpoint - returns completed scan timestamp
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID) &&
					!strings.Contains(r.URL.Path, "/account")
			},
			StatusCode: http.StatusOK,
			ResponseBody: `{
				"id": "org-123",
				"managementAccountId": "` + mockAWSAccountID + `",
				"organizationId": "o-123",
				"onboardingType": "` + mockOnboardingType + `",
				"lastSuccessfulScan": "` + completedScanTime + `"
			}`,
			OnRequest: func(r *http.Request) {
				orgCallCount++
			},
		},
		{
			// First call to add account - returns 400 "scan is in progress"
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/") && strings.Contains(r.URL.Path, "/account") {
					addAccountCallCount++
					return addAccountCallCount == 1
				}
				return false
			},
			StatusCode: http.StatusBadRequest,
			ResponseBody: `{
				"app_error_code": "SCAN_IN_PROGRESS",
				"attributes": null,
				"code": "400",
				"description": "scan is in progress, wait for it to finish before onboarding an account resources to organization",
				"message": "Bad Request"
			}`,
		},
		{
			// Second call to add account - returns success
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/") &&
					strings.Contains(r.URL.Path, "/account") && addAccountCallCount >= 2
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: mockAddAccountResponseJSON,
		},
		{
			// Get account details
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID)
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	// Configure fast retries for testing (no delay between retries)
	maxRetries := 5
	retryIntervalSeconds := 0

	input := &awsmodels.IdsecCCEAWSAddOrganizationAccountSync{
		IdsecCCEAWSAddOrganizationAccount: awsmodels.IdsecCCEAWSAddOrganizationAccount{
			ParentOrganizationID: mockOrganizationOnboardingID,
			AccountID:            mockAWSAccountID,
			Services: []ccemodels.IdsecCCEServiceInput{
				{
					ServiceName: ccemodels.DPA,
					Resources: map[string]interface{}{
						"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
					},
				},
			},
		},
		ScanProbeMaxRetries:      &maxRetries,
		ScanProbeIntervalSeconds: &retryIntervalSeconds,
	}

	// Call AddOrganizationAccountSync
	account, err := service.TfAddOrganizationAccountSync(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, mockAccountOnboardingID, account.ID)
	require.Equal(t, mockAWSAccountID, account.AccountID)
	require.Equal(t, mockOnboardingType, account.OnboardingType)
	// Verify the flow: NO scan call, organization polled at least once, account added twice
	require.Equal(t, 0, scanCallCount, "Expected NO scan calls (scan already in progress)")
	require.GreaterOrEqual(t, orgCallCount, 1, "Expected at least 1 organization poll")
	require.Equal(t, 2, addAccountCallCount, "Expected 2 calls to add account (first 400, second success)")
}

// TestAddOrganizationAccountSync_ScanCompletesWhileAddRequestInFlight pins the boundary the
// scan-in-progress wait is measured from. The API decides "scan in progress" from a read taken early
// in its own request, so the scan can record completion while that response is still travelling back
// (~150ms apart in integration). Measured from after the add returns, that completion is already in
// the past, and since this branch starts no new scan, no later timestamp could arrive and the poll
// could only time out.
func TestAddOrganizationAccountSync_ScanCompletesWhileAddRequestInFlight(t *testing.T) {
	testStart := time.Now()

	// Scan completes a moment after the call begins, but well before the add request below returns.
	completedScanTime := testStart.Add(10 * time.Millisecond).Format(time.RFC3339Nano)

	// Comfortably longer than the offset above, so the first add response cannot come back before the
	// scan's recorded completion time.
	const addRequestLatency = 250 * time.Millisecond

	addAccountCallCount := 0
	scanCallCount := 0
	orgCallCount := 0

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/organizations/scan")
			},
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
			OnRequest: func(r *http.Request) {
				scanCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID) &&
					!strings.Contains(r.URL.Path, "/account")
			},
			StatusCode: http.StatusOK,
			ResponseBody: `{
				"id": "org-123",
				"managementAccountId": "` + mockAWSAccountID + `",
				"organizationId": "o-123",
				"onboardingType": "` + mockOnboardingType + `",
				"lastSuccessfulScan": "` + completedScanTime + `"
			}`,
			OnRequest: func(r *http.Request) {
				orgCallCount++
			},
		},
		{
			// First add attempt: held in flight past the scan's completion, then rejected as
			// "scan in progress" - the race the integration run hit.
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/") && strings.Contains(r.URL.Path, "/account") {
					addAccountCallCount++
					return addAccountCallCount == 1
				}
				return false
			},
			StatusCode: http.StatusBadRequest,
			ResponseBody: `{
				"app_error_code": "SCAN_IN_PROGRESS",
				"attributes": null,
				"code": "400",
				"description": "scan is in progress, wait for it to finish before onboarding an account resources to organization",
				"message": "Bad Request"
			}`,
			OnRequest: func(r *http.Request) {
				time.Sleep(addRequestLatency)
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/") &&
					strings.Contains(r.URL.Path, "/account") && addAccountCallCount >= 2
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: mockAddAccountResponseJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID)
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	maxRetries := 3
	retryIntervalSeconds := 0

	input := &awsmodels.IdsecCCEAWSAddOrganizationAccountSync{
		IdsecCCEAWSAddOrganizationAccount: awsmodels.IdsecCCEAWSAddOrganizationAccount{
			ParentOrganizationID: mockOrganizationOnboardingID,
			AccountID:            mockAWSAccountID,
			Services: []ccemodels.IdsecCCEServiceInput{
				{
					ServiceName: ccemodels.DPA,
					Resources: map[string]interface{}{
						"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
					},
				},
			},
		},
		ScanProbeMaxRetries:      &maxRetries,
		ScanProbeIntervalSeconds: &retryIntervalSeconds,
	}

	account, err := service.TfAddOrganizationAccountSync(input)

	require.NoError(t, err, "a scan that completed while the add request was in flight must satisfy the wait")
	require.NotNil(t, account)
	require.Equal(t, mockAccountOnboardingID, account.ID)
	require.Equal(t, 0, scanCallCount, "Expected NO scan calls (scan already in progress)")
	require.Equal(t, 2, addAccountCallCount, "Expected 2 calls to add account (first 400, second success)")
}

// Mock account details JSON with organization ID and services
const mockAccountDetailsWithOrgJSON = `{
	"id": "` + mockAccountOnboardingID + `",
	"account_id": "` + mockAWSAccountID + `",
	"organization_id": "` + mockOrganizationOnboardingID + `",
	"onboarding_type": "` + mockOnboardingType + `",
	"services": ["dpa"],
	"services_data": [
		{
			"name": "dpa",
			"status": "Completely added",
			"errors": []
		}
	],
	"status": "Completely added"
}`

// Mock account details JSON with multiple services
const mockAccountDetailsWithMultipleServicesJSON = `{
	"id": "` + mockAccountOnboardingID + `",
	"account_id": "` + mockAWSAccountID + `",
	"organization_id": "` + mockOrganizationOnboardingID + `",
	"onboarding_type": "` + mockOnboardingType + `",
	"services": ["dpa", "sca"],
	"services_data": [
		{
			"name": "dpa",
			"status": "Completely added",
			"errors": []
		},
		{
			"name": "sca",
			"status": "Completely added",
			"errors": []
		}
	],
	"status": "Completely added"
}`

func TestTfUpdateOrganizationAccount_Success(t *testing.T) {
	// Test successful update with new services to add
	getAccountCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			// Get account details - returns account with existing "dpa" service
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			// Add services to organization account
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account")
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			// Get updated account details - returns account with both "dpa" and "sca" services
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithMultipleServicesJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
				},
			},
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]interface{}{
					"ScaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/ScaRole",
				},
			},
		},
	}

	// Call TfUpdateOrganizationAccount
	account, err := service.TfUpdateOrganizationAccount(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, mockAccountOnboardingID, account.ID)
	require.Equal(t, mockAWSAccountID, account.AccountID)
	require.Equal(t, mockOnboardingType, account.OnboardingType)
	require.Contains(t, account.ServiceNames, "dpa")
	require.Contains(t, account.ServiceNames, "sca")
}

func TestTfUpdateOrganizationAccount_NoServicesToAdd(t *testing.T) {
	// Account already has all desired services ("Completely added") and their currently-deployed
	// resources (exposed under "parameters") match the desired resources exactly. Nothing changed,
	// so the SDK must send NO add-account request (unchanged services are omitted).
	accountJSON := `{
		"id": "` + mockAccountOnboardingID + `",
		"account_id": "` + mockAWSAccountID + `",
		"organization_id": "` + mockOrganizationOnboardingID + `",
		"onboarding_type": "` + mockOnboardingType + `",
		"services": ["dpa", "sca"],
		"services_data": [
			{"name": "dpa", "status": "Completely added", "errors": []},
			{"name": "sca", "status": "Completely added", "errors": []}
		],
		"parameters": {
			"dpa": {"DpaRoleArn": "arn:aws:iam::` + mockAWSAccountID + `:role/DpaRole"},
			"sca": {"ScaRoleArn": "arn:aws:iam::` + mockAWSAccountID + `:role/ScaRole"}
		},
		"status": "Completely added"
	}`

	var postCallCount int
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			// Add/re-send services - must NOT be called since nothing changed.
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account")
			},
			StatusCode:   http.StatusNoContent,
			ResponseBody: ``,
			OnRequest:    func(r *http.Request) { postCallCount++ },
		},
		{
			// Get account details - returns account with both "dpa" and "sca" services and their params
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID)
			},
			StatusCode:   http.StatusOK,
			ResponseBody: accountJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
				},
			},
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]interface{}{
					"ScaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/ScaRole",
				},
			},
		},
	}

	// Call TfUpdateOrganizationAccount
	account, err := service.TfUpdateOrganizationAccount(input)

	// Assertions - nothing changed, so no add-account request is sent, and the account is returned.
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, mockAccountOnboardingID, account.ID)
	require.Equal(t, mockAWSAccountID, account.AccountID)
	require.Zero(t, postCallCount, "unchanged already-onboarded services must NOT be re-sent")
}

func TestTfUpdateOrganizationAccount_AccountNotFound(t *testing.T) {
	// Test case where account doesn't exist
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID)
			},
			StatusCode: http.StatusNotFound,
			ResponseBody: `{
				"code": "404",
				"message": "Account not found"
			}`,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
			},
		},
	}

	// Call TfUpdateOrganizationAccount
	account, err := service.TfUpdateOrganizationAccount(input)

	// Assertions
	require.Error(t, err)
	require.Nil(t, account)
	require.Contains(t, err.Error(), "failed to get account details")
}

func TestTfUpdateOrganizationAccount_AccountNotInOrganization(t *testing.T) {
	// This test verifies that an account without services_data (missing deployment status)
	// will still work correctly by treating all services as needing to be added.
	accountWithoutServicesDataJSON := `{
		"id": "` + mockAccountOnboardingID + `",
		"account_id": "` + mockAWSAccountID + `",
		"onboarding_type": "` + mockOnboardingType + `",
		"services": ["dpa"],
		"status": "Completely added"
	}`

	getCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: accountWithoutServicesDataJSON,
			OnRequest: func(r *http.Request) {
				getCallCount++
			},
		},
		{
			// POST to add services (since services_data is missing, dpa is not considered fully deployed)
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account")
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getCallCount == 1
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
				},
			},
		},
	}

	// Call TfUpdateOrganizationAccount
	account, err := service.TfUpdateOrganizationAccount(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, mockAccountOnboardingID, account.ID)
}

func TestTfUpdateOrganizationAccount_FailedToAddServices(t *testing.T) {
	// Test case where adding services fails
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID)
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account")
			},
			StatusCode: http.StatusBadRequest,
			ResponseBody: `{
				"code": "400",
				"message": "Invalid service configuration"
			}`,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]interface{}{
					"ScaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/ScaRole",
				},
			},
		},
	}

	// Call TfUpdateOrganizationAccount
	account, err := service.TfUpdateOrganizationAccount(input)

	// Assertions
	require.Error(t, err)
	require.Nil(t, account)
	require.Contains(t, err.Error(), "failed to add services to organization account")
}

func TestTfUpdateOrganizationAccount_FailedToFetchUpdatedAccount(t *testing.T) {
	// Test case where adding services succeeds but fetching updated account fails
	getAccountCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			// First GET - get account details
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account")
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			// Second GET - fetch updated account (fails)
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode: http.StatusInternalServerError,
			ResponseBody: `{
				"code": "500",
				"message": "Internal server error"
			}`,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]interface{}{
					"ScaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/ScaRole",
				},
			},
		},
	}

	// Call TfUpdateOrganizationAccount
	account, err := service.TfUpdateOrganizationAccount(input)

	// Assertions
	require.Error(t, err)
	require.Nil(t, account)
	require.Contains(t, err.Error(), "failed to fetch updated account details")
}

func TestTfUpdateOrganizationAccount_WithServiceParameters(t *testing.T) {
	// Test case with service parameters
	getAccountCallCount := 0
	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account") {
					// Verify request body contains serviceParameters
					bodyBytes, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					bodyStr := string(bodyBytes)
					require.Contains(t, bodyStr, "serviceParameters", "Expected serviceParameters in request body")
					return true
				}
				return false
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithMultipleServicesJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	serviceParameters := map[string]map[string]interface{}{
		"sca": {
			"region": "us-east-1",
		},
	}

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]interface{}{
					"ScaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/ScaRole",
				},
			},
		},
		ServiceParameters: serviceParameters,
	}

	// Call TfUpdateOrganizationAccount
	account, err := service.TfUpdateOrganizationAccount(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, mockAccountOnboardingID, account.ID)
}

func TestTfUpdateOrganizationAccount_ServiceStatusHandling(t *testing.T) {
	// Status does not decide anything: a service the account already reports is dropped whether it
	// is "Completely added", "Waiting for deployment" or "In progress". Sending any of them would
	// make the request an update, which the API rejects with 501 unless the tenant has the update
	// feature flag on. With all three services onboarded there is nothing new, so no request is made.
	accountWithMixedServiceStatusesJSON := `{
		"id": "` + mockAccountOnboardingID + `",
		"account_id": "` + mockAWSAccountID + `",
		"organization_id": "` + mockOrganizationOnboardingID + `",
		"onboarding_type": "` + mockOnboardingType + `",
		"services": ["dpa", "sca", "secrets_hub"],
		"services_data": [
			{
				"name": "dpa",
				"status": "Completely added",
				"errors": []
			},
			{
				"name": "sca",
				"status": "Waiting for deployment",
				"errors": []
			},
			{
				"name": "secrets_hub",
				"status": "In progress",
				"errors": []
			}
		],
		"status": "Partially added"
	}`

	getAccountCallCount := 0
	postCallCount := 0
	var capturedPostBody string

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			// First GET - returns account with mixed service statuses
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: accountWithMixedServiceStatusesJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			// POST to add/re-send services - should include DPA ("Completely added") and SCA
			// ("Waiting for deployment"), but NOT secrets_hub ("In progress").
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account") {
					// Capture request body to verify which services are being added
					bodyBytes, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					capturedPostBody = string(bodyBytes)
					postCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			// Second GET - returns account with all services fully deployed
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode: http.StatusOK,
			ResponseBody: `{
				"id": "` + mockAccountOnboardingID + `",
				"account_id": "` + mockAWSAccountID + `",
				"organization_id": "` + mockOrganizationOnboardingID + `",
				"onboarding_type": "` + mockOnboardingType + `",
				"services": ["dpa", "sca", "secrets_hub"],
				"services_data": [
					{
						"name": "dpa",
						"status": "Completely added",
						"errors": []
					},
					{
						"name": "sca",
						"status": "Completely added",
						"errors": []
					},
					{
						"name": "secrets_hub",
						"status": "Completely added",
						"errors": []
					}
				],
				"status": "Completely added"
			}`,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
				},
			},
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]interface{}{
					"ScaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/ScaRole",
				},
			},
			{
				ServiceName: ccemodels.SecretsHub,
				Resources: map[string]interface{}{
					"SecretsHubRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/SecretsHubRole",
				},
			},
		},
	}
	// This module onboarded all three, so their statuses describe deployments already under way.
	input.SetPriorState(&awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		Services: input.Services,
	})

	// Call TfUpdateOrganizationAccount
	account, err := service.TfUpdateOrganizationAccount(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, mockAccountOnboardingID, account.ID)
	require.Equal(t, mockAWSAccountID, account.AccountID)

	require.Equal(t, 0, postCallCount,
		"no service is new, so nothing may be sent regardless of the onboarded services' statuses")
	require.Empty(t, capturedPostBody)
}

func TestTfUpdateOrganizationAccount_AllServicesWaitingForDeployment(t *testing.T) {
	// Every service exists already, all of them still deploying. The backend has them queued, so
	// there is nothing to ask for and re-sending them would only turn the request into an update.
	accountWithAllServicesWaitingJSON := `{
		"id": "` + mockAccountOnboardingID + `",
		"account_id": "` + mockAWSAccountID + `",
		"organization_id": "` + mockOrganizationOnboardingID + `",
		"onboarding_type": "` + mockOnboardingType + `",
		"services": ["dpa", "sca"],
		"services_data": [
			{
				"name": "dpa",
				"status": "Waiting for deployment",
				"errors": []
			},
			{
				"name": "sca",
				"status": "Waiting for deployment",
				"errors": []
			}
		],
		"status": "Waiting for deployment"
	}`

	getAccountCallCount := 0
	postCallCount := 0
	var capturedPostBody string

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: accountWithAllServicesWaitingJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account") {
					bodyBytes, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					capturedPostBody = string(bodyBytes)
					postCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithMultipleServicesJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
				},
			},
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]interface{}{
					"ScaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/ScaRole",
				},
			},
		},
	}
	// This module sent both, so they are queued rather than merely listed by the organization scan.
	input.SetPriorState(&awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		Services: input.Services,
	})

	// Call TfUpdateOrganizationAccount
	account, err := service.TfUpdateOrganizationAccount(input)

	// Assertions
	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, 0, postCallCount, "services already queued for deployment must not be re-sent")
	require.Empty(t, capturedPostBody)
}

// TestTfUpdateOrganizationAccount_SkipsOnboardedServiceWithoutPriorState covers an onboarded service
// whose resources differ from what Terraform is sending, but with no prior state to compare against -
// an import, or state predating the PriorState mechanism. The change cannot be told apart from a
// value the API simply reports differently, so the service is left alone instead of being re-sent
// on a guess and risking the 501 update gate.
func TestTfUpdateOrganizationAccount_SkipsOnboardedServiceWithoutPriorState(t *testing.T) {
	getAccountCallCount := 0
	var capturedPostBody string
	var postCallCount int

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			// First GET - account with DPA already "Completely added"
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account") {
					bodyBytes, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					capturedPostBody = string(bodyBytes)
					postCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					// A changed role ARN for the already-deployed DPA service.
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRoleUPDATED",
				},
			},
		},
	}

	account, err := service.TfUpdateOrganizationAccount(input)

	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, 0, postCallCount,
		"without prior state there is nothing to compare, so the service must be left alone")
	require.Empty(t, capturedPostBody)
}

// TestTfUpdateOrganizationAccount_ResendsOnboardedServiceWhenParamsChangedSinceLastApply is the
// counterpart: the same changed resources, but with prior state showing what the last apply sent. The
// change is now provable, so the service goes out as an update.
func TestTfUpdateOrganizationAccount_ResendsOnboardedServiceWhenParamsChangedSinceLastApply(t *testing.T) {
	getAccountCallCount := 0
	var capturedPostBody string
	var postCallCount int

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDeployedServiceJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account") {
					bodyBytes, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					capturedPostBody = string(bodyBytes)
					postCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRoleUPDATED",
				},
			},
		},
	}
	input.SetPriorState(&awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
				},
			},
		},
	})

	account, err := service.TfUpdateOrganizationAccount(input)

	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, 1, postCallCount, "a parameter change proven against prior state must be sent")
	require.Contains(t, capturedPostBody, "DpaRoleUPDATED", "the re-sent service must carry the new resources")
}

// TestTfUpdateOrganizationAccount_SkipsOnboardedServiceUnchangedSinceLastApply pins the other half:
// prior state matching what Terraform is sending means there is nothing to apply, and the request
// must not go out - it would be read as an update and rejected with 501 on a tenant without the
// update feature flag. This is the common re-apply, so it has to stay a no-op.
func TestTfUpdateOrganizationAccount_SkipsOnboardedServiceUnchangedSinceLastApply(t *testing.T) {
	getAccountCallCount := 0
	var postCallCount int

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDeployedServiceJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account")
			},
			StatusCode:   http.StatusNotImplemented,
			ResponseBody: `{"app_error_code":"FEATURE_NOT_IMPLEMENTED","message":"Not Implemented"}`,
			OnRequest: func(r *http.Request) {
				postCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDeployedServiceJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	unchanged := []ccemodels.IdsecCCEServiceInput{
		{
			ServiceName: ccemodels.DPA,
			Resources: map[string]interface{}{
				"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
			},
		},
	}
	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services:             unchanged,
	}
	input.SetPriorState(&awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{Services: unchanged})

	account, err := service.TfUpdateOrganizationAccount(input)

	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, 0, postCallCount, "an onboarded service unchanged since the last apply must not be re-sent")
}

// TestTfUpdateOrganizationAccount_ResendsOnboardedServiceWhenServiceParametersChanged pins that the
// comparison covers terraform service_parameters too, not just a service's resources.
func TestTfUpdateOrganizationAccount_ResendsOnboardedServiceWhenServiceParametersChanged(t *testing.T) {
	getAccountCallCount := 0
	var capturedPostBody string
	var postCallCount int

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDeployedServiceJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account") {
					bodyBytes, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					capturedPostBody = string(bodyBytes)
					postCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	services := []ccemodels.IdsecCCEServiceInput{
		{
			ServiceName: ccemodels.DPA,
			Resources: map[string]interface{}{
				"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
			},
		},
	}
	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services:             services,
		ServiceParameters: map[string]map[string]interface{}{
			"dpa": {"someParameter": "new"},
		},
	}
	input.SetPriorState(&awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		Services: services,
		ServiceParameters: map[string]map[string]interface{}{
			"dpa": {"someParameter": "old"},
		},
	})

	account, err := service.TfUpdateOrganizationAccount(input)

	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, 1, postCallCount, "a service_parameters change must be detected as well")
	require.Contains(t, capturedPostBody, `"serviceName":"dpa"`)
}

// mockAccountWaitingAfterOrgUpgradeJSON is an account as it looks immediately after its parent
// organization was upgraded: the service is pending deployment, but nothing about it changed. The
// version already reads as the NEW version because the backend bumps the account's version column
// at org-upgrade time.
const mockAccountWaitingAfterOrgUpgradeJSON = `{
	"id": "` + mockAccountOnboardingID + `",
	"account_id": "` + mockAWSAccountID + `",
	"organization_id": "` + mockOrganizationOnboardingID + `",
	"onboarding_type": "` + mockOnboardingType + `",
	"services": ["dpa"],
	"services_data": [
		{
			"name": "dpa",
			"status": "Waiting for deployment",
			"version": "0.0.7",
			"errors": []
		}
	],
	"parameters": {
		"dpa": {
			"DpaRoleArn": "arn:aws:iam::` + mockAWSAccountID + `:role/DpaRole"
		}
	},
	"status": "Waiting for deployment"
}`

// TestTfUpdateOrganizationAccount_AddingNewServiceOmitsUnchangedPendingService pins that adding a
// service new to the account sends ONLY that service. The account here still has DPA pending
// deployment from the apply that created it, with resources identical to what Terraform re-sends.
// Carrying DPA along would make the add look like an update to the API, which rejects it when the
// update/upgrade feature is not activated for the tenant - failing an add that is not an update.
func TestTfUpdateOrganizationAccount_AddingNewServiceOmitsUnchangedPendingService(t *testing.T) {
	getAccountCallCount := 0
	var capturedPostBody string
	var postCallCount int

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountWaitingAfterOrgUpgradeJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account") {
					bodyBytes, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					capturedPostBody = string(bodyBytes)
					postCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				// already onboarded and pending, re-sent with the resources it already has
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
				},
			},
			{
				// new to the account - the only thing this request actually adds
				ServiceName: ccemodels.SCA,
				Resources: map[string]interface{}{
					"ScaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/ScaRole",
				},
			},
		},
	}
	// DPA is pending because the apply that created it sent it, so prior state holds it. That is
	// what separates it from a service the organization scan merely listed as waiting.
	input.SetPriorState(&awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
				},
			},
		},
	})

	account, err := service.TfUpdateOrganizationAccount(input)

	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, 1, postCallCount, "the new service must still be sent")
	require.Contains(t, capturedPostBody, `"serviceName":"sca"`, "the service being added must be in the POST body")
	require.NotContains(t, capturedPostBody, `"serviceName":"dpa"`,
		"an unchanged service pending deployment must NOT ride along with an add")
}

// TestTfUpdateOrganizationAccount_SendsWaitingServiceThisModuleNeverOnboarded pins that a service
// listed as waiting for deployment is still sent when this module never onboarded it.
//
// For a programmatic or terraform_provider organization, the periodic scan writes a "Waiting for
// deployment" row for every one of the organization's products onto each newly discovered member
// account, before anyone asks for them. Those names come back in the account's service list, but the
// backend does not consider them onboarded: it partitions an add request against the account's
// stored resources document, and only that partition goes through the upgrade gate. Treating the
// list as proof of onboarding leaves such a service skipped on every apply and never deployed, with
// no error to show for it.
//
// The absence of prior state is what separates this from a deployment already under way, which this
// module started and must not re-send.
func TestTfUpdateOrganizationAccount_SendsWaitingServiceThisModuleNeverOnboarded(t *testing.T) {
	getAccountCallCount := 0
	var capturedPostBody string
	var postCallCount int

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountWaitingAfterOrgUpgradeJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account") {
					bodyBytes, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					capturedPostBody = string(bodyBytes)
					postCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
				},
			},
		},
		// No prior state: this module has never sent DPA for this account, so the waiting row can
		// only have come from the organization scan.
	}

	account, err := service.TfUpdateOrganizationAccount(input)

	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, 1, postCallCount,
		"a waiting service this module never onboarded must be sent, or it never deploys")
	require.Contains(t, capturedPostBody, `"serviceName":"dpa"`)
}

// TestTfUpdateOrganizationAccount_SkipsDeployedServiceThisModuleNeverOnboarded is the counterpart:
// absent prior state is not on its own a reason to send. A service the account reports as completely
// added is onboarded whatever this module's state says, so re-sending it is an update, and the API
// rejects the whole request with 501 when the tenant's update feature flag is off.
func TestTfUpdateOrganizationAccount_SkipsDeployedServiceThisModuleNeverOnboarded(t *testing.T) {
	getAccountCallCount := 0
	var postCallCount int

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDeployedServiceJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account") {
					postCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
				},
			},
		},
	}

	account, err := service.TfUpdateOrganizationAccount(input)

	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, 0, postCallCount,
		"a fully deployed service must not be re-sent just because prior state does not mention it")
}

// mockAccountDeployedServiceJSON mirrors how the API reports an onboarded member account: the
// per-service entries carry a name, status and version, and no deployed resources at all.
const mockAccountDeployedServiceJSON = `{
	"id": "` + mockAccountOnboardingID + `",
	"account_id": "` + mockAWSAccountID + `",
	"organization_id": "` + mockOrganizationOnboardingID + `",
	"onboarding_type": "` + mockOnboardingType + `",
	"services": ["dpa"],
	"services_data": [
		{
			"name": "dpa",
			"status": "Completely added",
			"version": "0.0.2",
			"errors": []
		}
	],
	"status": "Completely added"
}`

// TestTfUpdateOrganizationAccount_AddingNewServiceOmitsOnboardedServiceEvenWhenChanged pins that an
// add drops already-onboarded services unconditionally, rather than relying on a parameter diff.
// Here dpa's deployed DpaRoleArn differs from the one terraform sends, so a diff-based rule would
// include it and the API would reject the whole add as an update.
func TestTfUpdateOrganizationAccount_AddingNewServiceOmitsOnboardedServiceEvenWhenChanged(t *testing.T) {
	getAccountCallCount := 0
	var capturedPostBody string
	var postCallCount int

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDeployedServiceJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account") {
					bodyBytes, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					capturedPostBody = string(bodyBytes)
					postCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				// already onboarded, and genuinely changed - still not part of an add
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRoleRenamed",
				},
			},
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]interface{}{
					"ScaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/ScaRole",
				},
			},
		},
	}

	account, err := service.TfUpdateOrganizationAccount(input)

	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, 1, postCallCount, "the new service must still be sent")
	require.Contains(t, capturedPostBody, `"serviceName":"sca"`, "the service being added must be in the POST body")
	require.NotContains(t, capturedPostBody, `"serviceName":"dpa"`,
		"an add must drop already-onboarded services even when their resources changed")
}

const mockAccountAddedServiceStillDeployingJSON = `{
	"id": "` + mockAccountOnboardingID + `",
	"account_id": "` + mockAWSAccountID + `",
	"organization_id": "` + mockOrganizationOnboardingID + `",
	"onboarding_type": "` + mockOnboardingType + `",
	"services": ["dpa", "sca"],
	"services_data": [
		{
			"name": "dpa",
			"status": "Completely added",
			"version": "0.0.2",
			"errors": []
		},
		{
			"name": "sca",
			"status": "Waiting for deployment",
			"version": "0.0.2",
			"errors": []
		}
	],
	"status": "In progress"
}`

// TestTfUpdateOrganizationAccount_ReapplyWhileAddedServiceIsDeployingSendsNothing covers the apply
// that is retried after the add already landed: sca is on the account and still deploying, dpa is
// deployed, and terraform asks for both again with the same resources. Nothing is new and nothing
// changed, so the correct request is no request - sending either service would be an update, and
// the tenant's update feature flag turns that into a 501 that no retry can get past.
func TestTfUpdateOrganizationAccount_ReapplyWhileAddedServiceIsDeployingSendsNothing(t *testing.T) {
	getAccountCallCount := 0
	var postCallCount int

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountAddedServiceStillDeployingJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account")
			},
			StatusCode:   http.StatusNotImplemented,
			ResponseBody: `{"app_error_code":"FEATURE_NOT_IMPLEMENTED","message":"Not Implemented"}`,
			OnRequest: func(r *http.Request) {
				postCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountAddedServiceStillDeployingJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				Resources: map[string]interface{}{
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
				},
			},
			{
				ServiceName: ccemodels.SCA,
				Resources: map[string]interface{}{
					"ScaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/ScaRole",
				},
			},
		},
	}
	// The apply being repeated is the one that sent both, so prior state holds them: SCA is
	// mid-deployment rather than a name the organization scan put on the account.
	input.SetPriorState(&awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		Services: input.Services,
	})

	account, err := service.TfUpdateOrganizationAccount(input)

	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, 0, postCallCount,
		"a re-apply over an in-flight deployment must send nothing: both services are already onboarded and unchanged")
}

// TestTfUpdateOrganizationAccount_SkipsWaitingServiceWithNoResourceChange pins that a service the
// backend has already queued is left alone, so a re-apply over an in-flight deployment stays a
// no-op instead of becoming a 501-rejected update.
//
// This deliberately gives up the EV-143045 behaviour, where a waiting service was re-sent
// unconditionally to nudge member accounts flipped to "Waiting for deployment" by an organization
// upgrade. That nudge was itself an update, so it only ever worked on tenants with upgrades
// enabled, while the unconditional re-send broke re-applies everywhere else.
func TestTfUpdateOrganizationAccount_SkipsWaitingServiceWithNoResourceChange(t *testing.T) {
	getAccountCallCount := 0
	var capturedPostBody string
	var postCallCount int

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountWaitingAfterOrgUpgradeJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account") {
					bodyBytes, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					capturedPostBody = string(bodyBytes)
					postCallCount++
					return true
				}
				return false
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.DPA,
				// Terraform carries the parent organization's version so that an org upgrade
				// produces a plan diff, but the resources are unchanged.
				Version: "0.0.7",
				Resources: map[string]interface{}{
					"DpaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/DpaRole",
				},
			},
		},
	}
	// This module onboarded DPA, so prior state holds it and the waiting status is a deployment
	// already under way rather than a row the organization scan created.
	input.SetPriorState(&awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		Services: input.Services,
	})

	account, err := service.TfUpdateOrganizationAccount(input)

	require.NoError(t, err)
	require.NotNil(t, account)
	require.Equal(t, 0, postCallCount,
		"a service waiting for deployment with unchanged resources must not be re-sent: it is already queued, and the re-send would be rejected as an update")
	require.Empty(t, capturedPostBody)
}

// TestTfUpdateOrganizationAccount_StripsServiceVersionFromPayload pins the contract that a member
// account's service version is Terraform-state-only. It exists solely to make an organization
// upgrade visible to Terraform's plan; the API derives the real version from the parent
// organization and its ServiceInput schema has no version field, so it must never be sent.
//
// sca is new to the account here, which is what gets it into the payload at all - the version alone
// never would.
func TestTfUpdateOrganizationAccount_StripsServiceVersionFromPayload(t *testing.T) {
	getAccountCallCount := 0
	var capturedPostBody string

	client, cleanup := internal.SetupMockCCEService(t, []internal.MockEndpointConfig{
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 0
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDeployedServiceJSON,
			OnRequest: func(r *http.Request) {
				getAccountCallCount++
			},
		},
		{
			Matcher: func(r *http.Request) bool {
				if r.Method == "POST" && strings.Contains(r.URL.Path, "/api/aws/programmatic/organization/"+mockOrganizationOnboardingID+"/account") {
					bodyBytes, _ := io.ReadAll(r.Body)
					r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					capturedPostBody = string(bodyBytes)
					return true
				}
				return false
			},
			StatusCode:   http.StatusCreated,
			ResponseBody: `{}`,
		},
		{
			Matcher: func(r *http.Request) bool {
				return r.Method == "GET" && strings.Contains(r.URL.Path, "/api/aws/programmatic/account/"+mockAccountOnboardingID) && getAccountCallCount == 1
			},
			StatusCode:   http.StatusOK,
			ResponseBody: mockAccountDetailsWithOrgJSON,
		},
	})
	defer cleanup()

	service := setupAWSService(client)

	input := &awsmodels.TfIdsecCCEAWSUpdateOrganizationAccount{
		ID:                   mockAccountOnboardingID,
		ParentOrganizationID: mockOrganizationOnboardingID,
		Services: []ccemodels.IdsecCCEServiceInput{
			{
				ServiceName: ccemodels.SCA,
				Version:     "0.0.7",
				Resources: map[string]interface{}{
					"ScaRoleArn": "arn:aws:iam::" + mockAWSAccountID + ":role/ScaRole",
				},
			},
		},
	}

	_, err := service.TfUpdateOrganizationAccount(input)

	require.NoError(t, err)
	require.Contains(t, capturedPostBody, `"serviceName":"sca"`, "the service itself must still be sent")
	require.NotContains(t, capturedPostBody, `"version"`, "the Terraform-state-only version must not reach the API")
	require.NotContains(t, capturedPostBody, "0.0.7", "the Terraform-state-only version must not reach the API")
	require.Contains(t, capturedPostBody, `"onboardingType":"terraform_provider"`,
		"the add-services request must carry onboardingType so the API allows the change on a terraform_provider onboarding")
}
