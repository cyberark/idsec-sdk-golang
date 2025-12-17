package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	awsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/aws/models"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
	cceinternal "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

// tfOrganization retrieves AWS organization details by Organization onboarding ID.
// API: GET /api/aws/programmatic/organization/{id}
func (s *IdsecCCEAWSService) tfOrganization(input *awsmodels.TfIdsecCCEAWSGetOrganization) (*awsmodels.TfIdsecCCEAWSOrganization, error) {
	s.Logger.Info("Getting AWS organization details for ID [%s]", input.ID)

	url := fmt.Sprintf(pathOrganizationGetOrDeleteURL, input.ID)
	response, err := s.client.Get(context.Background(), url, nil)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to get organization details")
	}

	organizationJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}

	var organization awsmodels.TfIdsecCCEAWSOrganization
	err = mapstructure.Decode(organizationJSON, &organization)
	if err != nil {
		return nil, err
	}

	return &organization, nil
}

// tfOrganizationDatasource retrieves AWS organization details with services information by Organization onboarding ID.
// API: GET /api/aws/programmatic/organization/{id}
func (s *IdsecCCEAWSService) tfOrganizationDatasource(input *awsmodels.TfIdsecCCEAWSGetOrganization) (*awsmodels.TfIdsecCCEAWSOrganizationDatasource, error) {
	s.Logger.Info("Getting AWS organization details for ID [%s]", input.ID)

	url := fmt.Sprintf(pathOrganizationGetOrDeleteURL, input.ID)
	response, err := s.client.Get(context.Background(), url, nil)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to get organization details")
	}

	organizationJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}

	var organization awsmodels.TfIdsecCCEAWSOrganizationDatasource
	err = mapstructure.Decode(organizationJSON, &organization)
	if err != nil {
		return nil, err
	}

	return &organization, nil
}

// getOrganizationWithRetry retrieves an organization with retry logic.
// It attempts to fetch the organization up to 3 times with 1 second delay between attempts.
func (s *IdsecCCEAWSService) getOrganizationWithRetry(organizationID string) (*awsmodels.TfIdsecCCEAWSOrganization, error) {
	var organization *awsmodels.TfIdsecCCEAWSOrganization
	err := common.RetryCall(func() error {
		org, getErr := s.tfOrganization(&awsmodels.TfIdsecCCEAWSGetOrganization{ID: organizationID})
		if getErr != nil {
			return getErr
		}
		organization = org
		return nil
	}, cceinternal.DefaultMaxRequestRetries, cceinternal.DefaultRetryDelaySeconds, nil, cceinternal.DefaultRetryBackoffMultiplier, 0, func(err error, delay int) {
		s.Logger.Info("Retrying to get organization in %d seconds: %v", delay, err)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve organization: %w", err)
	}

	return organization, nil
}

// tfAddOrganization adds an AWS organization programmatically using the organization's management account.
// After creation, it retrieves the full organization details with retry logic (3 attempts, 1 second delay).
// API: POST /api/aws/programmatic/organization
func (s *IdsecCCEAWSService) tfAddOrganization(input *awsmodels.TfIdsecCCEAWSAddOrganization) (*awsmodels.TfIdsecCCEAWSOrganization, error) {
	s.Logger.Info("Adding AWS organization with management account ID [%s]", input.ManagementAccountID)

	// Convert input to map using JSON marshal/unmarshal
	inputJSON, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal input: %w", err)
	}

	var requestBody map[string]interface{}
	if err := json.Unmarshal(inputJSON, &requestBody); err != nil {
		return nil, fmt.Errorf("failed to unmarshal input to map: %w", err)
	}

	// Add hardcoded onboarding type
	requestBody["onboardingType"] = ccemodels.TerraformProvider

	response, err := s.client.Post(context.Background(), pathOrganizationAddURL, requestBody)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to add organization")
	}

	outputJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}

	var output awsmodels.TfIdsecCCEAWSAddOrganizationOutput
	err = mapstructure.Decode(outputJSON, &output)
	if err != nil {
		return nil, err
	}

	// Retrieve the full organization details with retry logic
	s.Logger.Info("Retrieving organization details for ID [%s]", output.ID)
	organization, err := s.getOrganizationWithRetry(output.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve organization after creation: %w", err)
	}

	return organization, nil
}

// tfDeleteOrganization deletes an AWS organization by its onboarding ID.
// API: DELETE /api/aws/programmatic/organization/{id}
func (s *IdsecCCEAWSService) tfDeleteOrganization(input *awsmodels.TfIdsecCCEAWSGetOrganization) error {
	s.Logger.Info("Deleting AWS organization with ID [%s]", input.ID)

	url := fmt.Sprintf(pathOrganizationGetOrDeleteURL, input.ID)
	response, err := s.client.Delete(context.Background(), url, nil, nil)
	if err != nil {
		return err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	// Handle non-2xx status codes
	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to delete organization")
	}

	return nil
}

// tfUpdateOrganization updates an AWS organization programmatically by reconciling service changes.
// Compares the desired services in the input with the current services on the organization,
// then adds new services and removes services that are no longer desired.
func (s *IdsecCCEAWSService) tfUpdateOrganization(input *awsmodels.TfIdsecCCEAWSUpdateOrganization) (*awsmodels.TfIdsecCCEAWSOrganization, error) {
	s.Logger.Info("Updating AWS organization [%s]", input.ID)
	// Step 1: Get current organization details to determine existing services
	// We need to extract services from the raw API response since it's not in the struct
	url := fmt.Sprintf(pathOrganizationGetOrDeleteURL, input.ID)
	response, err := s.client.Get(context.Background(), url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get current organization details: %w", err)
	}
	defer cceinternal.CloseResponseBody(response.Body)

	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to get organization details")
	}

	organizationJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize organization response: %w", err)
	}

	// Extract current services from raw JSON
	var currentServiceNames []string
	if orgMap, ok := organizationJSON.(map[string]interface{}); ok {
		if servicesRaw, exists := orgMap["services"]; exists {
			if servicesList, ok := servicesRaw.([]interface{}); ok {
				for _, svc := range servicesList {
					if svcStr, ok := svc.(string); ok {
						currentServiceNames = append(currentServiceNames, svcStr)
					}
				}
			}
		}
	}

	// Step 2: Compare services to determine what to add and what to remove
	// Build maps for efficient lookup
	desiredServicesMap := make(map[string]ccemodels.IdsecCCEServiceInput)
	for _, service := range input.Services {
		desiredServicesMap[service.ServiceName] = service
	}

	currentServices := make(map[string]bool)
	for _, serviceName := range currentServiceNames {
		currentServices[serviceName] = true
	}

	s.Logger.Info("Current organization services: %v", currentServiceNames)
	s.Logger.Info("Desired organization services after update: %v", func() []string {
		names := make([]string, 0, len(desiredServicesMap))
		for name := range desiredServicesMap {
			names = append(names, name)
		}
		return names
	}())

	// Determine services to add (in desired but not in current)
	var servicesToAdd []ccemodels.IdsecCCEServiceInput
	for serviceName, service := range desiredServicesMap {
		if !currentServices[serviceName] {
			servicesToAdd = append(servicesToAdd, service)
			s.Logger.Info("Service '%s' will be ADDED", serviceName)
		}
	}

	// Determine services to remove (in current but not in desired)
	var servicesToRemove []string
	for serviceName := range currentServices {
		if _, exists := desiredServicesMap[serviceName]; !exists {
			servicesToRemove = append(servicesToRemove, serviceName)
			s.Logger.Info("Service '%s' will be REMOVED", serviceName)
		}
	}

	s.Logger.Info("Services to add: %d, Services to remove: %d\n", len(servicesToAdd), len(servicesToRemove))
	// Step 3: Add new services if any
	if len(servicesToAdd) > 0 {
		s.Logger.Info("Adding %d services to organization [%s]", len(servicesToAdd), input.ID)
		err = s.addOrganizationServices(&awsmodels.TfIdsecCCEAWSAddOrganizationServices{
			ID:       input.ID,
			Services: servicesToAdd,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to add services: %w", err)
		}
	}

	// Step 4: Remove services that are no longer desired
	if len(servicesToRemove) > 0 {
		s.Logger.Info("Removing %d services from organization [%s]", len(servicesToRemove), input.ID)
		err = s.deleteOrganizationServices(&awsmodels.TfIdsecCCEAWSDeleteOrganizationServices{
			ID:           input.ID,
			ServiceNames: servicesToRemove,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to remove services: %w", err)
		}
	}

	// Step 5: Fetch and return updated organization details
	s.Logger.Info("Fetching full details for organization [%s]", input.ID)
	fullOrganization, err := s.getOrganizationWithRetry(input.ID)
	if err != nil {
		return nil, fmt.Errorf("organization updated with ID %s, but failed to fetch details: %w", input.ID, err)
	}

	return fullOrganization, nil
}

// addOrganizationServices adds services to an AWS organization programmatically.
// API: POST /api/aws/programmatic/organization/{id}/services
func (s *IdsecCCEAWSService) addOrganizationServices(input *awsmodels.TfIdsecCCEAWSAddOrganizationServices) error {
	s.Logger.Info("Adding services to AWS organization [%s]", input.ID)

	url := fmt.Sprintf(pathOrganizationServicesURL, input.ID)

	// Create request body with services array
	requestBody := map[string]interface{}{
		"services": input.Services,
	}

	response, err := s.client.Post(context.Background(), url, requestBody)
	if err != nil {
		return fmt.Errorf("failed to add services to organization: %w", err)
	}
	defer cceinternal.CloseResponseBody(response.Body)

	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		bodyBytes, _ := io.ReadAll(response.Body)
		return fmt.Errorf("failed to add services to organization: status code %d, body: %s", response.StatusCode, string(bodyBytes))
	}

	return nil
}

// deleteOrganizationServices removes services from an AWS organization programmatically.
// API: DELETE /api/aws/programmatic/organization/{id}/services
func (s *IdsecCCEAWSService) deleteOrganizationServices(input *awsmodels.TfIdsecCCEAWSDeleteOrganizationServices) error {
	s.Logger.Info("Deleting services from AWS organization [%s]", input.ID)

	path := fmt.Sprintf(pathOrganizationServicesURL, input.ID)

	// Build query parameters with multiple values for the same key
	// The API expects: services_names=dpa&services_names=sca
	params := map[string][]string{
		"services_names": input.ServiceNames,
	}

	s.Logger.Info("Deleting services: %v from organization [%s]", input.ServiceNames, input.ID)

	response, err := s.client.Delete(context.Background(), path, nil, params)
	if err != nil {
		return fmt.Errorf("failed to delete services from organization: %w", err)
	}
	defer cceinternal.CloseResponseBody(response.Body)

	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		bodyBytes, _ := io.ReadAll(response.Body)
		return fmt.Errorf("failed to delete services from organization: status code %d, body: %s", response.StatusCode, string(bodyBytes))
	}

	return nil
}

// addOrganizationAccount adds an AWS account to an organization.
// This is a simple direct API call that returns immediately with the account ID.
// For synchronous operation with automatic scan/retry logic, use TfAddOrganizationAccountSync.
// API: POST /api/aws/programmatic/organization/{id}/account
func (s *IdsecCCEAWSService) addOrganizationAccount(input *awsmodels.IdsecCCEAWSAddOrganizationAccount) (*awsmodels.IdsecCCEAWSAddedOrganizationAccount, error) {
	s.Logger.Info("Adding AWS account [%s] to organization [%s]", input.AccountID, input.OrganizationID)

	requestBody := map[string]interface{}{
		"accountId": input.AccountID,
		"services":  input.Services,
	}

	url := fmt.Sprintf(pathOrganizationAccountURL, input.OrganizationID)
	response, err := s.client.Post(context.Background(), url, requestBody)
	if err != nil {
		return nil, err
	}
	defer cceinternal.CloseResponseBody(response.Body)

	if !cceinternal.IsHTTPSuccess(response.StatusCode) {
		return nil, cceinternal.HandleNon2xxResponse(s.Logger, response.StatusCode, response.Body, "failed to add account to organization")
	}

	responseJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, err
	}

	var addedAccount awsmodels.IdsecCCEAWSAddedOrganizationAccount
	err = mapstructure.Decode(responseJSON, &addedAccount)
	if err != nil {
		return nil, err
	}

	return &addedAccount, nil
}

// isAccountNotFoundError checks if the error indicates a 404 Not Found response.
// This helper is used by AddOrganizationAccountSync to determine if an account needs to be discovered via scan.
func isAccountNotFoundError(err error) bool {
	return err != nil && strings.Contains(err.Error(), fmt.Sprintf("%d", http.StatusNotFound))
}

// isScanInProgressError checks if the error indicates a scan is in progress
// by parsing the JSON response and checking for app_error_code = "SCAN_IN_PROGRESS".
// This helper is used by AddOrganizationAccountSync to determine if it should wait for an ongoing scan.
func isScanInProgressError(err error) bool {
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%d", http.StatusBadRequest)) {
		return false
	}

	// Parse JSON from error string to extract app_error_code
	errStr := err.Error()
	// Find JSON body in error string (after "status code: 400 - ")
	jsonStart := strings.Index(errStr, "{")
	if jsonStart == -1 {
		return false
	}

	jsonBody := errStr[jsonStart:]
	var errorResponse map[string]interface{}
	if err := json.Unmarshal([]byte(jsonBody), &errorResponse); err != nil {
		return false
	}

	// Check if app_error_code field exists and equals "SCAN_IN_PROGRESS"
	if appErrorCode, ok := errorResponse["app_error_code"].(string); ok {
		return appErrorCode == "SCAN_IN_PROGRESS"
	}

	return false
}

// triggerOrganizationScanIfNeeded triggers an organization scan if the account was not found.
// If the scan is already in progress (isScanInProgress is true), it skips triggering.
// Returns an error if the scan fails with a non-409 error.
// This helper is used by AddOrganizationAccountSync as part of its retry logic.
func (s *IdsecCCEAWSService) triggerOrganizationScanIfNeeded(isNotFound bool, organizationOnboardingID string) error {
	if isNotFound {
		// Fetch the organization to get the AWS organization ID for triggering scan
		s.Logger.Info("Fetching organization details for onboarding ID [%s] to trigger scan", organizationOnboardingID)
		org, err := s.tfOrganization(&awsmodels.TfIdsecCCEAWSGetOrganization{
			ID: organizationOnboardingID,
		})
		if err != nil {
			return fmt.Errorf("failed to get organization details: %w", err)
		}

		s.Logger.Info("Retrieved organization for scan: onboarding ID [%s], AWS organization ID [%s], management account [%s]",
			org.ID, org.OrganizationID, org.ManagementAccountID)

		// Trigger scan once with the AWS organization ID
		s.Logger.Info("Triggering scan for AWS organization ID [%s]", org.OrganizationID)
		_, scanErr := s.ScanOrganization(&awsmodels.IdsecCCEAWSScanOrganization{
			OrganizationID: org.OrganizationID,
		})
		if scanErr != nil && !strings.Contains(scanErr.Error(), fmt.Sprintf("%d", http.StatusConflict)) {
			// If scan failed with non-409 error, return error
			return fmt.Errorf("failed to trigger organization scan: %w", scanErr)
		}
		if scanErr != nil && strings.Contains(scanErr.Error(), fmt.Sprintf("%d", http.StatusConflict)) {
			s.Logger.Info("Scan already in progress, will poll for completion")
		} else {
			s.Logger.Info("Scan triggered successfully, polling for completion")
		}
	} else {
		s.Logger.Info("Scan already in progress, skipping scan trigger and polling for completion")
	}
	return nil
}

// waitForOrganizationScanCompletion polls the organization endpoint until the scan completes.
// It checks if lastSuccessfulScan timestamp is after the scanStartTime.
// Returns an error if the scan doesn't complete within maxRetries attempts.
// This helper is used by AddOrganizationAccountSync as part of its retry logic.
func (s *IdsecCCEAWSService) waitForOrganizationScanCompletion(organizationID string, scanStartTime time.Time, maxRetries int, retryInterval time.Duration) error {
	s.Logger.Info("Polling organization every %v for up to %d attempts", retryInterval, maxRetries)

	for i := 0; i < maxRetries; i++ {
		time.Sleep(retryInterval)

		s.Logger.Info("Poll attempt %d/%d: Checking organization scan status", i+1, maxRetries)

		// Get organization details to check last successful scan
		org, orgErr := s.tfOrganization(&awsmodels.TfIdsecCCEAWSGetOrganization{
			ID: organizationID,
		})

		if orgErr != nil {
			s.Logger.Warning("Failed to get organization details: %v, will retry", orgErr)
			continue
		}

		// Check if scan has completed
		if org.LastSuccessfulScan != "" {
			scanTime, parseErr := time.Parse(time.RFC3339Nano, org.LastSuccessfulScan)
			if parseErr != nil {
				s.Logger.Warning("Failed to parse lastSuccessfulScan timestamp: %v, will retry", parseErr)
				continue
			}

			if scanTime.After(scanStartTime) {
				s.Logger.Info("Scan completed successfully at %s", scanTime.Format(time.RFC3339Nano))
				return nil
			}
			s.Logger.Info("Scan not yet completed (last scan: %s, current scan started: %s)", scanTime.Format(time.RFC3339Nano), scanStartTime.Format(time.RFC3339Nano))
		} else {
			s.Logger.Info("No successful scan recorded yet, will continue polling")
		}
	}

	return fmt.Errorf("timeout waiting for organization scan to complete after %d attempts", maxRetries)
}

// tfAddOrganizationAccountSync adds an AWS account to an organization with intelligent retry logic.
// If the account is not yet discovered (404), it triggers a scan and retries with configurable intervals.
// Returns the full account details after successful addition.
// API: POST /api/aws/programmatic/organization/{id}/account
func (s *IdsecCCEAWSService) tfAddOrganizationAccountSync(input *awsmodels.IdsecCCEAWSAddOrganizationAccountSync) (*awsmodels.TfIdsecCCEAWSAccount, error) {
	s.Logger.Info("Adding AWS account [%s] to organization [%s] (sync mode with retry)", input.AccountID, input.OrganizationID)

	// Convert to base input struct (without retry options)
	baseInput := input.ToAddOrganizationAccount()

	// Initial attempt to add the account using the simple function
	result, err := s.addOrganizationAccount(baseInput)

	// Handle errors - classify once and reuse throughout
	if err != nil {
		// Classify error type once to avoid repeated checks (especially expensive JSON parsing)
		isNotFound := isAccountNotFoundError(err)
		isScanInProgress := isScanInProgressError(err)

		// If account not found or scan in progress, wait for scan completion and retry
		if isNotFound || isScanInProgress {
			// Log appropriate message based on error type
			if isNotFound {
				s.Logger.Info("Account not discovered yet, triggering organization scan and waiting for discovery")
			} else {
				s.Logger.Info("Scan is in progress, waiting for scan completion before adding account")
			}

			// Capture timestamp before triggering scan
			scanStartTime := time.Now()

			// Trigger scan if needed (only for 404, not if scan already in progress)
			if err := s.triggerOrganizationScanIfNeeded(isNotFound, input.OrganizationID); err != nil {
				return nil, err
			}

			// Get configured retry values or defaults
			maxRetries := input.GetScanProbeMaxRetries()
			retryInterval := input.GetScanProbeInterval()

			// Wait for scan completion
			if err := s.waitForOrganizationScanCompletion(input.OrganizationID, scanStartTime, maxRetries, retryInterval); err != nil {
				return nil, err
			}

			// Try to add the account after scan completion
			s.Logger.Info("Attempting to add account after scan completion")
			result, err = s.addOrganizationAccount(baseInput)
			if err != nil {
				return nil, err
			}
		} else {
			// Other errors should propagate immediately
			return nil, err
		}
	}

	// Fetch full account details using existing retry logic
	s.Logger.Info("Fetching full account details for account ID [%s]", result.ID)
	account, err := s.accountWithRetry(&awsmodels.TfIdsecCCEAWSGetAccount{
		ID: result.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch account details after adding to organization: %w", err)
	}

	return account, nil
}
