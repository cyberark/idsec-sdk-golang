package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"reflect"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
)

// Request body/query keys and deployment type values shared across all
// /api/{platform}/manual onboarding endpoints (Azure, GCP, ...).
const (
	RequestKeyDeploymentType           = "deploymentType"
	RequestKeyOnboardingType           = "onboardingType"
	RequestKeyOnboardingTypeQueryParam = "onboarding_type"
	DeploymentTypeOrganization         = "organization"
	DeploymentTypeFolder               = "folder"
	DeploymentTypeStandalone           = "standalone"
)

// manualAddOutput is the common shape returned by POST /api/{platform}/manual across platforms.
type manualAddOutput struct {
	ID string `json:"id"`
}

// ManualClient wraps the /api/{platform}/manual onboarding endpoints, which are
// identical across Azure and GCP apart from the platform segment in the base path.
type ManualClient struct {
	client   *isp.IdsecISPServiceClient
	logger   *common.IdsecLogger
	basePath string // e.g. "/api/gcp/manual" or "/api/azure/manual"
}

// NewManualClient creates a ManualClient bound to the given ISP client, logger, and base path.
func NewManualClient(client *isp.IdsecISPServiceClient, logger *common.IdsecLogger, basePath string) *ManualClient {
	return &ManualClient{client: client, logger: logger, basePath: basePath}
}

// Create POSTs a manual onboarding request to the base path, injecting the given
// deploymentType and the terraform_provider onboardingType, and returns the new onboarding ID.
func (c *ManualClient) Create(body map[string]interface{}, deploymentType string) (string, error) {
	body[RequestKeyDeploymentType] = deploymentType
	body[RequestKeyOnboardingType] = ccemodels.TerraformProvider

	response, err := c.client.Post(context.Background(), c.basePath, body)
	if err != nil {
		return "", err
	}
	defer CloseResponseBody(response.Body)

	if !IsHTTPSuccess(response.StatusCode) {
		return "", HandleNon2xxResponse(c.logger, response.StatusCode, response.Body, "failed to create manual onboarding")
	}

	var addOutput manualAddOutput
	if err := json.NewDecoder(response.Body).Decode(&addOutput); err != nil {
		return "", err
	}

	return addOutput.ID, nil
}

// CurrentServiceNames GETs the given URL and extracts the "services" string list
// from the response, for use as the "current" side of a service reconcile.
func (c *ManualClient) CurrentServiceNames(getURL string) ([]string, error) {
	response, err := c.client.Get(context.Background(), getURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get current onboarding details: %w", err)
	}
	defer CloseResponseBody(response.Body)

	if !IsHTTPSuccess(response.StatusCode) {
		return nil, HandleNon2xxResponse(c.logger, response.StatusCode, response.Body, "failed to get onboarding details")
	}

	entityJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize onboarding response: %w", err)
	}

	return ExtractServiceNames(entityJSON), nil
}

// CurrentServiceState holds the currently deployed service names, per-service versions, and
// per-service parameters (resources) for a manual onboarding entity, as read from its raw JSON.
// It is the "current" side of a version/resources-aware reconcile (see UpdateServicesWithReconcile).
type CurrentServiceState struct {
	Names      []string
	Versions   map[string]string
	Parameters map[string]map[string]interface{}
}

// GetCurrentServiceState GETs the given URL once and extracts the current service names,
// per-service versions (from "services_data"), and per-service parameters (from "parameters"),
// for use as the "current" side of a version/resources-aware service reconcile via
// UpdateServicesWithReconcile.
func (c *ManualClient) GetCurrentServiceState(getURL string) (*CurrentServiceState, error) {
	response, err := c.client.Get(context.Background(), getURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get current onboarding details: %w", err)
	}
	defer CloseResponseBody(response.Body)

	if !IsHTTPSuccess(response.StatusCode) {
		return nil, HandleNon2xxResponse(c.logger, response.StatusCode, response.Body, "failed to get onboarding details")
	}

	entityJSON, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize onboarding response: %w", err)
	}

	return &CurrentServiceState{
		Names:      ExtractServiceNames(entityJSON),
		Versions:   extractCurrentServiceVersions(entityJSON),
		Parameters: extractCurrentServiceParameters(entityJSON),
	}, nil
}

// extractCurrentServiceVersions builds a map of service name -> currently deployed version from
// the entity's "services_data" array. Services without a version entry are simply omitted.
// It is used to decide which already-onboarded services represent a real version upgrade (the
// only in-place change the add/update-services endpoint accepts, besides resources) versus an
// unchanged service that must be excluded from the request to avoid a 501 FEATURE_NOT_IMPLEMENTED
// response for a service that is not update-enabled.
func extractCurrentServiceVersions(entityJSON interface{}) map[string]string {
	versions := map[string]string{}
	entityMap, ok := entityJSON.(map[string]interface{})
	if !ok {
		return versions
	}
	servicesDataRaw, exists := entityMap["services_data"]
	if !exists {
		return versions
	}
	servicesDataList, ok := servicesDataRaw.([]interface{})
	if !ok {
		return versions
	}
	for _, svcData := range servicesDataList {
		svcMap, ok := svcData.(map[string]interface{})
		if !ok {
			continue
		}
		name, hasName := svcMap["name"].(string)
		version, hasVersion := svcMap["version"].(string)
		if hasName && hasVersion {
			versions[name] = version
		}
	}
	return versions
}

// extractCurrentServiceParameters builds a map of service name -> currently deployed parameters
// from the entity's "parameters" object (keyed by service name). The API returns each service's
// stored parameters (user-controlled resources), snake_cased on read. It is used to detect a real
// resources change on an already-onboarded service: the add/update-services endpoint applies such
// partial updates, but rejects (501 FEATURE_NOT_IMPLEMENTED) an already-onboarded service that is
// not update-enabled, so only genuinely-changed services must be sent.
func extractCurrentServiceParameters(entityJSON interface{}) map[string]map[string]interface{} {
	params := map[string]map[string]interface{}{}
	entityMap, ok := entityJSON.(map[string]interface{})
	if !ok {
		return params
	}
	raw, exists := entityMap["parameters"]
	if !exists {
		return params
	}
	perService, ok := raw.(map[string]interface{})
	if !ok {
		return params
	}
	for name, val := range perService {
		if svcParams, ok := val.(map[string]interface{}); ok {
			params[name] = svcParams
		}
	}
	return params
}

// ServiceParamsChanged reports whether the desired resources/parameters for an already-onboarded
// service differ from what is currently deployed. Only keys present in `desired` are inspected, so
// server-managed extras stored alongside the user's parameters (e.g. generated role ARNs) never
// produce a false positive that would re-send an unchanged service and trigger a 501. `desired`
// uses the caller's key casing (e.g. "SecretsManagerRegions") and is normalized to the snake_case
// form the API returns before comparison. Returns true when a desired key holds a different value
// than `current`, or when a desired key with a non-empty value is missing from `current`. A desired
// key that is missing from `current` but whose value is empty (nil / "" / empty collection) is NOT
// a change: optional inputs left unset (e.g. sca's `ssoRegion` when SSO is disabled) are dropped on
// the stored/API side, and counting their absence as a change would re-send an unchanged service
// and trigger a 501.
//
// This is the single, platform-agnostic home for this comparison logic, shared by all CCE
// platforms (AWS, Azure, GCP, ...) so it can't diverge between them.
func ServiceParamsChanged(desired, current map[string]interface{}) bool {
	if len(desired) == 0 {
		return false
	}
	normalized, ok := common.ConvertToSnakeCase(desired, nil).(map[string]interface{})
	if !ok {
		return true
	}
	for key, desiredVal := range normalized {
		currentVal, exists := current[key]
		if !exists {
			// A desired key absent from `current` is only a real change when the desired value is
			// non-empty. An unset optional parameter (nil / empty string / empty collection) - e.g.
			// sca's `ssoRegion` when SSO is disabled - is dropped on the stored/API side, so treating
			// its absence as a change would re-send an otherwise-unchanged service and trip the 501.
			if IsEmptyParamValue(desiredVal) {
				continue
			}
			return true
		}
		if !JSONValuesEqual(desiredVal, currentVal) {
			return true
		}
	}
	return false
}

// IsEmptyParamValue reports whether a desired parameter value is "unset" for change-detection
// purposes: nil, an empty string, or an empty map/slice. Such a value is equivalent to the key
// being absent on the stored/API side (the API drops optional inputs that are empty), so it must
// not count as a change.
func IsEmptyParamValue(v interface{}) bool {
	switch val := v.(type) {
	case nil:
		return true
	case string:
		return val == ""
	case map[string]interface{}:
		return len(val) == 0
	case []interface{}:
		return len(val) == 0
	}
	return false
}

// JSONValuesEqual compares two decoded-JSON values for equality by marshaling them back to JSON.
// This normalizes ordering-insensitive maps and typed slices (e.g. []interface{} vs []string)
// that reflect.DeepEqual would otherwise report as different. Falls back to reflect.DeepEqual if
// marshaling fails.
func JSONValuesEqual(a, b interface{}) bool {
	aBytes, errA := json.Marshal(a)
	bBytes, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return reflect.DeepEqual(a, b)
	}
	return string(aBytes) == string(bBytes)
}

// reconcileDesiredServices determines which desired services must be sent to the add-services
// endpoint: brand-new services (not yet onboarded), already-onboarded services whose desired
// version differs from what is currently deployed, and already-onboarded services whose desired
// resources differ from what is currently deployed. Unchanged services are omitted so we never
// re-send an already-onboarded service that isn't update-enabled (which the API rejects with 501
// FEATURE_NOT_IMPLEMENTED).
func (c *ManualClient) reconcileDesiredServices(
	desiredServices []ccemodels.IdsecCCEServiceInput,
	current *CurrentServiceState,
) []ccemodels.IdsecCCEServiceInput {
	currentServiceNamesSet := make(map[string]bool, len(current.Names))
	for _, serviceName := range current.Names {
		currentServiceNamesSet[serviceName] = true
	}

	var servicesToSend []ccemodels.IdsecCCEServiceInput
	for _, service := range desiredServices {
		currentVersion := current.Versions[service.ServiceName]
		switch {
		case !currentServiceNamesSet[service.ServiceName]:
			servicesToSend = append(servicesToSend, service)
			c.logger.Info("Service '%s' is NEW and will be ADDED", service.ServiceName)
		case service.Version != "" && service.Version != currentVersion:
			servicesToSend = append(servicesToSend, service)
			c.logger.Info("Service '%s' version changed (%s -> %s) and will be UPGRADED", service.ServiceName, currentVersion, service.Version)
		case ServiceParamsChanged(service.Resources, current.Parameters[service.ServiceName]):
			servicesToSend = append(servicesToSend, service)
			c.logger.Info("Service '%s' resources changed and will be UPDATED", service.ServiceName)
		default:
			c.logger.Info("Service '%s' is unchanged (version %s), skipping to avoid an unsupported update request", service.ServiceName, currentVersion)
		}
	}
	return servicesToSend
}

// UpdateServicesWithReconcile reconciles the desired services against the currently deployed
// state (names, versions, and resources), adding brand-new services, pushing partial updates
// (version upgrade and/or a resources change) to already-onboarded services whose desired state
// differs from what is deployed, and removing services that are no longer desired.
//
// Unlike UpdateServices, which only diffs by service name, this also detects in-place changes on
// already-onboarded services. Unchanged already-onboarded services are omitted from the request
// so the (idempotent) add/update-services endpoint leaves them untouched and does not reject the
// request with a 501 for a service that is not update-enabled: the endpoint validates every
// already-onboarded service it's given, changed or not.
func (c *ManualClient) UpdateServicesWithReconcile(
	id string,
	current *CurrentServiceState,
	desiredServices []ccemodels.IdsecCCEServiceInput,
	resourceType string,
) error {
	c.logger.Info("Updating services for %s [%s]", resourceType, id)
	c.logger.Info("Current %s services: %v", resourceType, current.Names)

	desiredServicesSet := make(map[string]bool, len(desiredServices))
	for _, service := range desiredServices {
		desiredServicesSet[service.ServiceName] = true
	}

	servicesToSend := c.reconcileDesiredServices(desiredServices, current)

	var servicesToRemove []string
	for _, serviceName := range current.Names {
		if !desiredServicesSet[serviceName] {
			servicesToRemove = append(servicesToRemove, serviceName)
			c.logger.Info("Service '%s' will be REMOVED", serviceName)
		}
	}

	c.logger.Info("Services to add/upgrade/update: %d, Services to remove: %d\n", len(servicesToSend), len(servicesToRemove))

	if len(servicesToSend) > 0 {
		c.logger.Info("Sending %d service(s) to %s [%s]", len(servicesToSend), resourceType, id)
		if err := c.AddServices(id, servicesToSend); err != nil {
			return fmt.Errorf("failed to add/update services: %w", err)
		}
	}

	if len(servicesToRemove) > 0 {
		c.logger.Info("Removing %d services from %s [%s]", len(servicesToRemove), resourceType, id)
		if err := c.DeleteServices(id, servicesToRemove); err != nil {
			return fmt.Errorf("failed to remove services: %w", err)
		}
	}

	return nil
}

// UpdateServices reconciles the desired services against the currently onboarded services,
// adding new services and removing services that are no longer desired.
func (c *ManualClient) UpdateServices(id string, currentServiceNames []string, desiredServices []ccemodels.IdsecCCEServiceInput, resourceType string) error {
	c.logger.Info("Updating services for %s [%s]", resourceType, id)

	desiredServicesMap := make(map[string]ccemodels.IdsecCCEServiceInput)
	for _, service := range desiredServices {
		desiredServicesMap[service.ServiceName] = service
	}

	currentServices := make(map[string]bool)
	for _, serviceName := range currentServiceNames {
		currentServices[serviceName] = true
	}

	c.logger.Info("Current %s services: %v", resourceType, currentServiceNames)
	c.logger.Info("Desired %s services after update: %v", resourceType, func() []string {
		names := make([]string, 0, len(desiredServicesMap))
		for name := range desiredServicesMap {
			names = append(names, name)
		}
		return names
	}())

	var servicesToAdd []ccemodels.IdsecCCEServiceInput
	for serviceName, service := range desiredServicesMap {
		if !currentServices[serviceName] {
			servicesToAdd = append(servicesToAdd, service)
			c.logger.Info("Service '%s' will be ADDED", serviceName)
		}
	}

	var servicesToRemove []string
	for serviceName := range currentServices {
		if _, exists := desiredServicesMap[serviceName]; !exists {
			servicesToRemove = append(servicesToRemove, serviceName)
			c.logger.Info("Service '%s' will be REMOVED", serviceName)
		}
	}

	c.logger.Info("Services to add: %d, Services to remove: %d\n", len(servicesToAdd), len(servicesToRemove))

	if len(servicesToAdd) > 0 {
		c.logger.Info("Adding %d services to %s [%s]", len(servicesToAdd), resourceType, id)
		if err := c.AddServices(id, servicesToAdd); err != nil {
			return fmt.Errorf("failed to add services: %w", err)
		}
	}

	if len(servicesToRemove) > 0 {
		c.logger.Info("Removing %d services from %s [%s]", len(servicesToRemove), resourceType, id)
		if err := c.DeleteServices(id, servicesToRemove); err != nil {
			return fmt.Errorf("failed to remove services: %w", err)
		}
	}

	return nil
}

// AddServices adds services to a manual onboarding.
// API: POST /api/{platform}/manual/{id}/services
func (c *ManualClient) AddServices(id string, services []ccemodels.IdsecCCEServiceInput) error {
	c.logger.Info("Adding services to manual onboarding [%s]", id)

	url := fmt.Sprintf("%s/%s/services", c.basePath, id)
	requestBody := map[string]interface{}{
		"services": services,
		// Explicitly set the onboarding type to terraform_provider so the API enforces that this entity was onboarded via Terraform.
		RequestKeyOnboardingType: ccemodels.TerraformProvider,
	}

	response, err := c.client.Post(context.Background(), url, requestBody)
	if err != nil {
		return err
	}
	defer CloseResponseBody(response.Body)

	if !IsHTTPSuccess(response.StatusCode) {
		return HandleNon2xxResponse(c.logger, response.StatusCode, response.Body, "failed to add services")
	}

	return nil
}

// DeleteServices removes services from a manual onboarding.
// API: DELETE /api/{platform}/manual/{id}/services
func (c *ManualClient) DeleteServices(id string, serviceNames []string) error {
	c.logger.Info("Removing services from manual onboarding [%s]", id)

	url := fmt.Sprintf("%s/%s/services", c.basePath, id)

	// Build query parameters using url.Values to properly encode multiple values with the same key
	// The API expects multiple services_names query params like: services_names=dpa&services_names=epm
	params := map[string][]string{
		"services_names": serviceNames,
		// Explicitly set the onboarding type to terraform_provider so the API enforces that this entity was onboarded via Terraform.
		RequestKeyOnboardingTypeQueryParam: {ccemodels.TerraformProvider},
	}

	c.logger.Info("Deleting services: %v from entity [%s]", serviceNames, id)

	response, err := c.client.Delete(context.Background(), url, nil, params)
	if err != nil {
		return fmt.Errorf("failed to delete services from manual onboarding: %w", err)
	}
	defer CloseResponseBody(response.Body)

	if !IsHTTPSuccess(response.StatusCode) {
		bodyBytes, _ := io.ReadAll(response.Body)
		return fmt.Errorf("failed to delete services from manual onboarding: status code %d, body: %s", response.StatusCode, string(bodyBytes))
	}

	return nil
}

// Delete deletes a manual onboarding.
// API: DELETE /api/{platform}/manual/{id}
func (c *ManualClient) Delete(id string) error {
	c.logger.Info("Deleting manual onboarding [%s]", id)

	url := fmt.Sprintf("%s/%s", c.basePath, id)
	// Explicitly set the onboarding type to terraform_provider so the API enforces that this entity was onboarded via Terraform.
	params := map[string][]string{RequestKeyOnboardingTypeQueryParam: {ccemodels.TerraformProvider}}
	response, err := c.client.Delete(context.Background(), url, nil, params)
	if err != nil {
		return err
	}
	defer CloseResponseBody(response.Body)

	if !IsHTTPSuccess(response.StatusCode) {
		return HandleNon2xxResponse(c.logger, response.StatusCode, response.Body, "failed to delete manual onboarding")
	}

	return nil
}

// StructToMap converts a struct to map[string]interface{} using JSON marshaling.
// This is a helper function to simplify request body preparation.
func StructToMap(v interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal struct: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal to map: %w", err)
	}

	return result, nil
}

// ExtractServiceNames extracts the list of service names from an entity JSON response.
// This logic is shared across all manual onboarding entities (Entra, Management Group,
// Subscription, Project, ...). It assumes all entities have a "services" field containing
// an array of service name strings.
func ExtractServiceNames(entityJSON interface{}) []string {
	var serviceNames []string
	if entityMap, ok := entityJSON.(map[string]interface{}); ok {
		if servicesRaw, exists := entityMap["services"]; exists {
			if servicesList, ok := servicesRaw.([]interface{}); ok {
				for _, svc := range servicesList {
					if svcStr, ok := svc.(string); ok {
						serviceNames = append(serviceNames, svcStr)
					}
				}
			}
		}
	}
	return serviceNames
}

// GetWithRetry wraps common.RetryCall with the CCE default retry configuration,
// replacing the per-entity tfXWithRetry functions duplicated across platforms.
func GetWithRetry[T any](logger *common.IdsecLogger, resourceType string, get func() (*T, error)) (*T, error) {
	var result *T
	err := common.RetryCall(func() error {
		res, getErr := get()
		if getErr != nil {
			return getErr
		}
		result = res
		return nil
	}, DefaultMaxRequestRetries, DefaultRetryDelaySeconds, nil, DefaultRetryBackoffMultiplier, 0, func(err error, delay int) {
		logger.Info("Retrying to get %s in %d seconds: %v", resourceType, delay, err)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve %s: %w", resourceType, err)
	}

	return result, nil
}
