package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

const (
	eligibilityRelURL = "/access/<csp>/eligibility/clusters"

	// elevateRelURL is the relative URL for the Elevate API (relative to the api/ base path).
	elevateRelURL            = "access/elevate/clusters"
	generateKubeconfigRelURL = "integration/k8s/generate-kubeconfig"
)

// IdsecSCAK8sService provides SCA Kubernetes cluster discovery capabilities.
//
// It exposes ListClusters to list clusters eligible for SCA discovery from the backend.
// Initialization requires a valid IdsecISPAuth to construct the internal ISP client.
//
// Concurrency: The service is safe for concurrent use provided the underlying
// IdsecISPServiceClient is concurrency-safe.
//
// Error Handling: All methods return contextual errors describing validation,
// network or decoding failures.
type IdsecSCAK8sService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecSCAK8sService creates a new SCA K8s service instance using provided authenticators.
//
// Parameters:
//   - authenticators: Variadic list of auth.IdsecAuth; must include an "isp" authenticator.
//
// Returns *IdsecSCAK8sService or error if required authenticators missing or client init fails.
func NewIdsecSCAK8sService(authenticators ...auth.IdsecAuth) (*IdsecSCAK8sService, error) {
	scak8sservice := &IdsecSCAK8sService{}
	base, err := services.NewIdsecBaseService(scak8sservice, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := base.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	// UAP base URL: https://<tenant>.sca.<platformdomain>/api/
	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "sca", ".", "api", scak8sservice.refreshScaAuth)
	if err != nil {
		return nil, err
	}

	scak8sservice.IdsecBaseService = base
	scak8sservice.IdsecISPBaseService = ispBaseService
	return scak8sservice, nil
}

// refreshScaAuth refreshes the underlying ISP client authentication.
func (s *IdsecSCAK8sService) refreshScaAuth(client *common.IdsecClient) error {
	return isp.RefreshClient(client, s.ISPAuth())
}

// ListTargets lists clusters eligible for SCA discovery via the eligibility API.
// req requires CSP (aws/azure/gcp, any case); optional workspaceId, limit (1-50), nextToken.
func (s *IdsecSCAK8sService) ListTargets(req *k8smodels.IdsecSCAk8sListClustersRequest) (*k8smodels.IdsecSCAk8sListClustersResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("list targets request cannot be nil")
	}
	csp := strings.TrimSpace(req.CSP)
	if csp == "" {
		return nil, fmt.Errorf("csp cannot be empty")
	}
	supported := map[string]struct{}{
		"aws":   {},
		"azure": {},
		"gcp":   {},
	}
	cspLower := strings.ToLower(csp)
	if _, ok := supported[cspLower]; !ok {
		return nil, fmt.Errorf("unsupported csp '%s'", csp)
	}
	cspUpper := strings.ToUpper(csp)
	if req.Limit != 0 && (req.Limit < 1 || req.Limit > 50) {
		return nil, fmt.Errorf("limit must be between 1 and 50, got %d", req.Limit)
	}
	if s == nil || s.IdsecISPBaseService == nil || s.ISPClient() == nil {
		return nil, fmt.Errorf("sca k8s service not initialized")
	}
	s.Logger.Info("Listing SCA eligible k8s clusters for CSP [%s]", cspUpper)

	params := make(map[string]string)
	if req.WorkspaceID != "" {
		params["workspaceId"] = req.WorkspaceID
	}
	if req.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", req.Limit)
	}
	if req.NextToken != "" {
		params["nextToken"] = req.NextToken
	}
	s.Logger.Debug("requesting list-targets API with params: %+v", params)

	route := strings.TrimPrefix(strings.Replace(eligibilityRelURL, "<csp>", cspUpper, 1), "/")

	// WAF rejects GET with Content-Type; restore after the call for other requests.
	s.ISPClient().RemoveHeader("Content-Type")
	response, err := s.ISPClient().Get(context.Background(), route, params)
	s.ISPClient().SetHeader("Content-Type", "application/json")

	if err != nil {
		return nil, fmt.Errorf("list-clusters API call failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(response.Body)
		return nil, fmt.Errorf(
			"list-clusters API returned status %d. Response body: %s",
			response.StatusCode, string(bodyBytes),
		)
	}

	var result k8smodels.IdsecSCAk8sListClustersResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode list-clusters response: %w", err)
	}
	return &result, nil
}

// Elevate calls the SCA Elevate API to obtain short-lived cloud credentials for
// the requested workspace/role target.
//
// Parameters:
//   - req: *IdsecSCAK8sElevateKubectlRequest with CSP (required), and either FQDN
//     or (WorkspaceID + TargetID), plus either RoleID or RoleName.
//
// Returns *IdsecSCAK8sElevateResponse on success or an error when:
//   - req is nil, CSP is empty, or required target fields are missing
//   - the network call fails or the response status is not 200
//   - JSON decoding fails
func (s *IdsecSCAK8sService) Elevate(req *k8smodels.IdsecSCAK8sElevateKubectlRequest) (*k8smodels.IdsecSCAK8sElevateResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("elevate request cannot be nil")
	}

	if strings.TrimSpace(req.CSP) == "" {
		return nil, fmt.Errorf("csp cannot be empty")
	}
	hasFQDN := strings.TrimSpace(req.FQDN) != ""
	hasWorkspaceAndTarget := strings.TrimSpace(req.WorkspaceID) != "" && strings.TrimSpace(req.TargetID) != ""
	if !hasFQDN && !hasWorkspaceAndTarget {
		return nil, fmt.Errorf("must specify either fqdn or (workspaceId + targetId)")
	}
	if strings.TrimSpace(req.RoleID) == "" && strings.TrimSpace(req.RoleName) == "" {
		return nil, fmt.Errorf("must specify either roleId or roleName")
	}
	if s == nil || s.IdsecISPBaseService == nil || s.ISPClient() == nil {
		return nil, fmt.Errorf("sca k8s service not initialized")
	}
	s.Logger.Debug("calling elevate API for CSP=%s", req.CSP)

	apiReq := &k8smodels.IdsecSCAK8sElevateRequest{
		CSP: req.CSP,
		Targets: []k8smodels.IdsecSCAK8sElevateTarget{
			{
				WorkspaceID: req.WorkspaceID,
				RoleID:      req.RoleID,
				RoleName:    req.RoleName,
				TargetID:    req.TargetID,
				FQDN:        req.FQDN,
			},
		},
	}

	response, err := s.ISPClient().Post(context.Background(), elevateRelURL, apiReq)
	if err != nil {
		return nil, fmt.Errorf("elevate API call failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(response.Body)
		return nil, fmt.Errorf(
			"elevate API returned status %d. Response body: %s",
			response.StatusCode, string(bodyBytes),
		)
	}

	var result k8smodels.IdsecSCAK8sElevateResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode elevate response: %w", err)
	}
	return &result, nil
}

// GenerateKubeconfig calls integration/k8s/generate-kubeconfig.
// Always sends ?all=<true|false> to the API. When req.CSP is non-empty, also sends ?csp=<value>.
// The backend Lambda reads both query_params["csp"] and query_params["all"].
// If req.CSP is empty and req.All is "false", returns an error (no valid call).
// Response is normalized to map[csp]yaml.
func (s *IdsecSCAK8sService) GenerateKubeconfig(req *k8smodels.IdsecSCAK8sGenerateKubeconfigRequest) (k8smodels.IdsecSCAK8sGenerateKubeconfigResponse, error) {
	var csp string
	allParam := "true"
	if req != nil {
		csp = strings.ToLower(strings.TrimSpace(req.CSP))
		_, norm, err := parseGenerateKubeconfigAllString(req.All)
		if err != nil {
			return nil, fmt.Errorf("generate-kubeconfig: %w", err)
		}
		allParam = norm
	}

	if csp == "" && req != nil && allParam == "false" {
		return nil, fmt.Errorf("generate-kubeconfig: specify --csp or set --all true; --all false with no --csp is invalid")
	}

	if csp != "" {
		supported := map[string]struct{}{
			"aws":   {},
			"azure": {},
			"gcp":   {},
		}
		if _, ok := supported[csp]; !ok {
			return nil, fmt.Errorf("unsupported csp '%s'; must be one of: aws, azure, gcp", csp)
		}
	}

	if s == nil || s.IdsecISPBaseService == nil || s.ISPClient() == nil {
		return nil, fmt.Errorf("sca k8s service not initialized")
	}

	cspDisplay := csp
	// When no CSP is provided, treat as "all"
	if cspDisplay == "" {
		cspDisplay = "all"
	}
	s.Logger.Info("Generating kubeconfig for CSP [%s]", cspDisplay)

	params := make(map[string]string)
	params["all"] = allParam
	if csp != "" {
		params["csp"] = csp
	}
	s.Logger.Debug("requesting generate-kubeconfig API with params: %+v", params)
	s.Logger.Info("generate-kubeconfig request — csp=%q, all=%q, params=%v", csp, allParam, params)

	s.ISPClient().RemoveHeader("Content-Type")
	response, err := s.ISPClient().Get(context.Background(), generateKubeconfigRelURL, params)
	s.ISPClient().SetHeader("Content-Type", "application/json")

	if err != nil {
		return nil, fmt.Errorf("generate-kubeconfig API call failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read generate-kubeconfig response body: %w", err)
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"generate-kubeconfig API returned status %d. Response body: %s",
			response.StatusCode, string(bodyBytes),
		)
	}

	s.Logger.Debug("generate-kubeconfig raw response length: %d bytes", len(bodyBytes))

	// Try JSON map first (all-CSPs response: {"aws":"...","azure":"...","gcp":"..."}).
	var mapResult k8smodels.IdsecSCAK8sGenerateKubeconfigResponse
	if err := json.Unmarshal(bodyBytes, &mapResult); err == nil && len(mapResult) > 0 {
		s.Logger.Debug("parsed generate-kubeconfig response as JSON map with %d entries", len(mapResult))
		return mapResult, nil
	}

	// Try JSON-quoted string (API returns the YAML wrapped in JSON quotes).
	var stringResult string
	if err := json.Unmarshal(bodyBytes, &stringResult); err == nil && strings.TrimSpace(stringResult) != "" {
		s.Logger.Debug("parsed generate-kubeconfig response as JSON string")
		key := csp
		if key == "" {
			key = "all"
		}
		return k8smodels.IdsecSCAK8sGenerateKubeconfigResponse{key: stringResult}, nil
	}

	rawBody := strings.TrimSpace(string(bodyBytes))
	if rawBody == "" {
		return nil, fmt.Errorf("generate-kubeconfig API returned empty response body")
	}
	s.Logger.Debug("treating generate-kubeconfig response as raw YAML")
	key := csp
	if key == "" {
		key = "all"
	}
	return k8smodels.IdsecSCAK8sGenerateKubeconfigResponse{key: rawBody}, nil
}

func (s *IdsecSCAK8sService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
