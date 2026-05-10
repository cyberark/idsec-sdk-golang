package cloudaccess

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sca"
	cloudaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/cloudaccess/models"
	scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"
)

const (
	// eligibilityURLFmt is the endpoint for listing eligible cloudaccess targets.
	// The CSP (AWS | AZURE | GCP) is a path parameter.
	eligibilityURLFmt = "/api/access/%s/eligibility"

	// elevateRelURL is the endpoint for obtaining short-lived cloud credentials.
	elevateRelURL = "/api/access/elevate"

	// maxRoleIDs is the maximum number of comma-separated role IDs allowed per elevate call.
	maxRoleIDs = 5

	// maxAWSRoleIDs is the maximum number of role IDs AWS accepts per elevate call.
	maxAWSRoleIDs = 1
)

// IdsecSCACloudAccessService provides SCA cloudaccess eligibility operations.
//
// It is an independent service that hits GET /api/access/{csp}/eligibility
// and supports AWS, AZURE and GCP as valid CSP values.
//
// Initialization requires a valid "isp" authenticator. Token refresh is delegated
// to refreshAuth.
//
// Example:
//
//	svc, err := NewIdsecSCACloudAccessService(ispAuth)
//	if err != nil { /* handle */ }
//	resp, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AWS"})
//	if err != nil { /* handle */ }
//	for _, t := range resp.Response { fmt.Println(t.WorkspaceName) } // t is cloudaccessmodels.IdsecSCAEligibleTarget
type IdsecSCACloudAccessService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecSCACloudAccessService creates a new IdsecSCACloudAccessService instance
// using the provided authenticators. An "isp" authenticator is required.
func NewIdsecSCACloudAccessService(authenticators ...auth.IdsecAuth) (*IdsecSCACloudAccessService, error) {
	svc := &IdsecSCACloudAccessService{}
	base, err := services.NewIdsecBaseService(svc, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := base.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "sca", ".", "", svc.refreshAuth)
	if err != nil {
		return nil, err
	}
	ispBaseService.ISPClient().SetHeader("X-API-Version", "2.0")

	svc.IdsecBaseService = base
	svc.IdsecISPBaseService = ispBaseService
	return svc, nil
}

func (s *IdsecSCACloudAccessService) refreshAuth(client *common.IdsecClient) error {
	return isp.RefreshClient(client, s.ISPAuth())
}

// ListTargets retrieves eligible cloudaccess targets for the authenticated user.
//
// It calls GET /api/access/{csp}/eligibility where CSP is a path parameter.
// Supports optional filtering by WorkspaceID and pagination via Limit and NextToken.
//
// Parameters:
//   - req: *IdsecSCAListTargetsRequest containing CSP (required), WorkspaceID, Limit
//     and NextToken (optional); must be non-nil.
//
// Returns *IdsecSCAListTargetsResponse with Response, Total and NextToken on success, or error when:
//   - req is nil
//   - CSP is empty or not one of AWS / AZURE / GCP
//   - the service is not initialized
//   - the network call fails
//   - the response status is not 200
//   - decoding fails
//
// Example:
//
//	resp, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AWS"})
//	if err != nil { /* handle */ }
//	for _, t := range resp.Response { fmt.Println(t.WorkspaceName) }
func (s *IdsecSCACloudAccessService) ListTargets(req *scamodels.IdsecSCAListTargetsRequest) (*cloudaccessmodels.IdsecSCAListTargetsResponse, error) { //nolint:revive
	if req == nil {
		return nil, fmt.Errorf("list targets request cannot be nil")
	}
	if req.CSP == "" {
		return nil, fmt.Errorf("csp cannot be empty")
	}
	supported := map[string]struct{}{"AWS": {}, "AZURE": {}, "GCP": {}}
	cspUpper := strings.ToUpper(req.CSP)
	if _, ok := supported[cspUpper]; !ok {
		return nil, fmt.Errorf("unsupported csp '%s': supported values are AWS, AZURE, GCP", req.CSP)
	}
	if s == nil || s.IdsecISPBaseService == nil || s.ISPClient() == nil {
		return nil, fmt.Errorf("sca cloudaccess service not initialized")
	}
	params := map[string]string{}
	if req.WorkspaceID != "" {
		params["workspaceId"] = req.WorkspaceID
	}
	if req.Limit > 0 {
		params["limit"] = fmt.Sprintf("%d", req.Limit)
	}
	if req.NextToken != "" {
		params["nextToken"] = req.NextToken
	}
	url := fmt.Sprintf(eligibilityURLFmt, cspUpper)
	s.Logger.Info("Listing SCA eligible cloudaccess targets for CSP [%s]", cspUpper)
	resp, err := s.ISPClient().Get(context.Background(), url, params)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list targets - [%d] - [%s]", resp.StatusCode, common.SerializeResponseToJSON(resp.Body))
	}
	decoded, err := common.DeserializeJSONCamel(resp.Body)
	if err != nil {
		return nil, err
	}
	dataMap, ok := decoded.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format from eligibility API")
	}
	var response cloudaccessmodels.IdsecSCAListTargetsResponse
	if err = mapstructure.Decode(dataMap, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// Elevate calls the SCA Elevate API to obtain short-lived cloud credentials.
//
// The flat request schema (IdsecSCACloudAccessElevateActionRequest) is used so
// the CLI framework can auto-wire flags directly to this method by naming convention
// ("elevate" → Elevate()), identical to how "list-targets" → ListTargets() works.
//
// Parameters:
//   - req: *IdsecSCACloudAccessElevateActionRequest with CSP, WorkspaceID, and RoleIDs (required).
//
// Returns *IdsecSCACloudAccessElevateResponse on success or an error when:
//   - req is nil, CSP is empty, WorkspaceID is empty, or RoleIDs is empty
//   - the network call fails or the response status is not 200
//   - JSON decoding fails
func (s *IdsecSCACloudAccessService) Elevate(req *cloudaccessmodels.IdsecSCACloudAccessElevateActionRequest) (*cloudaccessmodels.IdsecSCACloudAccessElevateResponse, error) { //nolint:revive
	if req == nil {
		return nil, fmt.Errorf("elevate request cannot be nil")
	}
	if strings.TrimSpace(req.CSP) == "" {
		return nil, fmt.Errorf("csp cannot be empty")
	}
	if strings.TrimSpace(req.WorkspaceID) == "" {
		return nil, fmt.Errorf("workspaceId cannot be empty")
	}
	if strings.TrimSpace(req.RoleIDs) == "" {
		return nil, fmt.Errorf("roleIds cannot be empty")
	}

	roleIDs := sca.SplitCommaSeparated(req.RoleIDs)
	maxAllowedRoleIDs := maxRoleIDs
	if strings.EqualFold(strings.TrimSpace(req.CSP), "AWS") {
		maxAllowedRoleIDs = maxAWSRoleIDs
	}
	if len(roleIDs) > maxAllowedRoleIDs {
		return nil, fmt.Errorf("maximum %d role IDs allowed for %s, got %d", maxAllowedRoleIDs, strings.ToUpper(strings.TrimSpace(req.CSP)), len(roleIDs))
	}

	if s == nil || s.IdsecISPBaseService == nil || s.ISPClient() == nil {
		return nil, fmt.Errorf("sca cloudaccess service not initialized")
	}
	s.Logger.Info("Calling SCA Elevate API for CSP [%s] workspaceId [%s]", req.CSP, req.WorkspaceID)

	var targets []cloudaccessmodels.IdsecSCACloudAccessElevateTarget
	for _, rid := range roleIDs {
		targets = append(targets, cloudaccessmodels.IdsecSCACloudAccessElevateTarget{
			WorkspaceID: req.WorkspaceID,
			RoleID:      rid,
		})
	}

	apiReq := &cloudaccessmodels.IdsecSCACloudAccessElevateRequest{
		CSP:            req.CSP,
		OrganizationID: req.OrganizationID,
		Targets:        targets,
	}

	resp, err := s.ISPClient().Post(context.Background(), elevateRelURL, apiReq)
	if err != nil {
		return nil, fmt.Errorf("elevate API call failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("elevate API returned status %d. Response body: %s", resp.StatusCode, string(bodyBytes))
	}

	var result cloudaccessmodels.IdsecSCACloudAccessElevateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode elevate response: %w", err)
	}
	return &result, nil
}

// ServiceConfig returns the service configuration (implements services.IdsecService).
func (s *IdsecSCACloudAccessService) ServiceConfig() services.IdsecServiceConfig { //nolint:revive
	return ServiceConfig
}
