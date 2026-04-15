package cloudconsole

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
	cloudconsolemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/cloudconsole/models"
	scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"
)

const (
	// eligibilityURLFmt is the endpoint for listing eligible cloud-console targets.
	// The CSP (AWS | AZURE | GCP) is a path parameter.
	eligibilityURLFmt = "/api/access/%s/eligibility"

	// elevateRelURL is the endpoint for obtaining short-lived cloud credentials.
	elevateRelURL = "/api/access/elevate"

	// maxRoleIDs is the maximum number of comma-separated role IDs allowed per elevate call.
	maxRoleIDs = 5
)

// IdsecSCACloudConsoleService provides SCA cloud-console eligibility operations.
//
// It is an independent service that hits GET /api/access/{csp}/eligibility
// and supports AWS, AZURE and GCP as valid CSP values.
//
// Initialization requires a valid "isp" authenticator. Token refresh is delegated
// to refreshAuth.
//
// Example:
//
//	svc, err := NewIdsecSCACloudConsoleService(ispAuth)
//	if err != nil { /* handle */ }
//	resp, err := svc.ListTargets(&scamodels.IdsecSCAListTargetsRequest{CSP: "AWS"})
//	if err != nil { /* handle */ }
//	for _, t := range resp.Response { fmt.Println(t.WorkspaceName) } // t is cloudconsolemodels.IdsecSCAEligibleTarget
type IdsecSCACloudConsoleService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecSCACloudConsoleService creates a new IdsecSCACloudConsoleService instance
// using the provided authenticators. An "isp" authenticator is required.
func NewIdsecSCACloudConsoleService(authenticators ...auth.IdsecAuth) (*IdsecSCACloudConsoleService, error) {
	svc := &IdsecSCACloudConsoleService{}
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

func (s *IdsecSCACloudConsoleService) refreshAuth(client *common.IdsecClient) error {
	return isp.RefreshClient(client, s.ISPAuth())
}

// ListTargets retrieves eligible cloud-console targets for the authenticated user.
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
func (s *IdsecSCACloudConsoleService) ListTargets(req *scamodels.IdsecSCAListTargetsRequest) (*cloudconsolemodels.IdsecSCAListTargetsResponse, error) { //nolint:revive
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
		return nil, fmt.Errorf("sca cloud-console service not initialized")
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
	s.Logger.Info("Listing SCA eligible cloud-console targets for CSP [%s]", cspUpper)
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
	var response cloudconsolemodels.IdsecSCAListTargetsResponse
	if err = mapstructure.Decode(dataMap, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// Elevate calls the SCA Elevate API to obtain short-lived cloud credentials.
//
// The flat request schema (IdsecSCACloudConsoleElevateActionRequest) is used so
// the CLI framework can auto-wire flags directly to this method by naming convention
// ("elevate" → Elevate()), identical to how "list-targets" → ListTargets() works.
//
// Parameters:
//   - req: *IdsecSCACloudConsoleElevateActionRequest with CSP, WorkspaceID, and RoleID (required).
//
// Returns *IdsecSCACloudConsoleElevateResponse on success or an error when:
//   - req is nil, CSP is empty, WorkspaceID is empty, or RoleID is empty
//   - the network call fails or the response status is not 200
//   - JSON decoding fails
func (s *IdsecSCACloudConsoleService) Elevate(req *cloudconsolemodels.IdsecSCACloudConsoleElevateActionRequest) (*cloudconsolemodels.IdsecSCACloudConsoleElevateResponse, error) { //nolint:revive
	if req == nil {
		return nil, fmt.Errorf("elevate request cannot be nil")
	}
	if strings.TrimSpace(req.CSP) == "" {
		return nil, fmt.Errorf("csp cannot be empty")
	}
	if strings.TrimSpace(req.WorkspaceID) == "" {
		return nil, fmt.Errorf("workspaceId cannot be empty")
	}
	if strings.TrimSpace(req.RoleID) == "" {
		return nil, fmt.Errorf("roleId cannot be empty")
	}

	roleIDs := sca.SplitCommaSeparated(req.RoleID)
	if len(roleIDs) > maxRoleIDs {
		return nil, fmt.Errorf("maximum %d role IDs allowed, got %d", maxRoleIDs, len(roleIDs))
	}

	if s == nil || s.IdsecISPBaseService == nil || s.ISPClient() == nil {
		return nil, fmt.Errorf("sca cloud-console service not initialized")
	}
	s.Logger.Info("Calling SCA Elevate API for CSP [%s] workspaceId [%s]", req.CSP, req.WorkspaceID)

	var targets []cloudconsolemodels.IdsecSCACloudConsoleElevateTarget
	for _, rid := range roleIDs {
		targets = append(targets, cloudconsolemodels.IdsecSCACloudConsoleElevateTarget{
			WorkspaceID: req.WorkspaceID,
			RoleID:      rid,
		})
	}

	apiReq := &cloudconsolemodels.IdsecSCACloudConsoleElevateRequest{
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

	var result cloudconsolemodels.IdsecSCACloudConsoleElevateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode elevate response: %w", err)
	}
	return &result, nil
}

// ServiceConfig returns the service configuration (implements services.IdsecService).
func (s *IdsecSCACloudConsoleService) ServiceConfig() services.IdsecServiceConfig { //nolint:revive
	return ServiceConfig
}
