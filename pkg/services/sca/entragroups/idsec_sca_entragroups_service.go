package entragroups

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sca"
	entragroupsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/entragroups/models"
	scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"
)

const (
	eligibilityGroupsURLFmt = "/api/access/%s/eligibility/groups"
	elevateGroupsURL        = "/api/access/elevate/groups"
	maxGroupIDs             = 50
)

// IdsecSCAEntraGroupsService provides SCA Entra ID group eligibility and elevate operations (AZURE-only).
type IdsecSCAEntraGroupsService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecSCAEntraGroupsService creates a new service instance. Requires an "isp" authenticator.
func NewIdsecSCAEntraGroupsService(authenticators ...auth.IdsecAuth) (*IdsecSCAEntraGroupsService, error) {
	svc := &IdsecSCAEntraGroupsService{}
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

func (s *IdsecSCAEntraGroupsService) refreshAuth(client *common.IdsecClient) error {
	return isp.RefreshClient(client, s.ISPAuth())
}

// ListTargets retrieves eligible Entra ID group targets via
// GET /api/access/{csp}/eligibility/groups. Only AZURE is supported.
func (s *IdsecSCAEntraGroupsService) ListTargets(req *scamodels.IdsecSCAListTargetsRequest) (*entragroupsmodels.IdsecSCAListGroupTargetsResponse, error) { //nolint:revive
	if req == nil {
		return nil, fmt.Errorf("list targets request cannot be nil")
	}
	if req.CSP == "" {
		return nil, fmt.Errorf("csp cannot be empty")
	}
	if strings.ToUpper(req.CSP) != "AZURE" {
		return nil, fmt.Errorf("unsupported csp '%s': only AZURE is supported for entragroups targets", req.CSP)
	}
	if s == nil || s.IdsecISPBaseService == nil || s.ISPClient() == nil {
		return nil, fmt.Errorf("sca entragroups service not initialized")
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
	url := fmt.Sprintf(eligibilityGroupsURLFmt, strings.ToUpper(req.CSP))
	s.Logger.Info("Listing SCA eligible group targets for CSP [AZURE]")
	resp, err := s.ISPClient().Get(context.Background(), url, params)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to list group targets - [%d] - [%s]", resp.StatusCode, common.SerializeResponseToJSON(resp.Body))
	}
	decoded, err := common.DeserializeJSONCamel(resp.Body)
	if err != nil {
		return nil, err
	}
	dataMap, ok := decoded.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format from eligibility groups API")
	}
	var response entragroupsmodels.IdsecSCAListGroupTargetsResponse
	if err = mapstructure.Decode(dataMap, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// Elevate requests just-in-time membership to one or more Entra ID groups
// via POST /api/access/elevate/groups. The --groups flag accepts comma-separated
// group IDs (max 50).
func (s *IdsecSCAEntraGroupsService) Elevate(req *entragroupsmodels.IdsecSCAEntraGroupsElevateActionRequest) (*entragroupsmodels.IdsecSCAEntraGroupsElevateResponse, error) { //nolint:revive
	if req == nil {
		return nil, fmt.Errorf("elevate request cannot be nil")
	}
	if strings.TrimSpace(req.CSP) == "" {
		return nil, fmt.Errorf("csp cannot be empty")
	}
	if strings.ToUpper(req.CSP) != "AZURE" {
		return nil, fmt.Errorf("unsupported csp '%s': only AZURE is supported for entragroups elevate", req.CSP)
	}
	if strings.TrimSpace(req.DirectoryID) == "" {
		return nil, fmt.Errorf("directoryId cannot be empty")
	}
	if strings.TrimSpace(req.Groups) == "" {
		return nil, fmt.Errorf("groups cannot be empty")
	}

	groupIDs := sca.SplitCommaSeparated(req.Groups)
	if len(groupIDs) > maxGroupIDs {
		return nil, fmt.Errorf("maximum %d group IDs allowed, got %d", maxGroupIDs, len(groupIDs))
	}

	if s == nil || s.IdsecISPBaseService == nil || s.ISPClient() == nil {
		return nil, fmt.Errorf("sca entragroups service not initialized")
	}

	targets := make([]map[string]interface{}, len(groupIDs))
	for i, gid := range groupIDs {
		targets[i] = map[string]interface{}{"group_id": gid}
	}
	body := map[string]interface{}{
		"csp":          strings.ToUpper(req.CSP),
		"directory_id": req.DirectoryID,
		"targets":      targets,
	}
	s.Logger.Info("Elevating into %d Entra group(s) in directory [%s]", len(groupIDs), req.DirectoryID)
	resp, err := s.ISPClient().Post(context.Background(), elevateGroupsURL, body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to elevate entra group - [%d] - [%s]", resp.StatusCode, common.SerializeResponseToJSON(resp.Body))
	}
	decoded, err := common.DeserializeJSONCamel(resp.Body)
	if err != nil {
		return nil, err
	}
	dataMap, ok := decoded.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format from elevate groups API")
	}
	var response entragroupsmodels.IdsecSCAEntraGroupsElevateResponse
	if err = mapstructure.Decode(dataMap, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// ServiceConfig returns the service configuration (implements services.IdsecService).
func (s *IdsecSCAEntraGroupsService) ServiceConfig() services.IdsecServiceConfig { //nolint:revive
	return ServiceConfig
}
