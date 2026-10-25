package groupaccess

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
	groupaccessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/groupaccess/models"
	scacommon "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/internal/common"
	scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"
)

const (
	eligibilityGroupsURLFmt = "/api/access/%s/eligibility/groups"
	elevateGroupsURL        = "/api/access/elevate/groups"
	maxGroupIDs             = 5
	gcpGroupIDPrefix        = "groups/"
)

var supportedCSPs = []string{scamodels.CSPAzure, scamodels.CSPGCP}

// IdsecSCAGroupAccessService provides SCA group eligibility and elevate operations
// for Entra ID (AZURE) and Google Cloud (GCP) groups.
type IdsecSCAGroupAccessService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecSCAGroupAccessService creates a new service instance. Requires an "isp" authenticator.
func NewIdsecSCAGroupAccessService(authenticators ...auth.IdsecAuth) (*IdsecSCAGroupAccessService, error) {
	svc := &IdsecSCAGroupAccessService{}
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

func (s *IdsecSCAGroupAccessService) refreshAuth(client *common.IdsecClient) error {
	return isp.RefreshClient(client, s.ISPAuth())
}

// ListTargets retrieves eligible group targets via
// GET /api/access/{csp}/eligibility/groups. AZURE and GCP are supported.
func (s *IdsecSCAGroupAccessService) ListTargets(req *scamodels.IdsecSCAListTargetsRequest) (*groupaccessmodels.IdsecSCAListGroupTargetsResponse, error) { //nolint:revive
	if req == nil {
		return nil, fmt.Errorf("list targets request cannot be nil")
	}
	if req.CSP == "" {
		return nil, scacommon.ErrCSPEmpty(supportedCSPs...)
	}
	if !scacommon.IsSupportedCSP(req.CSP, supportedCSPs...) {
		return nil, scacommon.ErrUnsupportedCSP(req.CSP, supportedCSPs...)
	}
	csp := strings.ToUpper(strings.TrimSpace(req.CSP))
	if s == nil || s.IdsecISPBaseService == nil || s.ISPClient() == nil {
		return nil, fmt.Errorf("sca groupaccess service not initialized")
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
	url := fmt.Sprintf(eligibilityGroupsURLFmt, csp)
	s.Logger.Info("Listing SCA eligible group targets for CSP [%s]", csp)
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
	var response groupaccessmodels.IdsecSCAListGroupTargetsResponse
	if err = mapstructure.Decode(dataMap, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// Elevate requests just-in-time membership to one or more groups via
// POST /api/access/elevate/groups. AZURE requires --directory-id; GCP requires
// --organization-id and group IDs in the groups/{id} format. The --groups flag
// accepts comma-separated group IDs (max 5).
func (s *IdsecSCAGroupAccessService) Elevate(req *groupaccessmodels.IdsecSCAGroupAccessElevateActionRequest) (*groupaccessmodels.IdsecSCAGroupAccessElevateResponse, error) { //nolint:revive
	if req == nil {
		return nil, fmt.Errorf("elevate request cannot be nil")
	}
	if strings.TrimSpace(req.CSP) == "" {
		return nil, scacommon.ErrCSPEmpty(supportedCSPs...)
	}
	if !scacommon.IsSupportedCSP(req.CSP, supportedCSPs...) {
		return nil, scacommon.ErrUnsupportedCSP(req.CSP, supportedCSPs...)
	}
	csp := strings.ToUpper(strings.TrimSpace(req.CSP))

	scopeKey, scopeID := "directory_id", strings.TrimSpace(req.DirectoryID)
	if csp == scamodels.CSPGCP {
		scopeKey, scopeID = "organization_id", strings.TrimSpace(req.OrganizationID)
		if scopeID == "" {
			return nil, fmt.Errorf("organizationId cannot be empty")
		}
	} else if scopeID == "" {
		return nil, fmt.Errorf("directoryId cannot be empty")
	}
	if strings.TrimSpace(req.Groups) == "" {
		return nil, fmt.Errorf("groups cannot be empty")
	}

	groupIDs := sca.SplitCommaSeparated(req.Groups)
	if len(groupIDs) > maxGroupIDs {
		return nil, fmt.Errorf("maximum %d group IDs allowed, got %d", maxGroupIDs, len(groupIDs))
	}
	if csp == scamodels.CSPGCP {
		for _, gid := range groupIDs {
			if !strings.HasPrefix(gid, gcpGroupIDPrefix) || len(gid) == len(gcpGroupIDPrefix) {
				return nil, fmt.Errorf("invalid GCP group ID '%s': expected the format %s{id}", gid, gcpGroupIDPrefix)
			}
		}
	}

	if s == nil || s.IdsecISPBaseService == nil || s.ISPClient() == nil {
		return nil, fmt.Errorf("sca groupaccess service not initialized")
	}

	targets := make([]map[string]interface{}, len(groupIDs))
	for i, gid := range groupIDs {
		targets[i] = map[string]interface{}{"group_id": gid}
	}
	body := map[string]interface{}{
		"csp":     csp,
		scopeKey:  scopeID,
		"targets": targets,
	}
	s.Logger.Info("Elevating into %d %s group(s) in [%s]", len(groupIDs), csp, scopeID)
	resp, err := s.ISPClient().Post(context.Background(), elevateGroupsURL, body)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to elevate group - [%d] - [%s]", resp.StatusCode, common.SerializeResponseToJSON(resp.Body))
	}
	decoded, err := common.DeserializeJSONCamel(resp.Body)
	if err != nil {
		return nil, err
	}
	dataMap, ok := decoded.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected response format from elevate groups API")
	}
	var response groupaccessmodels.IdsecSCAGroupAccessElevateResponse
	if err = mapstructure.Decode(dataMap, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// ServiceConfig returns the service configuration (implements services.IdsecService).
func (s *IdsecSCAGroupAccessService) ServiceConfig() services.IdsecServiceConfig { //nolint:revive
	return ServiceConfig
}
