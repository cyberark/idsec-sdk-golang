package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/services"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	discoverymodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/discovery/models"
)

const (
	// discoveryURL is the backend endpoint for starting a discovery job
	discoveryURL = "/api/cloud/discovery"
	// jobStatusURL is the backend endpoint for polling job status
	jobStatusURL = "/api/integrations/status"
)

// IdsecSCADiscoveryService provides SCA discovery capabilities.
//
// Covers discovery related operations (Discovery, JobStatus and checkIfJobFinished).
//
// Initialization requires a valid IdsecISPAuth to construct the internal ISP client.
// The client is reused across discovery calls. Token refresh is delegated to
// refreshDiscoveryAuth.
//
// Example:
//
//	auth := &auth.IdsecISPAuth{/* populated */}
//	svc, err := NewIdsecSCADiscoveryService(auth)
//	if err != nil { /* handle */ }
//	job, err := svc.Discovery(&discoverymodels.IdsecSCADiscoveryRequest{ /* fields */ })
//
// Concurrency: The service is safe for concurrent use provided the underlying
// IdsecISPServiceClient is concurrency-safe (it is assumed to be so in the SDK).
// No internal mutable shared state beyond the client pointer exists.
//
// Error Handling: All methods return contextual errors describing validation,
// network or decoding failures. Discovery expects 200 status codes; status
// polling expects 200.
//
// Cancellation: checkIfJobFinished honors context cancellation.
//
// Timeouts: Polling attempts capped at 40 (20s delay) ~13m20s total.
type IdsecSCADiscoveryService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
}

// NewIdsecSCADiscoveryService creates a new SCA discovery service instance using provided authenticators.
//
// Parameters:
//   - authenticators: Variadic list of auth.IdsecAuth; must include an "isp" authenticator.
//
// Returns *IdsecSCADiscoveryService or error if required authenticators missing or client init fails.
func NewIdsecSCADiscoveryService(authenticators ...auth.IdsecAuth) (*IdsecSCADiscoveryService, error) {
	svc := &IdsecSCADiscoveryService{}
	base, err := services.NewIdsecBaseService(svc, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := base.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)

	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "sca", ".", "", svc.refreshDiscoveryAuth)
	if err != nil {
		return nil, err
	}
	ispBaseService.ISPClient().SetHeader("X-API-Version", "2.0")

	svc.IdsecBaseService = base
	svc.IdsecISPBaseService = ispBaseService
	return svc, nil
}

// refreshDiscoveryAuth refreshes the underlying ISP client authentication.
//
// It delegates to isp.RefreshClient using the stored ispAuth. Returns any
// propagation error from the refresh attempt.
func (s *IdsecSCADiscoveryService) refreshDiscoveryAuth(client *common.IdsecClient) error {
	return isp.RefreshClient(client, s.ISPAuth())
}

// serializePayload copies all JSON-marshalable keys from req into a generic map[string]interface{}.
// It does not perform key case conversion; keys reflect struct field JSON tags.
// Returns error when req is nil or marshal/unmarshal fails.
func serializePayload(req interface{}) (map[string]interface{}, error) {
	if req == nil {
		return nil, fmt.Errorf("req cannot be nil")
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	result := make(map[string]interface{})
	if err = json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// discoveryRequest starts an SCA discovery asynchronous job.
//
// Parameters:
//   - req: *IdsecSCADiscoveryRequest containing CSP, OrganizationID and AccountInfo; must be non-nil.
//
// Returns *IdsecSCADiscoveryResponse with populated JobID on success or error when:
//   - req is nil
//   - serialization fails
//   - network call fails
//   - response code is not 200
//   - decoding fails or JobID missing
func (s *IdsecSCADiscoveryService) discoveryRequest(req *discoverymodels.IdsecSCADiscoveryRequest) (*discoverymodels.IdsecSCADiscoveryResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("discovery request cannot be nil")
	}
	payloadMap, err := serializePayload(req)
	if err != nil {
		return nil, err
	}
	s.Logger.Info("Starting SCA discovery for CSP [%s] Org [%s] Account [%s]", req.CSP, req.OrganizationID, req.AccountInfo.ID)
	resp, err := s.ISPClient().Post(context.Background(), discoveryURL, payloadMap)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return nil, fmt.Errorf("failed to start discovery - [%d] - [%s]", resp.StatusCode, common.SerializeResponseToJSON(resp.Body))
	}
	decoded, err := common.DeserializeJSONSnake(resp.Body)
	if err != nil {
		return nil, err
	}
	var jobResp discoverymodels.IdsecSCADiscoveryResponse
	if err = mapstructure.Decode(decoded, &jobResp); err != nil {
		return nil, err
	}
	if jobResp.JobID == "" {
		return nil, fmt.Errorf("discovery job id missing in response")
	}
	return &jobResp, nil
}

// jobStatus retrieves the current status of an SCA job.
//
// Parameters:
//   - jobID: string job identifier previously returned; must be non-empty.
//
// Returns *IdsecSCAJobStatusResponse describing the job state or error when:
//   - jobID empty
//   - network call fails
//   - response status not 200
//   - decoding fails
func (s *IdsecSCADiscoveryService) jobStatus(jobID string) (*discoverymodels.IdsecSCAJobStatusResponse, error) {
	if jobID == "" {
		return nil, fmt.Errorf("jobID cannot be empty")
	}
	params := map[string]string{"jobId": jobID}
	s.Logger.Info("Polling SCA job status for job [%s]", jobID)
	resp, err := s.ISPClient().Get(context.Background(), jobStatusURL, params)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get job status - [%d] - [%s]", resp.StatusCode, common.SerializeResponseToJSON(resp.Body))
	}
	decoded, err := common.DeserializeJSONSnake(resp.Body)
	if err != nil {
		return nil, err
	}
	var statusResp discoverymodels.IdsecSCAJobStatusResponse
	if err = mapstructure.Decode(decoded, &statusResp); err != nil {
		return nil, err
	}
	return &statusResp, nil
}

// singleJobProbe performs one status retrieval and interprets terminal states.
// Returns status response, finished flag, and error (including failure state).
func (s *IdsecSCADiscoveryService) singleJobProbe(ctx context.Context, jobID string) (*discoverymodels.IdsecSCAJobStatusResponse, bool, error) {
	statusResp, err := s.jobStatus(jobID)
	if err != nil {
		return nil, false, fmt.Errorf("error while getting job status request: %v", err)
	}
	if statusResp == nil {
		return nil, false, fmt.Errorf("nil status response")
	}
	if s.Logger != nil {
		s.Logger.Info("Job Status [%s]", statusResp.Status)
	}
	ls := strings.ToLower(statusResp.Status)
	switch ls {
	case "success":
		return statusResp, true, nil
	case "failure":
		return nil, false, fmt.Errorf("job status is Failure: %+v", statusResp)
	}
	return statusResp, false, nil
}

// waitInterval sleeps for the polling interval or returns if context canceled.
func (s *IdsecSCADiscoveryService) waitInterval(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("polling canceled: %v", ctx.Err())
	case <-time.After(d):
		return nil
	}
}

// pollJob executes the polling loop with a fixed attempt cap, preserving original semantics.
func (s *IdsecSCADiscoveryService) pollJob(ctx context.Context, jobID string) (bool, *discoverymodels.IdsecSCAJobStatusResponse, error) {
	var lastStatus *discoverymodels.IdsecSCAJobStatusResponse
	for attempt := 0; attempt <= 40; attempt++ {
		if ctx != nil && ctx.Err() != nil {
			return false, nil, fmt.Errorf("polling canceled: %v", ctx.Err())
		}
		statusResp, finished, probeErr := s.singleJobProbe(ctx, jobID)
		if probeErr != nil {
			return false, nil, probeErr
		}
		lastStatus = statusResp
		if finished {
			return true, statusResp, nil
		}
		if attempt == 40 { // exhausted attempts
			break
		}
		if err := s.waitInterval(ctx, 20*time.Second); err != nil {
			return false, nil, err
		}
	}
	if lastStatus != nil {
		return false, nil, fmt.Errorf("time out for checking job status. Last status was: %+v", lastStatus)
	}
	return false, nil, fmt.Errorf("time out for checking job status; no status responses received")
}

// checkIfJobFinished polls the job status until it reaches a terminal state or times out.
func (s *IdsecSCADiscoveryService) checkIfJobFinished(ctx context.Context, jobID string) (bool, *discoverymodels.IdsecSCAJobStatusResponse, error) { //nolint:revive
	if jobID == "" {
		return false, nil, fmt.Errorf("jobID cannot be empty")
	}
	return s.pollJob(ctx, jobID)
}

// Discovery starts a discovery job and waits for completion, returning the initial discovery response.
//
// Parameters:
//   - req: *discoverymodels.IdsecSCADiscoveryRequest containing CSP, OrganizationID and AccountInfo.ID; must be non-nil.
//
// Returns:
//   - *discoverymodels.IdsecSCADiscoveryResponse: The initial discovery response (contains JobID and AlreadyRunning).
//   - error: When validation fails, the service is uninitialized, the discovery start fails,
//     polling fails, times out, or finishes unsuccessfully.
//
// Supported CSP values (case-insensitive): AWS, AZURE, GCP.
//
// Example:
//
//	resp, err := svc.Discovery(&discoverymodels.IdsecSCADiscoveryRequest{CSP:"aws", OrganizationID:"org", AccountInfo: discoverymodels.IdsecSCADiscoveryAccountInfo{ID:"acct"}})
//	if err != nil { /* handle */ }
//	fmt.Println("Discovery Job ID:", resp.JobID)
func (s *IdsecSCADiscoveryService) Discovery(req *discoverymodels.IdsecSCADiscoveryRequest) (*discoverymodels.IdsecSCADiscoveryResponse, error) { //nolint:revive
	if req == nil {
		return nil, fmt.Errorf("discovery request cannot be nil")
	}
	if req.CSP == "" {
		return nil, fmt.Errorf("csp cannot be empty")
	}
	supported := map[string]struct{}{"AWS": {}, "AZURE": {}, "GCP": {}}
	if _, ok := supported[strings.ToUpper(req.CSP)]; !ok {
		return nil, fmt.Errorf("unsupported csp '%s'", req.CSP)
	}
	if req.OrganizationID == "" {
		return nil, fmt.Errorf("organization_id cannot be empty")
	}
	if req.AccountInfo.ID == "" {
		return nil, fmt.Errorf("account_info.id cannot be empty")
	}
	if s == nil || s.IdsecISPBaseService == nil || s.ISPClient() == nil {
		return nil, fmt.Errorf("sca discovery service not initialized")
	}
	s.Logger.Info("Start SCA Discovery [%s]", req.AccountInfo.ID)
	discResp, err := s.discoveryRequest(req)
	if err != nil {
		return nil, err
	}
	s.Logger.Info("Check if Discovery finished [%s]", discResp.JobID)
	finished, _, err := s.checkIfJobFinished(context.Background(), discResp.JobID)
	if err != nil {
		return nil, err
	}
	if !finished {
		return nil, fmt.Errorf("discovery job did not finish successfully")
	}
	return discResp, nil
}

// ServiceConfig returns the service configuration (implements services.IdsecService).
func (s *IdsecSCADiscoveryService) ServiceConfig() services.IdsecServiceConfig { //nolint:revive
	return ServiceConfig
}
