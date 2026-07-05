package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
	scamodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models"
)

const (
	eligibilityRelURL = "/access/<csp>/eligibility/clusters"

	// evaluateRelURL is the relative URL for evaluating cluster eligibility (contains <csp> placeholder).
	evaluateRelURL = "/access/<csp>/eligibility/clusters/evaluate"

	// elevateRelURL is the relative URL for the Elevate API (relative to the api/ base path).
	elevateRelURL = "access/elevate/clusters"

	// generateKubeconfigDpaRelURL is the per-CSP DPA generate-kubeconfig endpoint
	// (relative to https://<tenant>.dpa.<env>/api/). The CSP name (uppercase) is appended at call time:
	// e.g. "k8s/kube-config/AWS".
	generateKubeconfigDpaRelURL = "k8s/kube-config"

	// acquireDpaSsoTokenURL is the path relative to the DPA /api/ base for short-lived client certificate issuance.
	acquireDpaSsoTokenURL = "adb/sso/acquire" // #nosec G101

	// dpaK8sProxyService is the service identifier sent in the DPA SSO acquire request body.
	dpaK8sProxyService = "DPA-K8S"
)

// SupportedCSPs defines the cloud providers currently supported for kubeconfig generation.
var SupportedCSPs = []string{
	strings.ToLower(k8smodels.CSPAWS),
	strings.ToLower(k8smodels.CSPAzure),
}

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

	// dpaISP is a secondary ISP base service bound to the "dpa" subdomain
	// (https://<tenant>.dpa.<env>/api/). Used by both the generate-kubeconfig
	// endpoint and the DPA SSO acquire endpoint (adb/sso/acquire).
	dpaISP *services.IdsecISPBaseService
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

	// DPA base URL: https://<tenant>.dpa.<platformdomain>/api/
	// Used only by the new per-CSP generate-kubeconfig endpoint.
	dpaISPBaseService, err := services.NewIdsecISPBaseService(ispAuth, "dpa", ".", "api", scak8sservice.refreshScaAuth)
	if err != nil {
		return nil, err
	}

	scak8sservice.IdsecBaseService = base
	scak8sservice.IdsecISPBaseService = ispBaseService
	scak8sservice.dpaISP = dpaISPBaseService
	return scak8sservice, nil
}

// refreshScaAuth refreshes the underlying ISP client authentication.
func (s *IdsecSCAK8sService) refreshScaAuth(client *common.IdsecClient) error {
	return isp.RefreshClient(client, s.ISPAuth())
}

// ListTargets lists clusters eligible for SCA discovery via the eligibility API.
// req accepts optional CSP (aws/azure, any case); when omitted, AWS and AZURE are queried.
// workspaceId, limit (1-50), and nextToken are optional.
func (s *IdsecSCAK8sService) ListTargets(req *k8smodels.IdsecSCAk8sListClustersRequest) (*k8smodels.IdsecSCAk8sListClustersResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("list targets request cannot be nil")
	}
	if req.Limit != 0 && (req.Limit < 1 || req.Limit > 50) {
		return nil, fmt.Errorf("limit must be between 1 and 50, got %d", req.Limit)
	}

	csp := strings.TrimSpace(req.CSP)
	cspLower := strings.ToLower(csp)
	supported := map[string]struct{}{
		strings.ToLower(k8smodels.CSPAWS):   {},
		strings.ToLower(k8smodels.CSPAzure): {},
	}
	if cspLower != "" {
		if _, ok := supported[cspLower]; !ok {
			return nil, fmt.Errorf("unsupported csp '%s'", csp)
		}
	}
	if req.All && cspLower != "" {
		return nil, fmt.Errorf("choose either csp or all, not both")
	}
	if s == nil || s.IdsecISPBaseService == nil || s.ISPClient() == nil {
		return nil, fmt.Errorf("sca k8s service not initialized")
	}
	if req.All || cspLower == "" {
		return s.ListTargetsAllCSPs(req)
	}
	return s.listAllTargetsForCSP(req, strings.ToUpper(csp))
}

func (s *IdsecSCAK8sService) ListTargetsAllCSPs(req *k8smodels.IdsecSCAk8sListClustersRequest) (*k8smodels.IdsecSCAk8sListClustersResponse, error) {
	combined := &k8smodels.IdsecSCAk8sListClustersResponse{}

	for _, csp := range scamodels.ValidListTargetsCSPs {
		resp, err := s.listAllTargetsForCSP(req, csp)
		if err != nil {
			if combined.Errors == nil {
				combined.Errors = scamodels.IdsecSCAListTargetsErrors{}
			}
			combined.Errors[strings.ToLower(csp)] = "API call failed: " + err.Error()
			s.Logger.Debug("list-targets for CSP [%s] failed: %v", csp, err)
			continue
		}
		if combined.Responses == nil {
			combined.Responses = map[string]k8smodels.IdsecSCAk8sListClustersResponse{}
		}
		combined.Responses[strings.ToLower(csp)] = *resp
		combined.Total += resp.Total
	}

	return combined, nil
}

func (s *IdsecSCAK8sService) listAllTargetsForCSP(req *k8smodels.IdsecSCAk8sListClustersRequest, cspUpper string) (*k8smodels.IdsecSCAk8sListClustersResponse, error) {
	all := &k8smodels.IdsecSCAk8sListClustersResponse{}
	nextToken := req.NextToken
	totalSet := false

	for {
		pageReq := *req
		pageReq.NextToken = nextToken

		resp, err := s.listTargetsForCSP(&pageReq, cspUpper)
		if err != nil {
			return nil, err
		}
		all.Response = append(all.Response, resp.Response...)
		if !totalSet {
			all.Total = resp.Total
			totalSet = true
		}

		nextToken = ""
		if resp.NextToken != nil {
			nextToken = strings.TrimSpace(*resp.NextToken)
		}
		if nextToken == "" {
			if all.Total == 0 {
				all.Total = len(all.Response)
			}
			return all, nil
		}
	}
}

func (s *IdsecSCAK8sService) listTargetsForCSP(req *k8smodels.IdsecSCAk8sListClustersRequest, cspUpper string) (*k8smodels.IdsecSCAk8sListClustersResponse, error) {
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

// EvaluateEligibility calls the internal eligibility evaluation API to determine
// which connection method (direct or proxy) should be used for each target cluster.
//
// Parameters:
//   - req: *IdsecSCAK8sEvaluateRequest with at least one target. Each target must
//     provide either FQDN or Name.
//   - csp: Cloud service provider (AWS, AZURE). Case-insensitive.
//
// Returns *IdsecSCAK8sEvaluateResponse on success or an error when:
//   - req is nil, csp is empty, or targets have neither FQDN nor Name
//   - the network call fails or the response status is not 200
//   - JSON decoding fails
func (s *IdsecSCAK8sService) EvaluateEligibility(req *k8smodels.IdsecSCAK8sEvaluateRequest, csp string) (*k8smodels.IdsecSCAK8sEvaluateResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("evaluate request cannot be nil")
	}
	csp = strings.TrimSpace(csp)
	if csp == "" {
		return nil, fmt.Errorf("csp cannot be empty")
	}
	supported := map[string]struct{}{
		strings.ToLower(k8smodels.CSPAWS):   {},
		strings.ToLower(k8smodels.CSPAzure): {},
	}
	if _, ok := supported[strings.ToLower(csp)]; !ok {
		return nil, fmt.Errorf("unsupported csp '%s'", csp)
	}
	for i, target := range req.Targets {
		if strings.TrimSpace(target.FQDN) == "" && strings.TrimSpace(target.Name) == "" {
			return nil, fmt.Errorf("target[%d] must specify either fqdn or name", i)
		}
	}
	if s == nil || s.IdsecISPBaseService == nil || s.ISPClient() == nil {
		return nil, fmt.Errorf("sca k8s service not initialized")
	}

	cspUpper := strings.ToUpper(csp)
	s.Logger.Debug("calling evaluate eligibility API for CSP=%s targets=%d", cspUpper, len(req.Targets))

	route := strings.TrimPrefix(strings.Replace(evaluateRelURL, "<csp>", cspUpper, 1), "/")

	response, err := s.ISPClient().Post(context.Background(), route, req)
	if err != nil {
		return nil, fmt.Errorf("evaluate eligibility API call failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(response.Body)
		return nil, fmt.Errorf(
			"evaluate eligibility API returned status %d. Response body: %s",
			response.StatusCode, string(bodyBytes),
		)
	}

	var result k8smodels.IdsecSCAK8sEvaluateResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode evaluate eligibility response: %w", err)
	}

	for i, r := range result.Response {
		fqdn := "<nil>"
		if r.Target.FQDN != nil {
			fqdn = *r.Target.FQDN
		}
		s.Logger.Debug("evaluate result[%d]: connectionMethod=%s fqdn=%s", i, r.ConnectionMethod, fqdn)
	}

	return &result, nil
}

// Elevate calls the SCA Elevate API to obtain short-lived cloud credentials for
// the requested cluster/role target.
//
// Parameters:
//   - req: *IdsecSCAK8sElevateKubectlRequest with CSP, FQDN, and RoleID (all required).
//     OrganizationID and NamespaceID are forwarded when set.
//
// Returns *IdsecSCAK8sElevateResponse on success or an error when:
//   - req is nil, CSP is empty, or required target fields are missing
//   - the network call fails or the response status is not 200
//   - JSON decoding fails
func (s *IdsecSCAK8sService) Elevate(req *k8smodels.IdsecSCAK8sElevateKubectlRequest) (*k8smodels.IdsecSCAK8sElevateResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("elevate request cannot be nil")
	}

	// CSP is accepted in any case from the caller and always uppercased before
	// being sent on the wire / matched in downstream logic.
	cspUpper := strings.ToUpper(strings.TrimSpace(req.CSP))
	if cspUpper == "" {
		return nil, fmt.Errorf("csp cannot be empty")
	}
	if strings.TrimSpace(req.FQDN) == "" {
		return nil, fmt.Errorf("fqdn cannot be empty")
	}
	if strings.TrimSpace(req.RoleID) == "" {
		return nil, fmt.Errorf("roleId cannot be empty")
	}
	if s == nil || s.IdsecISPBaseService == nil || s.ISPClient() == nil {
		return nil, fmt.Errorf("sca k8s service not initialized")
	}
	s.Logger.Debug("calling elevate API for CSP=%s", cspUpper)

	apiReq := &k8smodels.IdsecSCAK8sElevateRequest{
		CSP: cspUpper,
		Targets: []k8smodels.IdsecSCAK8sElevateTarget{
			{
				RoleID:      req.RoleID,
				FQDN:        req.FQDN,
				NamespaceID: req.NamespaceID,
			},
		},
		OrganizationID: req.OrganizationID,
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

// GenerateProxyExecCredential returns a kubectl ExecCredential for the proxy
// connection method, dispatching to the CSP-specific proxy provider.
//
// Parameters:
//   - csp: Cloud service provider (AWS, AZURE). Case-insensitive.
//   - ctx: Optional cluster context (CSP, FQDN, role identifiers, region, etc.)
//     for providers that need cluster-specific inputs. May be nil for CSPs that
//     do not need it (currently AWS).
//
// Returns an error when the service is not initialized, when the CSP is not
// supported, or when the underlying provider fails.
func (s *IdsecSCAK8sService) GenerateProxyExecCredential(
	csp string,
	ctx *IdsecSCAK8sClusterContext,
) (*k8smodels.IdsecSCAK8sExecCredential, error) {
	if s == nil || s.IdsecISPBaseService == nil || s.ISPClient() == nil {
		return nil, fmt.Errorf("sca k8s service not initialized")
	}
	provider, err := GetProxyProvider(csp)
	if err != nil {
		return nil, err
	}
	s.Logger.Debug("dispatching proxy ExecCredential generation to provider CSP=%s", provider.CSP())
	return provider.GenerateExecCredential(s, ctx)
}

// generateDPAProxyExecCredential issues a kubectl ExecCredential containing a
// short-lived client certificate/key pair via POST https://<tenant>.dpa.<env>/api/adb/sso/acquire
// (DPA-K8S). Shared by AWS and Azure proxy providers.
// jweExtensionValue is forwarded as jwe_extension_value when non-empty (Azure AKS token).
func (s *IdsecSCAK8sService) generateDPAProxyExecCredential(jweExtensionValue string) (*k8smodels.IdsecSCAK8sExecCredential, error) {
	jweSet := strings.TrimSpace(jweExtensionValue) != ""
	s.Logger.Debug("generateDPAProxyExecCredential: POST %s service=%s jwe_extension_value_set=%v",
		acquireDpaSsoTokenURL, dpaK8sProxyService, jweSet)

	if s.dpaISP == nil || s.dpaISP.ISPClient() == nil {
		return nil, fmt.Errorf("proxy client certificate generation failed: dpa client not initialized")
	}

	body := map[string]interface{}{
		"token_type": "client_certificate",
		"service":    dpaK8sProxyService,
	}
	if jweSet {
		body["jwe_extension_value"] = jweExtensionValue
	}

	response, err := s.dpaISP.ISPClient().Post(context.Background(), acquireDpaSsoTokenURL, body)
	if err != nil {
		return nil, fmt.Errorf("proxy client certificate generation failed: %w", err)
	}
	defer func(Body io.ReadCloser) {
		if closeErr := Body.Close(); closeErr != nil {
			s.Logger.Warning("Error closing DPA SSO response body")
		}
	}(response.Body)

	if response.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("proxy client certificate generation failed: [%d] %s",
			response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}

	var result k8smodels.IdsecSCAK8sDpaSsoAcquireResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("proxy client certificate generation failed: decode error: %w", err)
	}

	certPEM := strings.TrimSpace(result.Token.ClientCertificate)
	keyPEM := strings.TrimSpace(result.Token.PrivateKey)
	if certPEM == "" || keyPEM == "" {
		return nil, fmt.Errorf("proxy client certificate generation failed: response missing client_certificate or private_key")
	}

	expiresAt, err := parseDpaSsoExpiresAt(&result.Metadata)
	if err != nil {
		return nil, fmt.Errorf("proxy client certificate generation failed: %w", err)
	}

	s.Logger.Info("generateDPAProxyExecCredential: cert=%d bytes key=%d bytes expires_at=%s — building ExecCredential",
		len(certPEM), len(keyPEM), expiresAt.UTC().Format(time.RFC3339))

	// Bake the early-refresh buffer into status.expirationTimestamp here, the one
	// place that knows the raw DPA expiry; downstream (kubectl cache, replay) treats
	// the value as final and applies no further arithmetic.
	return BuildProxyExecCredential(certPEM, keyPEM, expiresAt.Add(-proxyExecCredRefreshBuffer)), nil
}

// GenerateKubeconfig calls the DPA generate-kubeconfig endpoint:
// https://<tenant>.dpa.<env>/api/k8s/kube-config[/<CSP>].
// The response is normalized to map[csp]yaml.
func (s *IdsecSCAK8sService) GenerateKubeconfig(req *k8smodels.IdsecSCAK8sGenerateKubeconfigRequest) (k8smodels.IdsecSCAK8sGenerateKubeconfigResponse, error) {
	if s == nil || s.IdsecISPBaseService == nil || s.ISPClient() == nil {
		return nil, fmt.Errorf("sca k8s service not initialized")
	}
	return s.generateKubeconfigViaDpa(req)
}

// GenerateKubeconfigParallel fetches kubeconfigs for multiple CSPs concurrently.
// It continues on individual failures and aggregates all results into a response
// that separates successes from failures for partial success handling.
//
// Parameters:
//   - ctx: Context for cancellation; if cancelled, in-flight requests may still complete
//     but no new requests will be started.
//   - csps: List of CSP names (aws, azure) to generate kubeconfigs for.
//   - kubeconfigLocation: Optional custom file path (passed through to each request).
//
// Returns *IdsecSCAK8sGenerateKubeconfigParallelResponse with Succeeded and Failed slices.
// The response is never nil; check HasFailures() to determine if any generations failed.
func (s *IdsecSCAK8sService) GenerateKubeconfigParallel(
	ctx context.Context,
	csps []string,
	kubeconfigLocation string,
) *k8smodels.IdsecSCAK8sGenerateKubeconfigParallelResponse {
	if s == nil || s.IdsecISPBaseService == nil || s.ISPClient() == nil {
		response := &k8smodels.IdsecSCAK8sGenerateKubeconfigParallelResponse{}
		for _, csp := range csps {
			response.Failed = append(response.Failed, k8smodels.IdsecSCAK8sKubeconfigOutcome{
				CSP:   strings.ToLower(csp),
				Error: "sca k8s service not initialized",
			})
		}
		return response
	}

	if len(csps) == 0 {
		return &k8smodels.IdsecSCAK8sGenerateKubeconfigParallelResponse{}
	}

	s.Logger.Info("Generating kubeconfigs in parallel for CSPs: %v", csps)

	resultCh := make(chan k8smodels.IdsecSCAK8sKubeconfigOutcome, len(csps))
	var wg sync.WaitGroup

	for _, csp := range csps {
		wg.Add(1)
		go func(cspName string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				resultCh <- k8smodels.IdsecSCAK8sKubeconfigOutcome{
					CSP:   strings.ToLower(cspName),
					Error: ctx.Err().Error(),
				}
				return
			default:
			}

			req := &k8smodels.IdsecSCAK8sGenerateKubeconfigRequest{
				CSP:                cspName,
				All:                "false",
				KubeconfigLocation: kubeconfigLocation,
			}

			s.Logger.Debug("parallel generate-kubeconfig: starting CSP=%s", cspName)

			cspResult, err := s.GenerateKubeconfig(req)
			if err != nil {
				s.Logger.Debug("parallel generate-kubeconfig: CSP=%s failed: %v", cspName, err)
				resultCh <- k8smodels.IdsecSCAK8sKubeconfigOutcome{
					CSP:   strings.ToLower(cspName),
					Error: err.Error(),
				}
				return
			}

			kubeconfig := ""
			cspLower := strings.ToLower(cspName)
			if val, ok := cspResult[cspLower]; ok {
				kubeconfig = val
			} else if val, ok := cspResult["all"]; ok {
				kubeconfig = val
			} else if len(cspResult) == 1 {
				for _, v := range cspResult {
					kubeconfig = v
					break
				}
			}

			s.Logger.Debug("parallel generate-kubeconfig: CSP=%s succeeded (%d bytes)", cspName, len(kubeconfig))
			resultCh <- k8smodels.IdsecSCAK8sKubeconfigOutcome{
				CSP:        cspLower,
				Kubeconfig: kubeconfig,
			}
		}(csp)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	response := &k8smodels.IdsecSCAK8sGenerateKubeconfigParallelResponse{}
	for outcome := range resultCh {
		if outcome.IsSuccess() {
			response.Succeeded = append(response.Succeeded, outcome)
		} else {
			response.Failed = append(response.Failed, outcome)
		}
	}

	s.Logger.Info("Parallel kubeconfig generation complete: %d succeeded, %d failed",
		response.SuccessCount(), response.FailureCount())

	return response
}

// generateKubeconfigViaDpa implements the DPA endpoint:
//
//	GET https://<tenant>.dpa.<env>/api/k8s/kube-config           (when --all=true and --csp is empty)
//	GET https://<tenant>.dpa.<env>/api/k8s/kube-config/<CSP>     (when --csp is provided)
//
// Mirrors the legacy SCA endpoint's --csp/--all semantics: must specify --csp or have --all=true.
// The response is wrapped into the same map[csp]yaml shape used by the legacy endpoint.
func (s *IdsecSCAK8sService) generateKubeconfigViaDpa(req *k8smodels.IdsecSCAK8sGenerateKubeconfigRequest) (k8smodels.IdsecSCAK8sGenerateKubeconfigResponse, error) {
	if s.dpaISP == nil || s.dpaISP.ISPClient() == nil {
		return nil, fmt.Errorf("sca k8s service dpa client not initialized")
	}

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

	if csp == "" && allParam == "false" {
		return nil, fmt.Errorf("generate-kubeconfig: specify --csp or set --all true; --all false with no --csp is invalid")
	}

	route := generateKubeconfigDpaRelURL
	cspDisplay := "all"
	if csp != "" {
		if err := validateSupportedCSP(csp); err != nil {
			return nil, err
		}
		cspRouteSegment := dpaGenerateKubeconfigCSPSegment(csp)
		route = generateKubeconfigDpaRelURL + "/" + cspRouteSegment
		cspDisplay = cspRouteSegment
	}

	s.Logger.Info("Generating kubeconfig (dpa endpoint) for CSP [%s]", cspDisplay)
	s.Logger.Debug("requesting generate-kubeconfig DPA API at route: %s", route)

	client := s.dpaISP.ISPClient()
	client.RemoveHeader("Content-Type")
	response, err := client.Get(context.Background(), route, nil)
	client.SetHeader("Content-Type", "application/json")

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

	return s.parseGenerateKubeconfigBody(bodyBytes, csp)
}

func dpaGenerateKubeconfigCSPSegment(csp string) string {
	if csp == strings.ToLower(k8smodels.CSPAzure) {
		return "azure_resource"
	}
	return strings.ToUpper(csp)
}

// parseGenerateKubeconfigBody normalizes the response body into the shared
// IdsecSCAK8sGenerateKubeconfigResponse (map[csp]yaml) shape. Accepts a JSON map,
// a JSON-quoted YAML string, or raw YAML.
func (s *IdsecSCAK8sService) parseGenerateKubeconfigBody(bodyBytes []byte, csp string) (k8smodels.IdsecSCAK8sGenerateKubeconfigResponse, error) {
	s.Logger.Debug("generate-kubeconfig raw response length: %d bytes", len(bodyBytes))

	var mapResult k8smodels.IdsecSCAK8sGenerateKubeconfigResponse
	if err := json.Unmarshal(bodyBytes, &mapResult); err == nil && len(mapResult) > 0 {
		s.Logger.Debug("parsed generate-kubeconfig response as JSON map with %d entries", len(mapResult))
		return mapResult, nil
	}

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

// validateSupportedCSP returns an error if csp is not one of the supported lowercase CSP names.
func validateSupportedCSP(csp string) error {
	supported := map[string]struct{}{
		strings.ToLower(k8smodels.CSPAWS):   {},
		strings.ToLower(k8smodels.CSPAzure): {},
	}
	if _, ok := supported[csp]; !ok {
		return fmt.Errorf("unsupported csp '%s'; must be one of: %s, %s",
			csp, strings.ToLower(k8smodels.CSPAWS), strings.ToLower(k8smodels.CSPAzure))
	}
	return nil
}

func (s *IdsecSCAK8sService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
