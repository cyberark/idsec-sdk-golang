package k8s

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithymiddleware "github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/toqueteos/webbrowser"

	k8scommon "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/common"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

const (
	awsIDCDeviceCodeGrantType   = "urn:ietf:params:oauth:grant-type:device_code"
	awsIDCRefreshTokenGrantType = "refresh_token"

	// eksPresignDuration is the hard AWS limit for STS presigned URL validity.
	// EKS does not honour longer durations.
	eksPresignDuration = 15 * time.Minute
)

// AWS IDC OIDC / SSO portal error codes returned in the JSON "error" field of the
// token endpoint during device-authorization polling.
const (
	awsIDCErrAuthorizationPending = "authorization_pending"
	awsIDCErrSlowDown             = "slow_down"
)

// awsIDCHTTPTimeout bounds each AWS IDC OIDC / SSO portal REST call.
const awsIDCHTTPTimeout = 30 * time.Second

// awsIDCHTTPClient performs AWS IDC OIDC / SSO portal REST calls.
// It is built at startup so it picks up env-var-based SDK settings
// (IDSEC_PROXY_ADDRESS, IDSEC_EXTRA_TRUSTED_CA_CERTS_BUNDLE_PATH) that are
// present when the process starts. Tests override it to target httptest servers.
var awsIDCHTTPClient = k8scommon.K8sHTTPClient(awsIDCHTTPTimeout) //nolint:gochecknoglobals

// awsIDCOIDCEndpoint and awsIDCPortalEndpoint build the AWS IAM Identity Center
// OIDC and SSO portal base URLs for a region. They are vars so tests can point
// them at httptest servers.
//
// NOTE: these use the commercial AWS partition (amazonaws.com). GovCloud and
// China partitions use different hostnames and are not handled here; extend
// these builders if those partitions must be supported.
var (
	awsIDCOIDCEndpoint = func(region string) string {
		return fmt.Sprintf("https://oidc.%s.amazonaws.com", region)
	}
	awsIDCPortalEndpoint = func(region string) string {
		return fmt.Sprintf("https://portal.sso.%s.amazonaws.com", region)
	}
)

// awsIDCStartDeviceAuthRequest is the POST body for /device_authorization.
// JSON tags match the AWS IDC OIDC API (camelCase).
type awsIDCStartDeviceAuthRequest struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret" secret:"true"`
	StartURL     string `json:"startUrl"`
}

// awsIDCStartDeviceAuthResponse is the /device_authorization reply.
type awsIDCStartDeviceAuthResponse struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	ExpiresIn               int64  `json:"expiresIn"`
	Interval                int64  `json:"interval"`
}

// awsIDCCreateTokenRequest is the POST body for /token. It serves both the
// device_code grant (DeviceCode set) and the refresh_token grant (RefreshToken
// set); the unused field is omitted so a single struct covers both flows.
type awsIDCCreateTokenRequest struct {
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret" secret:"true"`
	DeviceCode   string `json:"deviceCode,omitempty"`
	RefreshToken string `json:"refreshToken,omitempty" secret:"true"`
	GrantType    string `json:"grantType"`
}

// awsIDCCreateTokenResponse is the /token success reply. RefreshToken is present
// only when the registered client includes the refresh_token grant type; AWS may
// also rotate it on each refresh_token grant.
type awsIDCCreateTokenResponse struct {
	AccessToken  string `json:"accessToken" secret:"true"`
	RefreshToken string `json:"refreshToken" secret:"true"`
	TokenType    string `json:"tokenType"`
	ExpiresIn    int64  `json:"expiresIn"`
}

// awsIDCErrorResponse is the JSON error body returned by the OIDC endpoints.
type awsIDCErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// awsIDCRoleCredentials mirrors the SSO portal roleCredentials object.
type awsIDCRoleCredentials struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey" secret:"true"`
	SessionToken    string `json:"sessionToken" secret:"true"`
	Expiration      int64  `json:"expiration"`
}

// awsIDCGetRoleCredentialsResponse is the /federation/credentials reply.
type awsIDCGetRoleCredentialsResponse struct {
	RoleCredentials awsIDCRoleCredentials `json:"roleCredentials" secret:"true"`
}

// AWSIDCOIDCCache stores optional callbacks for reusing a cached SSO OIDC access
// token (and refresh token) across kubectl invocations. When nil, every hydrate
// runs the device flow.
//
// LoadAccessToken returns the cached access token together with the refresh
// token. The bool reports only whether the ACCESS token is still valid; the
// refresh token is returned regardless (even when the access token is expired or
// empty) so the caller can run the refresh_token grant instead of the browser
// device flow. SaveAccessToken persists both; the refresh token may be empty when
// the registered client does not issue one.
type AWSIDCOIDCCache struct {
	LoadAccessToken func() (token, refreshToken string, expiresAt time.Time, ok bool)
	SaveAccessToken func(token, refreshToken string, expiresAt time.Time) error
}

// HydrateAWSAccessCredentialsFromElevate runs the AWS IDC device-registration flow
// when needed and writes STS credentials into result.AccessCredentials. Callers
// then pass the hydrated result to AWSTokenProvider.GenerateToken (or directly
// to GenerateEKSTokenFromAccessCredentials below) for client-side STS presigning.
func HydrateAWSAccessCredentialsFromElevate(
	result *k8smodels.IdsecSCAK8sElevateResult,
	diagnostics bool,
	oidcCache *AWSIDCOIDCCache,
) error {
	if result == nil {
		return fmt.Errorf("elevate result cannot be nil")
	}
	if !IsAWSIDCPermissionSetRole(result.RoleID) {
		return nil
	}
	if err := ValidateAWSIDCDeviceRegistration(result); err != nil {
		return err
	}
	if strings.TrimSpace(result.AccessCredentials) != "" {
		return nil
	}

	creds, accessToken, refreshToken, accessTokenExp, err := EnsureAWSIDCAccessCredentials(result, diagnostics, oidcCache)

	// Never let the cached OIDC token outlive the SCA elevation session: cap its
	// expiry at the Elevate sessionExpTime so a refresh_token grant can never mint
	// AWS credentials beyond the window CyberArk granted. Once past that point the
	// token reads as expired and the caller re-runs Elevate before any AWS call.
	accessTokenExp = capExpiryToElevateSession(accessTokenExp, result.SessionExpTime)

	// Cache the OIDC access token (and refresh token) whenever one was acquired,
	// even if the subsequent GetRoleCredentials call failed. This ensures retries
	// skip device authorization and fail fast at GetRoleCredentials instead of
	// triggering the browser-based device flow on every kubectl retry.
	if oidcCache != nil && oidcCache.SaveAccessToken != nil && strings.TrimSpace(accessToken) != "" {
		if saveErr := oidcCache.SaveAccessToken(accessToken, refreshToken, accessTokenExp); saveErr != nil && diagnostics {
			KubectlLoginLog(KubectlLoginLogLevelInfo, "failed to cache AWS IDC OIDC access token: %v", saveErr)
		}
	}

	if err != nil {
		return err
	}
	encoded, err := MarshalAWSAccessCredentials(creds)
	if err != nil {
		return err
	}
	result.AccessCredentials = encoded
	return nil
}

// GenerateEKSTokenFromAccessCredentials builds an EKS bearer token by presigning
// a GetCallerIdentity STS request from the STS credentials in
// result.AccessCredentials (populated by HydrateAWSAccessCredentialsFromElevate
// above). This is the AWS IDC permission-set half of AWSTokenProvider.GenerateToken
// (idsec_sca_k8s_aws_token.go), which calls this function as its fallback when
// result.EKSToken is empty; it is also exported for callers that need the raw
// presigned token outside the ExecCredential provider path (e.g. embedding it
// in a proxy JWE payload). ctx.Region and ctx.ClusterID must be populated.
func GenerateEKSTokenFromAccessCredentials(
	result *k8smodels.IdsecSCAK8sElevateResult,
	ctx *IdsecSCAK8sClusterContext,
) (*k8smodels.IdsecSCAK8sExecCredential, error) {
	if result == nil {
		return nil, fmt.Errorf("elevate result cannot be nil")
	}
	if ctx == nil {
		return nil, fmt.Errorf("cluster context cannot be nil")
	}
	if strings.TrimSpace(result.AccessCredentials) == "" {
		return nil, fmt.Errorf("accessCredentials is empty for AWS IDC flow")
	}
	var awsCreds k8smodels.IdsecSCAK8sAWSAccessCredentials
	if err := json.Unmarshal([]byte(result.AccessCredentials), &awsCreds); err != nil {
		return nil, fmt.Errorf("failed to parse AWS access credentials: %w", err)
	}
	if awsCreds.AWSAccessKey == "" || awsCreds.AWSSecretAccessKey == "" {
		return nil, fmt.Errorf("AWS access key or secret key is missing in access credentials")
	}

	cfg := aws.Config{
		Region: ctx.Region,
		Credentials: credentials.NewStaticCredentialsProvider(
			awsCreds.AWSAccessKey,
			awsCreds.AWSSecretAccessKey,
			awsCreds.AWSSessionToken,
		),
	}
	presignClient := sts.NewPresignClient(sts.NewFromConfig(cfg))

	clusterID := ctx.ClusterID
	// Capture issuance time before the call so the stamped expirationTimestamp
	// is conservative even if the network call takes a few hundred ms.
	presignedAt := time.Now()
	presignedReq, err := presignClient.PresignGetCallerIdentity(
		context.Background(),
		&sts.GetCallerIdentityInput{},
		func(o *sts.PresignOptions) {
			o.ClientOptions = append(o.ClientOptions, func(opts *sts.Options) {
				opts.APIOptions = append(opts.APIOptions, func(stack *smithymiddleware.Stack) error {
					return stack.Build.Add(
						&eksPresignMiddleware{clusterID: clusterID, expires: eksPresignDuration},
						smithymiddleware.After,
					)
				})
			})
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to presign STS GetCallerIdentity: %w", err)
	}

	token := eksTokenPrefix + base64.RawURLEncoding.EncodeToString([]byte(presignedReq.URL))
	expiresAt := presignedAt.Add(eksPresignDuration).Add(-eksExecCredRefreshBuffer).UTC()
	return &k8smodels.IdsecSCAK8sExecCredential{
		APIVersion: eksExecCredAPIVersion,
		Kind:       "ExecCredential",
		Status: k8smodels.IdsecSCAK8sExecCredentialStatus{
			Token:               token,
			ExpirationTimestamp: expiresAt.Format(time.RFC3339),
		},
	}, nil
}

// eksPresignMiddleware is a Build-phase middleware that injects the
// x-k8s-aws-id header and X-Amz-Expires query parameter required by EKS.
// Both must be present before SigV4 signing (Finalize phase) so they are
// included in the computed signature.
type eksPresignMiddleware struct {
	clusterID string
	expires   time.Duration
}

func (m *eksPresignMiddleware) ID() string { return "EKSPresignHeaderAndExpiry" }

func (m *eksPresignMiddleware) HandleBuild(
	bCtx context.Context,
	in smithymiddleware.BuildInput,
	next smithymiddleware.BuildHandler,
) (smithymiddleware.BuildOutput, smithymiddleware.Metadata, error) {
	if req, ok := in.Request.(*smithyhttp.Request); ok {
		req.Header.Set("x-k8s-aws-id", m.clusterID)
		q := req.URL.Query()
		q.Set("X-Amz-Expires", strconv.FormatInt(int64(m.expires/time.Second), 10))
		req.URL.RawQuery = q.Encode()
	}
	return next.HandleBuild(bCtx, in)
}

// EnsureAWSIDCAccessCredentials obtains temporary AWS STS credentials for an IDC
// permission set via SSO OIDC device authorization and GetRoleCredentials.
func EnsureAWSIDCAccessCredentials(
	result *k8smodels.IdsecSCAK8sElevateResult,
	diagnostics bool,
	oidcCache *AWSIDCOIDCCache,
) (*k8smodels.IdsecSCAK8sAWSAccessCredentials, string, string, time.Time, error) {
	if err := ValidateAWSIDCDeviceRegistration(result); err != nil {
		return nil, "", "", time.Time{}, err
	}
	if !IsAWSIDCPermissionSetRole(result.RoleID) {
		return nil, "", "", time.Time{}, fmt.Errorf("elevate result does not require AWS IDC device registration")
	}

	cd := result.ClientDetails
	ssoRegion := awsIDCRegion(cd)

	ctx := context.Background()
	accessToken, refreshToken, accessTokenExp, err := resolveAWSIDCOIDCAccessToken(ctx, ssoRegion, cd, diagnostics, oidcCache)
	if err != nil {
		return nil, "", "", time.Time{}, err
	}

	roleCreds, err := getAWSIDCRoleCredentials(
		ctx,
		ssoRegion,
		accessToken,
		strings.TrimSpace(result.WorkspaceID),
		strings.TrimSpace(result.RoleName),
	)
	if err != nil {
		// Return the tokens even on failure so the caller can cache them.
		// This prevents re-triggering device authorization on subsequent retries
		// when GetRoleCredentials fails (e.g. 403 ForbiddenException).
		return nil, accessToken, refreshToken, accessTokenExp, fmt.Errorf("AWS SSO GetRoleCredentials failed: %w", err)
	}
	if strings.TrimSpace(roleCreds.AccessKeyID) == "" || strings.TrimSpace(roleCreds.SecretAccessKey) == "" {
		return nil, "", "", time.Time{}, fmt.Errorf("AWS SSO GetRoleCredentials returned incomplete credentials")
	}

	return &k8smodels.IdsecSCAK8sAWSAccessCredentials{
		AWSAccessKey:       roleCreds.AccessKeyID,
		AWSSecretAccessKey: roleCreds.SecretAccessKey,
		AWSSessionToken:    roleCreds.SessionToken,
	}, accessToken, refreshToken, accessTokenExp, nil
}

// resolveAWSIDCOIDCAccessToken returns an OIDC access token using the cheapest
// available path, in priority order:
//  1. A still-valid cached access token (no network call).
//  2. The refresh_token grant, when the cache holds a refresh token but the
//     access token is missing/expired (one non-interactive HTTP call).
//  3. The browser-based device authorization flow (last resort).
//
// It also returns the (possibly rotated) refresh token so the caller can persist
// it. Overhead in the common case is zero: step 2 fires only when the access
// token is actually expired, and it replaces the far heavier interactive flow.
func resolveAWSIDCOIDCAccessToken(
	ctx context.Context,
	region string,
	cd *k8smodels.IdsecSCAK8sElevateClientDetails,
	diagnostics bool,
	oidcCache *AWSIDCOIDCCache,
) (accessToken, refreshToken string, expiresAt time.Time, err error) {
	var cachedRefresh string
	if oidcCache != nil && oidcCache.LoadAccessToken != nil {
		token, refresh, exp, ok := oidcCache.LoadAccessToken()
		cachedRefresh = strings.TrimSpace(refresh)

		// 1. Cached access token still valid → reuse it, no network call.
		if ok && strings.TrimSpace(token) != "" {
			if diagnostics {
				KubectlLoginLog(KubectlLoginLogLevelInfo, "reusing cached AWS IDC OIDC access token (expires %s)", exp.Format(time.RFC3339))
			}
			return token, cachedRefresh, exp, nil
		}

		// 2. Access token missing/expired but a refresh token is cached →
		//    refresh_token grant instead of the browser device flow.
		if cachedRefresh != "" {
			out, refreshErr := refreshAWSIDCToken(ctx, region, cd, cachedRefresh)
			if refreshErr == nil {
				newExp := time.Now().Add(time.Hour)
				if out.ExpiresIn > 0 {
					newExp = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
				}
				// AWS may rotate the refresh token; keep the previous one if the
				// response omits it.
				newRefresh := cachedRefresh
				if trimmed := strings.TrimSpace(out.RefreshToken); trimmed != "" {
					newRefresh = trimmed
				}
				if diagnostics {
					KubectlLoginLog(KubectlLoginLogLevelInfo, "refreshed AWS IDC OIDC access token via refresh_token grant (expires %s)", newExp.Format(time.RFC3339))
				}
				return out.AccessToken, newRefresh, newExp, nil
			}
			if diagnostics {
				KubectlLoginLog(KubectlLoginLogLevelInfo, "refresh_token grant failed, falling back to device authorization: %v", refreshErr)
			}
		}
	}

	// 3. No usable access or refresh token → interactive device authorization.
	return acquireAWSIDCOIDCAccessToken(ctx, region, cd, diagnostics)
}

// refreshAWSIDCToken exchanges a refresh token for a fresh access token via the
// refresh_token grant, avoiding the interactive device-authorization flow.
func refreshAWSIDCToken(
	ctx context.Context,
	region string,
	cd *k8smodels.IdsecSCAK8sElevateClientDetails,
	refreshToken string,
) (*awsIDCCreateTokenResponse, error) {
	reqBody := awsIDCCreateTokenRequest{
		ClientID:     strings.TrimSpace(cd.ClientID),
		ClientSecret: strings.TrimSpace(cd.ClientSecret),
		RefreshToken: strings.TrimSpace(refreshToken),
		GrantType:    awsIDCRefreshTokenGrantType,
	}
	endpoint := awsIDCOIDCEndpoint(region) + "/token"

	var out awsIDCCreateTokenResponse
	if _, err := doAWSIDCJSONRequest(ctx, http.MethodPost, endpoint, nil, reqBody, &out); err != nil {
		return nil, fmt.Errorf("AWS SSO OIDC refresh_token grant failed: %w", err)
	}
	if strings.TrimSpace(out.AccessToken) == "" {
		return nil, fmt.Errorf("AWS SSO OIDC refresh_token grant returned empty access token")
	}
	return &out, nil
}

// capExpiryToElevateSession returns the earlier of tokenExp and the parsed
// Elevate sessionExpTime. A missing/unparseable sessionExpTime leaves tokenExp
// unchanged (the ExecCredential TTL min still bounds served credentials).
func capExpiryToElevateSession(tokenExp time.Time, sessionExpTime string) time.Time {
	sessionExp, err := parseAWSIDCSessionExpTime(sessionExpTime)
	if err != nil {
		return tokenExp
	}
	if tokenExp.IsZero() || sessionExp.Before(tokenExp) {
		return sessionExp
	}
	return tokenExp
}

// parseAWSIDCSessionExpTime parses the Elevate sessionExpTime, accepting the
// RFC3339 variants and the zone-less fractional-second form seen in production.
func parseAWSIDCSessionExpTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, fmt.Errorf("empty sessionExpTime")
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC(), nil
		}
	}
	for _, layout := range []string{
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05",
	} {
		if t, err := time.ParseInLocation(layout, raw, time.UTC); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized sessionExpTime format %q", raw)
}

func acquireAWSIDCOIDCAccessToken(
	ctx context.Context,
	region string,
	cd *k8smodels.IdsecSCAK8sElevateClientDetails,
	diagnostics bool,
) (accessToken, refreshToken string, expiresAt time.Time, err error) {
	startOut, err := startAWSIDCDeviceAuthorization(ctx, region, cd)
	if err != nil {
		return "", "", time.Time{}, err
	}

	userCode := startOut.UserCode
	verificationURI := startOut.VerificationURIComplete
	if verificationURI == "" {
		verificationURI = startOut.VerificationURI
	}
	if diagnostics {
		KubectlLoginLog(KubectlLoginLogLevelInfo, "AWS IDC device authorization required")
	}
	fmt.Fprintf(
		os.Stderr,
		"\nAWS IAM Identity Center authorization required.\nUser code: %s\nOpen: %s\n\n",
		userCode,
		verificationURI,
	)
	if verificationURI != "" {
		_ = webbrowser.Open(verificationURI)
	}

	interval := time.Duration(startOut.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	expiresIn := time.Duration(startOut.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = 10 * time.Minute
	}
	deadline := time.Now().Add(expiresIn)

	for {
		if time.Now().After(deadline) {
			return "", "", time.Time{}, fmt.Errorf("AWS IDC device authorization timed out")
		}

		tokenOut, errCode, err := createAWSIDCToken(ctx, region, cd, startOut.DeviceCode)
		if err == nil {
			token := strings.TrimSpace(tokenOut.AccessToken)
			if token == "" {
				return "", "", time.Time{}, fmt.Errorf("AWS SSO OIDC CreateToken returned empty access token")
			}
			expiresAt := time.Now().Add(time.Hour)
			if tokenOut.ExpiresIn > 0 {
				expiresAt = time.Now().Add(time.Duration(tokenOut.ExpiresIn) * time.Second)
			}
			if diagnostics {
				KubectlLoginLog(KubectlLoginLogLevelInfo, "AWS IDC OIDC access token acquired (expires %s)", expiresAt.Format(time.RFC3339))
			}
			return token, strings.TrimSpace(tokenOut.RefreshToken), expiresAt, nil
		}

		switch errCode {
		case awsIDCErrAuthorizationPending:
			time.Sleep(interval)
			continue
		case awsIDCErrSlowDown:
			interval += 5 * time.Second
			time.Sleep(interval)
			continue
		default:
			return "", "", time.Time{}, fmt.Errorf("AWS SSO OIDC CreateToken failed: %w", err)
		}
	}
}

// startAWSIDCDeviceAuthorization calls POST /device_authorization on the OIDC endpoint.
func startAWSIDCDeviceAuthorization(
	ctx context.Context,
	region string,
	cd *k8smodels.IdsecSCAK8sElevateClientDetails,
) (*awsIDCStartDeviceAuthResponse, error) {
	reqBody := awsIDCStartDeviceAuthRequest{
		ClientID:     strings.TrimSpace(cd.ClientID),
		ClientSecret: strings.TrimSpace(cd.ClientSecret),
		StartURL:     strings.TrimSpace(cd.StartURL),
	}
	endpoint := awsIDCOIDCEndpoint(region) + "/device_authorization"

	var out awsIDCStartDeviceAuthResponse
	if _, err := doAWSIDCJSONRequest(ctx, http.MethodPost, endpoint, nil, reqBody, &out); err != nil {
		return nil, fmt.Errorf("AWS SSO OIDC StartDeviceAuthorization failed: %w", err)
	}
	return &out, nil
}

// createAWSIDCToken calls POST /token on the OIDC endpoint. On an AWS error
// response it returns the parsed "error" code (e.g. authorization_pending) so the
// caller can drive the polling loop.
func createAWSIDCToken(
	ctx context.Context,
	region string,
	cd *k8smodels.IdsecSCAK8sElevateClientDetails,
	deviceCode string,
) (*awsIDCCreateTokenResponse, string, error) {
	reqBody := awsIDCCreateTokenRequest{
		ClientID:     strings.TrimSpace(cd.ClientID),
		ClientSecret: strings.TrimSpace(cd.ClientSecret),
		DeviceCode:   deviceCode,
		GrantType:    awsIDCDeviceCodeGrantType,
	}
	endpoint := awsIDCOIDCEndpoint(region) + "/token"

	var out awsIDCCreateTokenResponse
	if _, err := doAWSIDCJSONRequest(ctx, http.MethodPost, endpoint, nil, reqBody, &out); err != nil {
		var apiErr *awsIDCAPIError
		if errors.As(err, &apiErr) {
			return nil, apiErr.Code, err
		}
		return nil, "", err
	}
	return &out, "", nil
}

// getAWSIDCRoleCredentials calls GET /federation/credentials on the SSO portal
// endpoint using the OIDC access token as the bearer token.
func getAWSIDCRoleCredentials(
	ctx context.Context,
	region, accessToken, accountID, roleName string,
) (*awsIDCRoleCredentials, error) {
	base := awsIDCPortalEndpoint(region) + "/federation/credentials"
	q := url.Values{}
	q.Set("account_id", accountID)
	q.Set("role_name", roleName)
	endpoint := base + "?" + q.Encode()

	headers := map[string]string{"x-amz-sso_bearer_token": accessToken}

	var out awsIDCGetRoleCredentialsResponse
	if _, err := doAWSIDCJSONRequest(ctx, http.MethodGet, endpoint, headers, nil, &out); err != nil {
		return nil, err
	}
	return &out.RoleCredentials, nil
}

// awsIDCAPIError carries the AWS error code parsed from a non-2xx JSON response.
type awsIDCAPIError struct {
	Code        string
	Description string
	Status      int
}

func (e *awsIDCAPIError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("AWS IDC error %q (HTTP %d): %s", e.Code, e.Status, e.Description)
	}
	if e.Code != "" {
		return fmt.Sprintf("AWS IDC error %q (HTTP %d)", e.Code, e.Status)
	}
	return fmt.Sprintf("AWS IDC request failed (HTTP %d)", e.Status)
}

// doAWSIDCJSONRequest performs a JSON request against an AWS IDC endpoint. On a
// non-2xx response it returns an *awsIDCAPIError populated from the JSON error
// body when present. reqBody may be nil for GET requests; out may be nil to skip
// response decoding.
func doAWSIDCJSONRequest(
	ctx context.Context,
	method, endpoint string,
	headers map[string]string,
	reqBody any,
	out any,
) (int, error) {
	var body io.Reader
	if reqBody != nil {
		encoded, err := json.Marshal(reqBody)
		if err != nil {
			return 0, fmt.Errorf("failed to encode request body: %w", err)
		}
		body = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return 0, fmt.Errorf("failed to build request: %w", err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := awsIDCHTTPClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &awsIDCAPIError{Status: resp.StatusCode}
		var parsed awsIDCErrorResponse
		if json.Unmarshal(respBody, &parsed) == nil {
			apiErr.Code = strings.TrimSpace(parsed.Error)
			apiErr.Description = strings.TrimSpace(parsed.ErrorDescription)
		}
		return resp.StatusCode, apiErr
	}

	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return resp.StatusCode, fmt.Errorf("failed to decode response: %w", err)
		}
	}
	return resp.StatusCode, nil
}
