package k8s

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

const (
	// eksExecCredRefreshBuffer is the early-refresh window subtracted from the
	// presigned URL expiry before stamping status.expirationTimestamp. Shared
	// with the IDC client-side presign path in idsec_sca_k8s_aws_idc.go.
	eksExecCredRefreshBuffer = 60 * time.Second

	// eksTokenPrefix is prepended to the base64url-encoded presigned URL.
	// Shared with the IDC client-side presign path.
	eksTokenPrefix = "k8s-aws-v1."

	// eksExecCredAPIVersion is the Kubernetes client-auth API version.
	// Shared with the IDC client-side presign path.
	eksExecCredAPIVersion = "client.authentication.k8s.io/v1beta1"
)

// AWSTokenProvider implements IdsecSCAK8sTokenProvider for AWS EKS IAM roles.
type AWSTokenProvider struct{}

// CSP returns the AWS CSP identifier.
func (p *AWSTokenProvider) CSP() string { return k8smodels.CSPAWS }

// GenerateToken returns an ExecCredential for EKS.
//
// Uses the server-provided eksToken when present, decoding its embedded expiry
// via ParseEKSTokenExpiry (IAM direct/proxy path — ctx is unused here since the
// server already baked region/cluster into the presigned URL). Falls back to
// GenerateEKSTokenFromAccessCredentials, which presigns a GetCallerIdentity
// request client-side from result.AccessCredentials, when eksToken is absent
// (AWS IDC permission-set path — ctx.Region/ctx.ClusterID are required here).
func (p *AWSTokenProvider) GenerateToken(
	result *k8smodels.IdsecSCAK8sElevateResult,
	ctx *IdsecSCAK8sClusterContext,
) (*k8smodels.IdsecSCAK8sExecCredential, error) {
	if result == nil {
		return nil, fmt.Errorf("elevate result cannot be nil")
	}

	// Server-side EKS token path: the Elevate API has already presigned the STS
	// request and returned a ready-to-use bearer token. Parse the exact expiry
	// from the embedded presigned URL parameters instead of approximating locally.
	if strings.TrimSpace(result.EKSToken) != "" {
		expiry, err := ParseEKSTokenExpiry(result.EKSToken)
		if err != nil {
			return nil, fmt.Errorf("failed to parse eksToken expiry: %w", err)
		}
		expiresAt := expiry.Add(-eksExecCredRefreshBuffer).UTC()
		return &k8smodels.IdsecSCAK8sExecCredential{
			APIVersion: eksExecCredAPIVersion,
			Kind:       "ExecCredential",
			Status: k8smodels.IdsecSCAK8sExecCredentialStatus{
				Token:               result.EKSToken,
				ExpirationTimestamp: expiresAt.Format(time.RFC3339),
			},
		}, nil
	}

	// IDC permission-set path: client-side presign using STS credentials
	// hydrated into result.AccessCredentials by HydrateAWSAccessCredentialsFromElevate.
	return GenerateEKSTokenFromAccessCredentials(result, ctx)
}

// ParseEKSARN extracts the AWS region and EKS cluster name from an EKS cluster ARN.
//
// Expected ARN format: arn:aws:eks:{region}:{accountId}:cluster/{clusterName}
// Example: "arn:aws:eks:us-east-1:134672441550:cluster/k8s-demo-cluster"
//
// Returns (region, clusterName, nil) on success, or ("", "", err) if the ARN
// does not match the expected format.
func ParseEKSARN(arn string) (region, clusterName string, err error) {
	// ARN parts when split by ":" are:
	//   [0]=arn  [1]=aws  [2]=eks  [3]=region  [4]=accountId  [5]=cluster/name
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "eks" {
		return "", "", fmt.Errorf("invalid EKS ARN format: %q", arn)
	}
	region = parts[3]
	if region == "" {
		return "", "", fmt.Errorf("region is empty in EKS ARN: %q", arn)
	}
	clusterPart := parts[5]
	const clusterPrefix = "cluster/"
	if !strings.HasPrefix(clusterPart, clusterPrefix) {
		return "", "", fmt.Errorf("expected 'cluster/' prefix in EKS ARN resource segment, got: %q", clusterPart)
	}
	clusterName = strings.TrimPrefix(clusterPart, clusterPrefix)
	if clusterName == "" {
		return "", "", fmt.Errorf("cluster name is empty in EKS ARN: %q", arn)
	}
	return region, clusterName, nil
}

// ParseEKSTokenExpiry extracts the exact expiration time from a server-provided
// EKS bearer token by decoding the embedded STS presigned URL.
//
// An EKS token is: k8s-aws-v1.<base64url-no-padding(presigned-URL)>
// The presigned URL contains:
//   - X-Amz-Date  — the STS request signing time  (format: 20060102T150405Z)
//   - X-Amz-Expires — token lifetime in seconds
//
// The raw expiry is signingTime + X-Amz-Expires. Callers should subtract
// eksExecCredRefreshBuffer before stamping status.expirationTimestamp.
func ParseEKSTokenExpiry(eksToken string) (time.Time, error) {
	tokenBody, ok := strings.CutPrefix(eksToken, eksTokenPrefix)
	if !ok {
		return time.Time{}, fmt.Errorf("eksToken missing required prefix %q", eksTokenPrefix)
	}
	urlBytes, err := base64.RawURLEncoding.DecodeString(tokenBody)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to base64-decode eksToken: %w", err)
	}
	// Skip full URL parsing — extract only the query string since that's all we need.
	_, rawQuery, ok := strings.Cut(string(urlBytes), "?")
	if !ok {
		return time.Time{}, fmt.Errorf("presigned URL in eksToken has no query string")
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse query string from eksToken: %w", err)
	}
	amzDate := q.Get("X-Amz-Date")
	signingTime, err := time.Parse("20060102T150405Z", amzDate)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid X-Amz-Date %q in eksToken: %w", amzDate, err)
	}
	amzExpires := q.Get("X-Amz-Expires")
	expiresSecs, err := strconv.Atoi(amzExpires)
	if err != nil || expiresSecs <= 0 {
		return time.Time{}, fmt.Errorf("invalid X-Amz-Expires %q in eksToken: must be a positive integer", amzExpires)
	}
	return signingTime.Add(time.Duration(expiresSecs) * time.Second).UTC(), nil
}
