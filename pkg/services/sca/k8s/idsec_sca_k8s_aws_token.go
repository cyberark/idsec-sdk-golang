package k8s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithymiddleware "github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

const (
	// eksPresignDuration is the hard AWS limit for STS presigned URL validity.
	// EKS does not honour longer durations.
	eksPresignDuration = 15 * time.Minute

	// eksExecCredRefreshBuffer is the early-refresh window subtracted from the
	// presigned URL expiry before stamping status.expirationTimestamp. It mirrors
	// the proxy refresh buffer so kubectl/client-go and the unified ExecCredential
	// cache rotate slightly before the credential actually expires server-side.
	eksExecCredRefreshBuffer = 60 * time.Second

	// eksTokenPrefix is prepended to the base64url-encoded presigned URL.
	eksTokenPrefix = "k8s-aws-v1."

	// eksExecCredAPIVersion is the Kubernetes client-auth API version.
	eksExecCredAPIVersion = "client.authentication.k8s.io/v1beta1"
)

// AWSTokenProvider implements IdsecSCAK8sTokenProvider for AWS EKS.
type AWSTokenProvider struct{}

// CSP returns the AWS CSP identifier.
func (p *AWSTokenProvider) CSP() string { return k8smodels.CSPAWS }

// GenerateToken returns an ExecCredential for EKS.
// Uses the server-provided eksToken when present (expiry decoded via ParseEKSTokenExpiry);
// falls back to client-side STS presigning from accessCredentials (legacy path).
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

	// Client-side fallback: presign GetCallerIdentity using accessCredentials.
	if result.AccessCredentials == "" {
		return nil, fmt.Errorf("accessCredentials is empty for AWS CSP")
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

	stsClient := sts.NewFromConfig(cfg)
	presignClient := sts.NewPresignClient(stsClient)

	clusterID := ctx.ClusterID
	// Capture the presign issuance time BEFORE the call so the stamped
	// expirationTimestamp is conservative if the call itself takes a few hundred ms.
	presignedAt := time.Now()
	presignedReq, err := presignClient.PresignGetCallerIdentity(
		context.Background(),
		&sts.GetCallerIdentityInput{},
		func(o *sts.PresignOptions) {
			o.ClientOptions = append(o.ClientOptions, func(opts *sts.Options) {
				opts.APIOptions = append(opts.APIOptions, func(stack *smithymiddleware.Stack) error {
					return stack.Build.Add(
						&eksPresignMiddleware{
							clusterID: clusterID,
							expires:   eksPresignDuration,
						},
						smithymiddleware.After,
					)
				})
			})
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to presign STS GetCallerIdentity: %w", err)
	}

	// EKS token format: k8s-aws-v1.<base64url-no-padding of the presigned URL>
	token := eksTokenPrefix + base64.RawURLEncoding.EncodeToString([]byte(presignedReq.URL))

	// Bake the early-refresh buffer in once, here, mirroring the proxy generator. The
	// kubectl cache and unified ExecCredential cache treat status.expirationTimestamp
	// as final and apply no further arithmetic.
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

// eksPresignMiddleware is a Build-phase middleware that:
//  1. Sets the x-k8s-aws-id header (required by the EKS API server for cluster identification)
//  2. Sets the X-Amz-Expires query parameter (required by the SigV4 presigner to encode URL TTL)
//
// Both are injected at Build phase (before SigV4 signing in Finalize) so that
// they form part of the computed signature.
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

		// X-Amz-Expires encodes the presigned URL TTL in seconds.
		// The v4 signer reads this from the query string — it does not set it automatically.
		query := req.URL.Query()
		query.Set("X-Amz-Expires", strconv.FormatInt(int64(m.expires/time.Second), 10))
		req.URL.RawQuery = query.Encode()
	}
	return next.HandleBuild(bCtx, in)
}
