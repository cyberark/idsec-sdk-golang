package k8s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

	// eksTokenPrefix is prepended to the base64url-encoded presigned URL.
	eksTokenPrefix = "k8s-aws-v1."

	// eksExecCredAPIVersion is the Kubernetes client-auth API version.
	eksExecCredAPIVersion = "client.authentication.k8s.io/v1beta1"

	// awsElevateTTL is the maximum session duration returned by the Elevate API
	// for AWS STS credentials.
	awsElevateTTL = 1 * time.Hour
)

// AWSTokenProvider implements IdsecSCAK8sTokenProvider for AWS EKS.
type AWSTokenProvider struct{}

// CSP returns the AWS CSP identifier.
func (p *AWSTokenProvider) CSP() string { return "AWS" }

// ElevateTTL returns the Elevate credential cache duration for AWS (1 hour).
func (p *AWSTokenProvider) ElevateTTL() time.Duration { return awsElevateTTL }

// GenerateToken creates an EKS bearer token by presigning a GetCallerIdentity
// request using the AWS STS credentials from the Elevate API response.
//
// The x-k8s-aws-id header and X-Amz-Expires query parameter are both injected
// via a Build-phase middleware so they are included in the SigV4 signature,
// which EKS requires.
//
// No ExpirationTimestamp is set in the returned ExecCredential: kubectl will
// re-invoke the plugin on 401 Unauthorized from the cluster API server.
func (p *AWSTokenProvider) GenerateToken(
	result *k8smodels.IdsecSCAK8sElevateResult,
	ctx *IdsecSCAK8sClusterContext,
) (*k8smodels.IdsecSCAK8sExecCredential, error) {
	if result == nil {
		return nil, fmt.Errorf("elevate result cannot be nil")
	}
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

	return &k8smodels.IdsecSCAK8sExecCredential{
		APIVersion: eksExecCredAPIVersion,
		Kind:       "ExecCredential",
		Status: k8smodels.IdsecSCAK8sExecCredentialStatus{
			Token: token,
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
