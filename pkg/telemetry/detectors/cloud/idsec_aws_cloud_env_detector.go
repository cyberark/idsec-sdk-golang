package cloud

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/detectors"
)

const (
	defaultAwsMetadataIpAddr = "169.254.169.254"
)

type IdsecAWSCloudEnvDetector struct {
	httpClient *http.Client

	// For testing purposes
	envVarPrefix      string
	awsMetadataIpAddr string
}

func NewIdsecAWSCloudEnvDetector() detectors.IdsecEnvDetector {
	return &IdsecAWSCloudEnvDetector{
		httpClient:        &http.Client{Timeout: 150 * time.Millisecond},
		awsMetadataIpAddr: defaultAwsMetadataIpAddr,
	}
}

func (d *IdsecAWSCloudEnvDetector) Detect() (*detectors.IdsecEnvContext, bool) {
	if instanceID, region, accountID, ok := d.detectEC2(); ok {
		return &detectors.IdsecEnvContext{
			Provider:    "aws",
			Environment: "ec2",
			Region:      region,
			InstanceID:  instanceID,
			AccountID:   accountID,
		}, true
	}
	if os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "ECS_CONTAINER_METADATA_URI_V4")) != "" {
		return &detectors.IdsecEnvContext{
			Provider:    "aws",
			Environment: "ecs",
			Region:      d.fallbackRegion(),
			AccountID:   d.fallbackAccountID(),
		}, true
	}
	if os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "AWS_LAMBDA_FUNCTION_NAME")) != "" {
		return &detectors.IdsecEnvContext{
			Provider:    "aws",
			Environment: "lambda",
			Region:      d.fallbackRegion(),
			AccountID:   d.fallbackAccountID(),
		}, true
	}
	if d.isEKS() {
		return &detectors.IdsecEnvContext{
			Provider:    "aws",
			Environment: "k8s",
			Region:      d.fallbackRegion(),
			AccountID:   d.fallbackAccountID(),
		}, true
	}

	return &detectors.IdsecEnvContext{}, false
}

func (d *IdsecAWSCloudEnvDetector) detectEC2() (instanceID, region, accountID string, ok bool) {
	id, err1 := d.getMetadata("latest/meta-data/instance-id")
	regionVal, err2 := d.getMetadata("latest/meta-data/placement/region")
	document, err3 := d.getMetadata("latest/dynamic/instance-identity/document")

	// If both fail, not EC2
	if err1 != nil && err2 != nil && err3 != nil {
		return "", "", "", false
	}
	accountID = d.fallbackAccountID()
	if err3 == nil {
		// Try to parse account from instance identity document
		var parsedDocument struct {
			AccountID string `json:"accountId"`
		}
		err := json.Unmarshal([]byte(document), &parsedDocument)
		if err == nil && parsedDocument.AccountID != "" {
			accountID = parsedDocument.AccountID
		}
	}
	return id, regionVal, accountID, true
}

func (d *IdsecAWSCloudEnvDetector) getMetadata(path string) (string, error) {
	// Get token for IMDSv2
	tokenReq, _ := http.NewRequest("PUT", fmt.Sprintf("http://%s/latest/api/token", d.awsMetadataIpAddr), nil)
	tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")

	tokenResp, err := d.httpClient.Do(tokenReq)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(tokenResp.Body)

	req, _ := http.NewRequest("GET",
		fmt.Sprintf("http://%s/%s", d.awsMetadataIpAddr, path),
		nil)

	// Add token if available
	if tokenResp.StatusCode == http.StatusOK {
		token, _ := io.ReadAll(tokenResp.Body)
		req.Header.Set("X-aws-ec2-metadata-token", string(token))
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata returned %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

// isEKS checks if the environment is Amazon Elastic Kubernetes Service (EKS).
// It verifies both Kubernetes presence and AWS-specific indicators.
func (d *IdsecAWSCloudEnvDetector) isEKS() bool {
	isK8s := os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "KUBERNETES_SERVICE_HOST")) != ""
	if !isK8s {
		if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err != nil {
			return false
		}
	}
	if os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "AWS_ROLE_ARN")) != "" {
		return true
	}
	if os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "AWS_WEB_IDENTITY_TOKEN_FILE")) != "" {
		return true
	}
	eksIndicators := []string{
		"/etc/eks/release",
		"/etc/eks/containerd/containerd-config.toml",
		"/var/lib/amazon",
	}
	for _, indicator := range eksIndicators {
		if _, err := os.Stat(indicator); err == nil {
			return true
		}
	}
	if _, err := d.getMetadata("latest/meta-data/instance-id"); err == nil {
		return true
	}
	return false
}

func (d *IdsecAWSCloudEnvDetector) fallbackRegion() string {
	if v := os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "AWS_REGION")); v != "" {
		return v
	}
	if v := os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "AWS_DEFAULT_REGION")); v != "" {
		return v
	}
	return "unknown"
}

func (d *IdsecAWSCloudEnvDetector) fallbackAccountID() string {
	if v := os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "AWS_ACCOUNT_ID")); v != "" {
		return v
	}
	if v := os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "CDK_DEFAULT_ACCOUNT")); v != "" {
		return v
	}
	return "unknown"
}
