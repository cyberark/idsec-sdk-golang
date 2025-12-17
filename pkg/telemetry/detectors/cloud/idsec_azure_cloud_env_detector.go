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
	defaultAzureMetadataIpAddr = "169.254.169.254"
)

type IdsecAzureCloudEnvDetector struct {
	httpClient *http.Client

	// For testing purposes
	envVarPrefix        string
	azureMetadataIpAddr string
}

func NewIdsecAzureCloudDetector() detectors.IdsecEnvDetector {
	return &IdsecAzureCloudEnvDetector{
		httpClient:          &http.Client{Timeout: 200 * time.Millisecond},
		azureMetadataIpAddr: defaultAzureMetadataIpAddr,
	}
}

func (d *IdsecAzureCloudEnvDetector) Detect() (*detectors.IdsecEnvContext, bool) {

	if ctx, ok := d.detectAzureIMDS(); ok {
		return ctx, true
	}
	if os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "FUNCTIONS_WORKER_RUNTIME")) != "" {
		return &detectors.IdsecEnvContext{
			Provider:    "azure",
			Environment: "functions",
			Region:      d.fallbackRegion(),
			AccountID:   d.fallbackSubscriptionID(),
		}, true
	}
	if os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "WEBSITE_INSTANCE_ID")) != "" || os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "WEBSITE_SITE_NAME")) != "" {
		return &detectors.IdsecEnvContext{
			Provider:    "azure",
			Environment: "appservice",
			Region:      d.fallbackRegion(),
			AccountID:   d.fallbackSubscriptionID(),
		}, true
	}
	if d.isAKS() {
		return &detectors.IdsecEnvContext{
			Provider:    "azure",
			Environment: "k8s",
			Region:      d.fallbackRegion(),
			AccountID:   d.fallbackSubscriptionID(),
		}, true
	}
	return &detectors.IdsecEnvContext{}, false
}

func (d *IdsecAzureCloudEnvDetector) detectAzureIMDS() (*detectors.IdsecEnvContext, bool) {
	req, _ := http.NewRequest(
		"GET",
		fmt.Sprintf("http://%s/metadata/instance?api-version=2021-02-01", d.azureMetadataIpAddr),
		nil,
	)
	req.Header.Set("Metadata", "true")

	resp, err := d.httpClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return &detectors.IdsecEnvContext{}, false
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	body, _ := io.ReadAll(resp.Body)

	type imdsCompute struct {
		Location          string `json:"location"`
		VMID              string `json:"vmId"`
		SubscriptionID    string `json:"subscriptionId"`
		ResourceGroupName string `json:"resourceGroupName"`
	}
	var imds struct {
		Compute imdsCompute `json:"compute"`
	}
	if err := json.Unmarshal(body, &imds); err != nil {
		return &detectors.IdsecEnvContext{}, false
	}

	return &detectors.IdsecEnvContext{
		Provider:    "azure",
		Environment: "vm",
		Region:      imds.Compute.Location,
		AccountID:   imds.Compute.SubscriptionID,
		InstanceID:  imds.Compute.VMID,
	}, true
}

// isAKS checks if the environment is Azure Kubernetes Service (AKS).
// It verifies both Kubernetes presence and Azure-specific indicators.
func (d *IdsecAzureCloudEnvDetector) isAKS() bool {
	isK8s := os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "KUBERNETES_SERVICE_HOST")) != ""
	if !isK8s {
		if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err != nil {
			return false
		}
	}
	if os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "AKS_CLUSTER_NAME")) != "" {
		return true
	}
	if os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "AZURE_CONTAINER_INSTANCE_ID")) != "" {
		return true
	}
	azureFiles := []string{
		"/etc/kubernetes/azure.json",
		"/etc/kubernetes/azurekubeletidentity.json",
	}
	for _, file := range azureFiles {
		if _, err := os.Stat(file); err == nil {
			return true
		}
	}
	return false
}

func (d *IdsecAzureCloudEnvDetector) fallbackRegion() string {
	if v := os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "AZURE_REGION")); v != "" {
		return v
	}
	if v := os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "REGION_NAME")); v != "" {
		return v
	}
	if v := os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "LOCATION")); v != "" {
		return v
	}
	return "unknown"
}

func (d *IdsecAzureCloudEnvDetector) fallbackSubscriptionID() string {
	if v := os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "AZURE_SUBSCRIPTION_ID")); v != "" {
		return v
	}
	if v := os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "SUBSCRIPTION_ID")); v != "" {
		return v
	}
	return "unknown"
}
