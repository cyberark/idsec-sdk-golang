package cloud

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/detectors"
)

const (
	defaultGcpMetadataIpAddr = "169.254.169.254"
)

type IdsecGCPCloudEnvDetector struct {
	httpClient *http.Client

	// For testing purposes
	envVarPrefix      string
	gcpMetadataIpAddr string
}

func NewIdsecGCPCloudEnvDetector() detectors.IdsecEnvDetector {
	return &IdsecGCPCloudEnvDetector{
		httpClient:        &http.Client{Timeout: 200 * time.Millisecond},
		gcpMetadataIpAddr: defaultGcpMetadataIpAddr,
	}
}

func (d *IdsecGCPCloudEnvDetector) Detect() (*detectors.IdsecEnvContext, bool) {
	if instanceID, zone, projectID, ok := d.detectGCE(); ok {
		return &detectors.IdsecEnvContext{
			Provider:    "gcp",
			Environment: "gce",
			Region:      d.extractRegionFromZone(zone),
			InstanceID:  instanceID,
			AccountID:   projectID,
		}, true
	}
	if os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "FUNCTION_NAME")) != "" || os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "FUNCTION_TARGET")) != "" {
		return &detectors.IdsecEnvContext{
			Provider:    "gcp",
			Environment: "functions",
			Region:      d.fallbackRegion(),
			AccountID:   d.fallbackProjectID(),
		}, true
	}
	if os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "K_SERVICE")) != "" {
		return &detectors.IdsecEnvContext{
			Provider:    "gcp",
			Environment: "cloudrun",
			Region:      d.fallbackRegion(),
			AccountID:   d.fallbackProjectID(),
		}, true
	}
	if d.isGKE() {
		return &detectors.IdsecEnvContext{
			Provider:    "gcp",
			Environment: "k8s",
			Region:      d.fallbackRegion(),
			AccountID:   d.fallbackProjectID(),
		}, true
	}

	return &detectors.IdsecEnvContext{}, false
}

func (d *IdsecGCPCloudEnvDetector) detectGCE() (instanceID, zone, projectID string, ok bool) {
	vmID, err1 := d.getMetadata("instance/id")
	zone, err2 := d.getMetadata("instance/zone")
	projectID, err3 := d.getMetadata("project/project-id")

	if err1 != nil && err2 != nil && err3 != nil {
		return "", "", "", false
	}

	return vmID, zone, projectID, true
}

func (d *IdsecGCPCloudEnvDetector) getMetadata(path string) (string, error) {
	req, _ := http.NewRequest(
		"GET",
		fmt.Sprintf("http://%s/computeMetadata/v1/%s)", d.gcpMetadataIpAddr, path),
		nil,
	)
	req.Header.Set("Metadata-Flavor", "Google") // required

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata status %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

func (d *IdsecGCPCloudEnvDetector) extractRegionFromZone(zone string) string {
	if zone == "" {
		return ""
	}
	parts := strings.Split(zone, "/")
	last := parts[len(parts)-1] // "us-central1-a"
	regionParts := strings.Split(last, "-")
	if len(regionParts) < 2 {
		return last
	}
	return fmt.Sprintf("%s-%s", regionParts[0], regionParts[1])
}

// isGKE checks if the environment is Google Kubernetes Engine (GKE).
//
// It verifies both Kubernetes presence and GCP-specific indicators to distinguish
// GKE from other Kubernetes environments. The detection uses multiple signals
// including environment variables, GCP-specific files, and metadata service availability.
//
// Returns true if running in GKE, false otherwise.
func (d *IdsecGCPCloudEnvDetector) isGKE() bool {
	isK8s := os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "KUBERNETES_SERVICE_HOST")) != ""
	if !isK8s {
		if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err != nil {
			return false
		}
	}
	if os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "GKE_CLUSTER_NAME")) != "" {
		return true
	}
	if os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "GOOGLE_APPLICATION_CREDENTIALS")) != "" {
		return true
	}
	if os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "GCE_METADATA_HOST")) != "" {
		return true
	}
	gkeIndicators := []string{
		"/var/lib/google",
		"/etc/gke/config",
		"/home/kubernetes",
		"/var/lib/kubelet/kubeconfig",
	}
	for _, indicator := range gkeIndicators {
		if _, err := os.Stat(indicator); err == nil {
			return true
		}
	}
	if _, err := d.getMetadata("instance/id"); err == nil {
		return true
	}

	return false
}

func (d *IdsecGCPCloudEnvDetector) fallbackRegion() string {
	if v := os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "FUNCTION_REGION")); v != "" {
		return v
	}
	if v := os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "GOOGLE_CLOUD_REGION")); v != "" {
		return v
	}
	if v := os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "REGION")); v != "" {
		return v
	}
	return "unknown"
}

func (d *IdsecGCPCloudEnvDetector) fallbackProjectID() string {
	if v := os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "GOOGLE_CLOUD_PROJECT")); v != "" {
		return v
	}
	if v := os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "GCLOUD_PROJECT")); v != "" {
		return v
	}
	if v := os.Getenv(commonmodels.ConcatEnv(d.envVarPrefix, "PROJECT_ID")); v != "" {
		return v
	}
	return "unknown"
}
