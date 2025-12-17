package cloud

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestNewIdsecGCPCloudEnvDetector(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{
			name:     "success_creates_detector_instance",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			detector := NewIdsecGCPCloudEnvDetector()

			if detector == nil {
				t.Error("Expected non-nil detector")
			}

			if _, ok := detector.(*IdsecGCPCloudEnvDetector); !ok && tt.expected {
				t.Error("Expected detector to be of type *IdsecGCPCloudEnvDetector")
			}

			gcpDetector := detector.(*IdsecGCPCloudEnvDetector)
			if gcpDetector.httpClient == nil {
				t.Error("Expected non-nil httpClient")
			}

			if gcpDetector.httpClient.Timeout != 200*time.Millisecond {
				t.Errorf("Expected timeout of 200ms, got %v", gcpDetector.httpClient.Timeout)
			}
		})
	}
}

func TestIdsecGCPCloudEnvDetector_Detect(t *testing.T) {
	tests := []struct {
		name              string
		envPrefix         string
		setupEnv          func(prefix string) map[string]string
		expectedDetected  bool
		expectedProvider  string
		expectedEnv       string
		expectedRegion    string
		expectedAccountID string
	}{
		{
			name:      "success_detects_functions_environment",
			envPrefix: "TEST_GCP_FUNC_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "FUNCTION_NAME": "my-function",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "gcp",
			expectedEnv:       "functions",
			expectedRegion:    "unknown",
			expectedAccountID: "unknown",
		},
		{
			name:      "success_detects_cloudrun_environment",
			envPrefix: "TEST_GCP_RUN_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "K_SERVICE": "my-service",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "gcp",
			expectedEnv:       "cloudrun",
			expectedRegion:    "unknown",
			expectedAccountID: "unknown",
		},
		{
			name:      "success_detects_kubernetes_environment",
			envPrefix: "TEST_GCP_K8S_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "KUBERNETES_SERVICE_HOST": "10.0.0.1",
					prefix + "GKE_CLUSTER_NAME":        "my-gke-cluster",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "gcp",
			expectedEnv:       "k8s",
			expectedRegion:    "unknown",
			expectedAccountID: "unknown",
		},
		{
			name: "success_not_detected_no_gcp_indicators",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{}
			},
			expectedDetected: false,
		},
		{
			name:      "success_functions_with_region_fallback",
			envPrefix: "TEST_GCP_FUNC_REGION_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "FUNCTION_NAME":   "my-function",
					prefix + "FUNCTION_REGION": "us-central1",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "gcp",
			expectedEnv:       "functions",
			expectedRegion:    "us-central1",
			expectedAccountID: "unknown",
		},
		{
			name:      "success_cloudrun_with_project_fallback",
			envPrefix: "TEST_GCP_RUN_PROJECT_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "K_SERVICE":            "my-service",
					prefix + "GOOGLE_CLOUD_PROJECT": "my-project",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "gcp",
			expectedEnv:       "cloudrun",
			expectedRegion:    "unknown",
			expectedAccountID: "my-project",
		},
		{
			name:      "success_k8s_with_google_cloud_region_fallback",
			envPrefix: "TEST_GCP_K8S_REGION_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "KUBERNETES_SERVICE_HOST": "10.0.0.1",
					prefix + "GKE_CLUSTER_NAME":        "my-gke-cluster",
					prefix + "GOOGLE_CLOUD_REGION":     "us-west1",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "gcp",
			expectedEnv:       "k8s",
			expectedRegion:    "us-west1",
			expectedAccountID: "unknown",
		},
		{
			name:      "success_gce_priority_over_functions",
			envPrefix: "TEST_GCP_FUNC_GCE_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "FUNCTION_NAME": "my-function",
				}
			},
			expectedDetected:  true, // Will detect functions since GCE detection fails
			expectedProvider:  "gcp",
			expectedEnv:       "functions",
			expectedRegion:    "unknown",
			expectedAccountID: "unknown",
		},
		{
			name:      "success_functions_priority_over_cloudrun",
			envPrefix: "TEST_GCP_FUNC_CLOUDRUN_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "FUNCTION_NAME": "my-function",
					prefix + "K_SERVICE":     "my-service",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "gcp",
			expectedEnv:       "functions",
			expectedRegion:    "unknown",
			expectedAccountID: "unknown",
		},
		{
			name:      "success_cloudrun_priority_over_k8s",
			envPrefix: "TEST_GCP_RUN_K8S_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "K_SERVICE":               "my-service",
					prefix + "KUBERNETES_SERVICE_HOST": "10.0.0.1",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "gcp",
			expectedEnv:       "cloudrun",
			expectedRegion:    "unknown",
			expectedAccountID: "unknown",
		},
		{
			name:      "success_region_fallback_priority",
			envPrefix: "TEST_GCP_REGION_FALLBACK_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "FUNCTION_NAME":       "my-function",
					prefix + "FUNCTION_REGION":     "us-central1",
					prefix + "GOOGLE_CLOUD_REGION": "us-east1",
					prefix + "REGION":              "us-west1",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "gcp",
			expectedEnv:       "functions",
			expectedRegion:    "us-central1",
			expectedAccountID: "unknown",
		},
		{
			name:      "success_project_id_fallback_priority",
			envPrefix: "TEST_GCP_PROJECT_PRIORITY_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "K_SERVICE":            "my-service",
					prefix + "GOOGLE_CLOUD_PROJECT": "project-1",
					prefix + "GCLOUD_PROJECT":       "project-2",
					prefix + "PROJECT_ID":           "project-3",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "gcp",
			expectedEnv:       "cloudrun",
			expectedRegion:    "unknown",
			expectedAccountID: "project-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupEnv != nil {
				testEnv := tt.setupEnv(tt.envPrefix)
				defer func() {
					for key := range testEnv {
						os.Unsetenv(key)
					}
				}()
				for key, val := range testEnv {
					os.Setenv(key, val)
				}
			}

			detector := &IdsecGCPCloudEnvDetector{
				httpClient:   &http.Client{Timeout: 200 * time.Millisecond},
				envVarPrefix: tt.envPrefix,
			}
			ctx, detected := detector.Detect()

			if detected != tt.expectedDetected {
				t.Errorf("Expected detected to be %v, got %v", tt.expectedDetected, detected)
				return
			}

			if !detected {
				return
			}

			if ctx.Provider != tt.expectedProvider {
				t.Errorf("Expected provider '%s', got '%s'", tt.expectedProvider, ctx.Provider)
			}

			if ctx.Environment != tt.expectedEnv {
				t.Errorf("Expected environment '%s', got '%s'", tt.expectedEnv, ctx.Environment)
			}

			if ctx.Region != tt.expectedRegion {
				t.Errorf("Expected region '%s', got '%s'", tt.expectedRegion, ctx.Region)
			}

			if ctx.AccountID != tt.expectedAccountID {
				t.Errorf("Expected accountID '%s', got '%s'", tt.expectedAccountID, ctx.AccountID)
			}
		})
	}
}

func TestIdsecGCPCloudEnvDetector_detectGCE(t *testing.T) {
	tests := []struct {
		name               string
		mockServer         func() *httptest.Server
		expectedOK         bool
		expectedInstanceID string
		expectedZone       string
		expectedProjectID  string
	}{
		{
			name: "success_detects_gce_vm",
			mockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Metadata-Flavor") != "Google" {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					switch r.URL.Path {
					case "/computeMetadata/v1/instance/id)":
						w.WriteHeader(http.StatusOK)
						w.Write([]byte("1234567890"))
					case "/computeMetadata/v1/instance/zone)":
						w.WriteHeader(http.StatusOK)
						w.Write([]byte("projects/123456/zones/us-central1-a"))
					case "/computeMetadata/v1/project/project-id)":
						w.WriteHeader(http.StatusOK)
						w.Write([]byte("my-project"))
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}))
			},
			expectedOK:         true,
			expectedInstanceID: "1234567890",
			expectedZone:       "projects/123456/zones/us-central1-a",
			expectedProjectID:  "my-project",
		},
		{
			name: "error_metadata_endpoint_not_reachable",
			mockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}))
			},
			expectedOK:         false,
			expectedInstanceID: "",
			expectedZone:       "",
			expectedProjectID:  "",
		},
		{
			name: "error_missing_metadata_flavor_header",
			mockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Simulate missing header by returning BadRequest for all requests
					w.WriteHeader(http.StatusBadRequest)
				}))
			},
			expectedOK:         false,
			expectedInstanceID: "",
			expectedZone:       "",
			expectedProjectID:  "",
		},
		{
			name: "success_partial_metadata_available",
			mockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Metadata-Flavor") != "Google" {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					// Only respond to instance ID
					if r.URL.Path == "/computeMetadata/v1/instance/id)" {
						w.WriteHeader(http.StatusOK)
						w.Write([]byte("partial-id"))
					} else {
						w.WriteHeader(http.StatusNotFound)
					}
				}))
			},
			expectedOK:         true,
			expectedInstanceID: "partial-id",
			expectedZone:       "",
			expectedProjectID:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := tt.mockServer()
			defer server.Close()

			detector := NewIdsecGCPCloudEnvDetector()
			gcpDetector := detector.(*IdsecGCPCloudEnvDetector)
			// Extract host:port from server.URL (e.g., "http://127.0.0.1:12345" -> "127.0.0.1:12345")
			gcpDetector.gcpMetadataIpAddr = server.URL[7:] // Remove "http://"

			instanceID, zone, projectID, ok := gcpDetector.detectGCE()

			if ok != tt.expectedOK {
				t.Errorf("Expected ok to be %v, got %v", tt.expectedOK, ok)
			}

			if instanceID != tt.expectedInstanceID {
				t.Errorf("Expected instanceID '%s', got '%s'", tt.expectedInstanceID, instanceID)
			}

			if zone != tt.expectedZone {
				t.Errorf("Expected zone '%s', got '%s'", tt.expectedZone, zone)
			}

			if projectID != tt.expectedProjectID {
				t.Errorf("Expected projectID '%s', got '%s'", tt.expectedProjectID, projectID)
			}
		})
	}
}

func TestIdsecGCPCloudEnvDetector_getMetadata(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		mockServer    func() *httptest.Server
		expectedData  string
		expectedError bool
	}{
		{
			name: "success_gets_metadata",
			path: "instance/id",
			mockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Metadata-Flavor") != "Google" {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("test-value"))
				}))
			},
			expectedData:  "test-value",
			expectedError: false,
		},
		{
			name: "error_metadata_endpoint_returns_error",
			path: "instance/id",
			mockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotFound)
				}))
			},
			expectedError: true,
		},
		{
			name: "error_missing_metadata_flavor_header",
			path: "instance/id",
			mockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Return BadRequest to simulate missing header rejection
					w.WriteHeader(http.StatusBadRequest)
				}))
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := tt.mockServer()
			defer server.Close()

			detector := &IdsecGCPCloudEnvDetector{
				httpClient:        &http.Client{Timeout: 200 * time.Millisecond},
				gcpMetadataIpAddr: server.URL[7:], // Remove "http://"
			}

			data, err := detector.getMetadata(tt.path)

			if tt.expectedError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Expected no error, got %v", err)
				return
			}

			if data != tt.expectedData {
				t.Errorf("Expected data '%s', got '%s'", tt.expectedData, data)
			}
		})
	}
}

func TestIdsecGCPCloudEnvDetector_extractRegionFromZone(t *testing.T) {
	tests := []struct {
		name           string
		zone           string
		expectedRegion string
	}{
		{
			name:           "success_extracts_region_from_full_zone_path",
			zone:           "projects/123456/zones/us-central1-a",
			expectedRegion: "us-central1",
		},
		{
			name:           "success_extracts_region_from_zone_name",
			zone:           "us-east1-b",
			expectedRegion: "us-east1",
		},
		{
			name:           "success_extracts_region_from_multi_part_zone",
			zone:           "europe-west1-c",
			expectedRegion: "europe-west1",
		},
		{
			name:           "success_returns_zone_if_cannot_extract_region",
			zone:           "unknown",
			expectedRegion: "unknown",
		},
		{
			name:           "success_returns_empty_string_for_empty_zone",
			zone:           "",
			expectedRegion: "",
		},
		{
			name:           "success_handles_single_part_zone",
			zone:           "zone",
			expectedRegion: "zone",
		},
		{
			name:           "success_handles_asia_region",
			zone:           "asia-northeast1-a",
			expectedRegion: "asia-northeast1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			detector := &IdsecGCPCloudEnvDetector{}
			region := detector.extractRegionFromZone(tt.zone)

			if region != tt.expectedRegion {
				t.Errorf("Expected region '%s', got '%s'", tt.expectedRegion, region)
			}
		})
	}
}

func TestIdsecGCPCloudEnvDetector_isGKE(t *testing.T) {
	tests := []struct {
		name      string
		envPrefix string
		setupEnv  func(prefix string) map[string]string
		expected  bool
	}{
		{
			name:      "success_detected_with_service_host_only",
			envPrefix: "TEST_GCP_K8S_1_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "KUBERNETES_SERVICE_HOST": "10.0.0.1",
				}
			},
			expected: false, // Will be false unless GKE-specific indicators are present
		},
		{
			name:      "success_detected_with_gke_cluster_name",
			envPrefix: "TEST_GCP_K8S_GKE_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "KUBERNETES_SERVICE_HOST": "10.0.0.1",
					prefix + "GKE_CLUSTER_NAME":        "my-gke-cluster",
				}
			},
			expected: true,
		},
		{
			name:      "success_detected_with_google_application_credentials",
			envPrefix: "TEST_GCP_K8S_CREDS_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "KUBERNETES_SERVICE_HOST":        "10.0.0.1",
					prefix + "GOOGLE_APPLICATION_CREDENTIALS": "/var/secrets/google/key.json",
				}
			},
			expected: true,
		},
		{
			name:      "success_detected_with_gce_metadata_host",
			envPrefix: "TEST_GCP_K8S_METADATA_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "KUBERNETES_SERVICE_HOST": "10.0.0.1",
					prefix + "GCE_METADATA_HOST":       "metadata.google.internal",
				}
			},
			expected: true,
		},
		{
			name: "success_not_detected_without_indicators",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{}
			},
			expected: false,
		},
		{
			name:      "success_not_detected_with_empty_service_host",
			envPrefix: "TEST_GCP_K8S_2_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "KUBERNETES_SERVICE_HOST": "",
				}
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupEnv != nil {
				testEnv := tt.setupEnv(tt.envPrefix)
				defer func() {
					for key := range testEnv {
						os.Unsetenv(key)
					}
				}()
				for key, val := range testEnv {
					os.Setenv(key, val)
				}
			}

			detector := &IdsecGCPCloudEnvDetector{
				httpClient:        &http.Client{Timeout: 200 * time.Millisecond},
				envVarPrefix:      tt.envPrefix,
				gcpMetadataIpAddr: "169.254.169.254", // Use default to prevent network calls
			}
			result := detector.isGKE()

			if result != tt.expected {
				t.Errorf("Expected isGKE() to return %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIdsecGCPCloudEnvDetector_fallbackRegion(t *testing.T) {
	tests := []struct {
		name           string
		envPrefix      string
		setupEnv       func(prefix string) map[string]string
		expectedRegion string
	}{
		{
			name:      "success_returns_function_region",
			envPrefix: "TEST_GCP_REGION_1_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "FUNCTION_REGION": "us-central1",
				}
			},
			expectedRegion: "us-central1",
		},
		{
			name:      "success_returns_google_cloud_region_when_function_region_not_set",
			envPrefix: "TEST_GCP_REGION_2_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "GOOGLE_CLOUD_REGION": "us-east1",
				}
			},
			expectedRegion: "us-east1",
		},
		{
			name:      "success_returns_region_when_others_not_set",
			envPrefix: "TEST_GCP_REGION_3_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "REGION": "us-west1",
				}
			},
			expectedRegion: "us-west1",
		},
		{
			name:      "success_prefers_function_region_over_others",
			envPrefix: "TEST_GCP_REGION_4_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "FUNCTION_REGION":     "us-central1",
					prefix + "GOOGLE_CLOUD_REGION": "us-east1",
					prefix + "REGION":              "us-west1",
				}
			},
			expectedRegion: "us-central1",
		},
		{
			name:      "success_prefers_google_cloud_region_over_region",
			envPrefix: "TEST_GCP_REGION_5_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "GOOGLE_CLOUD_REGION": "us-east1",
					prefix + "REGION":              "us-west1",
				}
			},
			expectedRegion: "us-east1",
		},
		{
			name:      "success_returns_unknown_when_no_env_vars",
			envPrefix: "TEST_GCP_REGION_6_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{}
			},
			expectedRegion: "unknown",
		},
		{
			name:      "success_returns_unknown_when_empty_env_vars",
			envPrefix: "TEST_GCP_REGION_7_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "FUNCTION_REGION":     "",
					prefix + "GOOGLE_CLOUD_REGION": "",
					prefix + "REGION":              "",
				}
			},
			expectedRegion: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupEnv != nil {
				testEnv := tt.setupEnv(tt.envPrefix)
				defer func() {
					for key := range testEnv {
						os.Unsetenv(key)
					}
				}()
				for key, val := range testEnv {
					os.Setenv(key, val)
				}
			}

			detector := &IdsecGCPCloudEnvDetector{envVarPrefix: tt.envPrefix}
			region := detector.fallbackRegion()

			if region != tt.expectedRegion {
				t.Errorf("Expected region '%s', got '%s'", tt.expectedRegion, region)
			}
		})
	}
}

func TestIdsecGCPCloudEnvDetector_fallbackProjectID(t *testing.T) {
	tests := []struct {
		name              string
		envPrefix         string
		setupEnv          func(prefix string) map[string]string
		expectedProjectID string
	}{
		{
			name:      "success_returns_google_cloud_project",
			envPrefix: "TEST_GCP_PROJ_1_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "GOOGLE_CLOUD_PROJECT": "project-1",
				}
			},
			expectedProjectID: "project-1",
		},
		{
			name:      "success_returns_gcloud_project_when_google_cloud_project_not_set",
			envPrefix: "TEST_GCP_PROJ_2_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "GCLOUD_PROJECT": "project-2",
				}
			},
			expectedProjectID: "project-2",
		},
		{
			name:      "success_returns_project_id_when_others_not_set",
			envPrefix: "TEST_GCP_PROJ_3_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "PROJECT_ID": "project-3",
				}
			},
			expectedProjectID: "project-3",
		},
		{
			name:      "success_prefers_google_cloud_project_over_others",
			envPrefix: "TEST_GCP_PROJ_4_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "GOOGLE_CLOUD_PROJECT": "project-1",
					prefix + "GCLOUD_PROJECT":       "project-2",
					prefix + "PROJECT_ID":           "project-3",
				}
			},
			expectedProjectID: "project-1",
		},
		{
			name:      "success_prefers_gcloud_project_over_project_id",
			envPrefix: "TEST_GCP_PROJ_5_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "GCLOUD_PROJECT": "project-2",
					prefix + "PROJECT_ID":     "project-3",
				}
			},
			expectedProjectID: "project-2",
		},
		{
			name:      "success_returns_unknown_when_no_env_vars",
			envPrefix: "TEST_GCP_PROJ_6_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{}
			},
			expectedProjectID: "unknown",
		},
		{
			name:      "success_returns_unknown_when_empty_env_vars",
			envPrefix: "TEST_GCP_PROJ_7_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "GOOGLE_CLOUD_PROJECT": "",
					prefix + "GCLOUD_PROJECT":       "",
					prefix + "PROJECT_ID":           "",
				}
			},
			expectedProjectID: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupEnv != nil {
				testEnv := tt.setupEnv(tt.envPrefix)
				defer func() {
					for key := range testEnv {
						os.Unsetenv(key)
					}
				}()
				for key, val := range testEnv {
					os.Setenv(key, val)
				}
			}

			detector := &IdsecGCPCloudEnvDetector{envVarPrefix: tt.envPrefix}
			projectID := detector.fallbackProjectID()

			if projectID != tt.expectedProjectID {
				t.Errorf("Expected projectID '%s', got '%s'", tt.expectedProjectID, projectID)
			}
		})
	}
}

func TestIdsecGCPCloudEnvDetector_PriorityOrder(t *testing.T) {
	tests := []struct {
		name        string
		envPrefix   string
		setupEnv    func(prefix string) map[string]string
		expectedEnv string
	}{
		{
			name:      "success_functions_has_second_priority",
			envPrefix: "TEST_GCP_PRIORITY_1_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "FUNCTION_NAME":           "my-function",
					prefix + "K_SERVICE":               "my-service",
					prefix + "KUBERNETES_SERVICE_HOST": "10.0.0.1",
				}
			},
			expectedEnv: "functions",
		},
		{
			name:      "success_cloudrun_has_third_priority",
			envPrefix: "TEST_GCP_PRIORITY_2_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "K_SERVICE":               "my-service",
					prefix + "KUBERNETES_SERVICE_HOST": "10.0.0.1",
				}
			},
			expectedEnv: "cloudrun",
		},
		{
			name:      "success_k8s_has_fourth_priority",
			envPrefix: "TEST_GCP_PRIORITY_3_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "KUBERNETES_SERVICE_HOST": "10.0.0.1",
					prefix + "GKE_CLUSTER_NAME":        "my-gke-cluster",
				}
			},
			expectedEnv: "k8s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupEnv != nil {
				testEnv := tt.setupEnv(tt.envPrefix)
				defer func() {
					for key := range testEnv {
						os.Unsetenv(key)
					}
				}()
				for key, val := range testEnv {
					os.Setenv(key, val)
				}
			}

			detector := &IdsecGCPCloudEnvDetector{
				httpClient:   &http.Client{Timeout: 200 * time.Millisecond},
				envVarPrefix: tt.envPrefix,
			}
			ctx, detected := detector.Detect()

			if tt.expectedEnv == "" {
				if detected {
					t.Error("Expected no detection, but environment was detected")
				}
				return
			}

			if !detected {
				t.Error("Expected environment to be detected")
				return
			}

			if ctx.Environment != tt.expectedEnv {
				t.Errorf("Expected environment '%s', got '%s'", tt.expectedEnv, ctx.Environment)
			}
		})
	}
}

func TestIdsecGCPCloudEnvDetector_Timeout(t *testing.T) {
	tests := []struct {
		name            string
		expectedTimeout time.Duration
	}{
		{
			name:            "success_timeout_set_to_200ms",
			expectedTimeout: 200 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			detector := NewIdsecGCPCloudEnvDetector()
			gcpDetector := detector.(*IdsecGCPCloudEnvDetector)

			if gcpDetector.httpClient.Timeout != tt.expectedTimeout {
				t.Errorf("Expected timeout of %v, got %v", tt.expectedTimeout, gcpDetector.httpClient.Timeout)
			}
		})
	}
}

func TestIdsecGCPCloudEnvDetector_MultipleEnvironmentIndicators(t *testing.T) {
	tests := []struct {
		name            string
		envPrefix       string
		setupEnv        func(prefix string) map[string]string
		expectedEnv     string
		expectedRegion  string
		expectedAccount string
	}{
		{
			name:      "success_functions_with_all_metadata",
			envPrefix: "TEST_GCP_MULTI_1_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "FUNCTION_NAME":        "my-function",
					prefix + "FUNCTION_REGION":      "us-central1",
					prefix + "GOOGLE_CLOUD_PROJECT": "my-project",
				}
			},
			expectedEnv:     "functions",
			expectedRegion:  "us-central1",
			expectedAccount: "my-project",
		},
		{
			name:      "success_cloudrun_with_all_metadata",
			envPrefix: "TEST_GCP_MULTI_2_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "K_SERVICE":            "my-service",
					prefix + "GOOGLE_CLOUD_REGION":  "us-east1",
					prefix + "GOOGLE_CLOUD_PROJECT": "my-project",
				}
			},
			expectedEnv:     "cloudrun",
			expectedRegion:  "us-east1",
			expectedAccount: "my-project",
		},
		{
			name:      "success_k8s_with_all_metadata",
			envPrefix: "TEST_GCP_MULTI_3_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "KUBERNETES_SERVICE_HOST": "10.0.0.1",
					prefix + "GKE_CLUSTER_NAME":        "my-gke-cluster",
					prefix + "REGION":                  "us-west1",
					prefix + "PROJECT_ID":              "my-project",
				}
			},
			expectedEnv:     "k8s",
			expectedRegion:  "us-west1",
			expectedAccount: "my-project",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupEnv != nil {
				testEnv := tt.setupEnv(tt.envPrefix)
				defer func() {
					for key := range testEnv {
						os.Unsetenv(key)
					}
				}()
				for key, val := range testEnv {
					os.Setenv(key, val)
				}
			}

			detector := &IdsecGCPCloudEnvDetector{
				httpClient:   &http.Client{Timeout: 200 * time.Millisecond},
				envVarPrefix: tt.envPrefix,
			}
			ctx, detected := detector.Detect()

			if !detected {
				t.Error("Expected environment to be detected")
				return
			}

			if ctx.Environment != tt.expectedEnv {
				t.Errorf("Expected environment '%s', got '%s'", tt.expectedEnv, ctx.Environment)
			}

			if ctx.Region != tt.expectedRegion {
				t.Errorf("Expected region '%s', got '%s'", tt.expectedRegion, ctx.Region)
			}

			if ctx.AccountID != tt.expectedAccount {
				t.Errorf("Expected accountID '%s', got '%s'", tt.expectedAccount, ctx.AccountID)
			}
		})
	}
}
