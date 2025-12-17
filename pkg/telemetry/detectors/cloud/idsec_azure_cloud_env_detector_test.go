package cloud

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestNewIdsecAzureCloudDetector(t *testing.T) {
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

			detector := NewIdsecAzureCloudDetector()

			if detector == nil {
				t.Error("Expected non-nil detector")
			}

			if _, ok := detector.(*IdsecAzureCloudEnvDetector); !ok && tt.expected {
				t.Error("Expected detector to be of type *IdsecAzureCloudEnvDetector")
			}

			azureDetector := detector.(*IdsecAzureCloudEnvDetector)
			if azureDetector.httpClient == nil {
				t.Error("Expected non-nil httpClient")
			}

			if azureDetector.httpClient.Timeout != 200*time.Millisecond {
				t.Errorf("Expected timeout of 200ms, got %v", azureDetector.httpClient.Timeout)
			}
		})
	}
}

func TestIdsecAzureCloudEnvDetector_Detect(t *testing.T) {
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
			envPrefix: "TEST_AZURE_FUNC_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "FUNCTIONS_WORKER_RUNTIME": "node",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "azure",
			expectedEnv:       "functions",
			expectedRegion:    "unknown",
			expectedAccountID: "unknown",
		},
		{
			name:      "success_detects_appservice_with_instance_id",
			envPrefix: "TEST_AZURE_APP_INST_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "WEBSITE_INSTANCE_ID": "12345",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "azure",
			expectedEnv:       "appservice",
			expectedRegion:    "unknown",
			expectedAccountID: "unknown",
		},
		{
			name:      "success_detects_appservice_with_site_name",
			envPrefix: "TEST_AZURE_APP_NAME_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "WEBSITE_SITE_NAME": "my-app",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "azure",
			expectedEnv:       "appservice",
			expectedRegion:    "unknown",
			expectedAccountID: "unknown",
		},
		{
			name:      "success_detects_appservice_with_both_indicators",
			envPrefix: "TEST_AZURE_APP_BOTH_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "WEBSITE_INSTANCE_ID": "12345",
					prefix + "WEBSITE_SITE_NAME":   "my-app",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "azure",
			expectedEnv:       "appservice",
			expectedRegion:    "unknown",
			expectedAccountID: "unknown",
		},
		{
			name:      "success_detects_kubernetes_with_service_host",
			envPrefix: "TEST_AZURE_K8S_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "KUBERNETES_SERVICE_HOST": "10.0.0.1",
					prefix + "AKS_CLUSTER_NAME":        "my-aks-cluster",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "azure",
			expectedEnv:       "k8s",
			expectedRegion:    "unknown",
			expectedAccountID: "unknown",
		},
		{
			name:      "success_not_detected_no_azure_indicators",
			envPrefix: "TEST_AZURE_NO_INDICATORS_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{}
			},
			expectedDetected: false,
		},
		{
			name:      "success_functions_with_region_fallback",
			envPrefix: "TEST_AZURE_FUNC_REGION_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "FUNCTIONS_WORKER_RUNTIME": "dotnet",
					prefix + "AZURE_REGION":             "eastus",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "azure",
			expectedEnv:       "functions",
			expectedRegion:    "eastus",
			expectedAccountID: "unknown",
		},
		{
			name:      "success_appservice_with_subscription_id_fallback",
			envPrefix: "TEST_AZURE_APP_SUB_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "WEBSITE_INSTANCE_ID":   "12345",
					prefix + "AZURE_SUBSCRIPTION_ID": "sub-123",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "azure",
			expectedEnv:       "appservice",
			expectedRegion:    "unknown",
			expectedAccountID: "sub-123",
		},
		{
			name:      "success_k8s_with_region_name_fallback",
			envPrefix: "TEST_AZURE_K8S_REGION_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "KUBERNETES_SERVICE_HOST": "10.0.0.1",
					prefix + "AKS_CLUSTER_NAME":        "my-aks-cluster",
					prefix + "REGION_NAME":             "westus2",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "azure",
			expectedEnv:       "k8s",
			expectedRegion:    "westus2",
			expectedAccountID: "unknown",
		},
		{
			name:      "success_functions_priority_over_appservice",
			envPrefix: "TEST_AZURE_FUNC_PRIORITY_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "FUNCTIONS_WORKER_RUNTIME": "python",
					prefix + "WEBSITE_INSTANCE_ID":      "12345",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "azure",
			expectedEnv:       "functions",
			expectedRegion:    "unknown",
			expectedAccountID: "unknown",
		},
		{
			name:      "success_appservice_priority_over_k8s",
			envPrefix: "TEST_AZURE_APP_PRIORITY_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "WEBSITE_INSTANCE_ID":     "12345",
					prefix + "KUBERNETES_SERVICE_HOST": "10.0.0.1",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "azure",
			expectedEnv:       "appservice",
			expectedRegion:    "unknown",
			expectedAccountID: "unknown",
		},
		{
			name:      "success_location_fallback_priority",
			envPrefix: "TEST_AZURE_LOCATION_PRIORITY_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "FUNCTIONS_WORKER_RUNTIME": "java",
					prefix + "LOCATION":                 "northeurope",
					prefix + "REGION_NAME":              "westus",
					prefix + "AZURE_REGION":             "eastus",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "azure",
			expectedEnv:       "functions",
			expectedRegion:    "eastus",
			expectedAccountID: "unknown",
		},
		{
			name:      "success_subscription_id_fallback_priority",
			envPrefix: "TEST_AZURE_SUBSCRIPTION_PRIORITY_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "WEBSITE_INSTANCE_ID":   "12345",
					prefix + "SUBSCRIPTION_ID":       "sub-456",
					prefix + "AZURE_SUBSCRIPTION_ID": "sub-123",
				}
			},
			expectedDetected:  true,
			expectedProvider:  "azure",
			expectedEnv:       "appservice",
			expectedRegion:    "unknown",
			expectedAccountID: "sub-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment - no need to clear unprefixed vars anymore
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

			detector := &IdsecAzureCloudEnvDetector{
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

func TestIdsecAzureCloudEnvDetector_detectAzureIMDS(t *testing.T) {
	tests := []struct {
		name               string
		mockServer         func() *httptest.Server
		expectedOK         bool
		expectedProvider   string
		expectedEnv        string
		expectedRegion     string
		expectedAccountID  string
		expectedInstanceID string
	}{
		{
			name: "success_detects_vm_from_imds",
			mockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Metadata") != "true" {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					response := map[string]interface{}{
						"compute": map[string]interface{}{
							"location":          "eastus",
							"vmId":              "vm-12345",
							"subscriptionId":    "sub-67890",
							"resourceGroupName": "my-resource-group",
						},
					}
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(response)
				}))
			},
			expectedOK:         true,
			expectedProvider:   "azure",
			expectedEnv:        "vm",
			expectedRegion:     "eastus",
			expectedAccountID:  "sub-67890",
			expectedInstanceID: "vm-12345",
		},
		{
			name: "error_imds_endpoint_not_reachable",
			mockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}))
			},
			expectedOK: false,
		},
		{
			name: "error_missing_metadata_header",
			mockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Header.Get("Metadata") != "true" {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					w.WriteHeader(http.StatusOK)
				}))
			},
			expectedOK: false,
		},
		{
			name: "error_invalid_json_response",
			mockServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("invalid json"))
				}))
			},
			expectedOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := tt.mockServer()
			defer server.Close()

			detector := NewIdsecAzureCloudDetector()
			azureDetector := detector.(*IdsecAzureCloudEnvDetector)
			// Extract host:port from server.URL (e.g., "http://127.0.0.1:12345" -> "127.0.0.1:12345")
			azureDetector.azureMetadataIpAddr = server.URL[7:] // Remove "http://"

			ctx, ok := azureDetector.detectAzureIMDS()

			if ok != tt.expectedOK {
				t.Errorf("Expected ok to be %v, got %v", tt.expectedOK, ok)
			}

			if !ok {
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

			if ctx.InstanceID != tt.expectedInstanceID {
				t.Errorf("Expected instanceID '%s', got '%s'", tt.expectedInstanceID, ctx.InstanceID)
			}
		})
	}
}

func TestIdsecAzureCloudEnvDetector_isAKS(t *testing.T) {
	tests := []struct {
		name      string
		envPrefix string
		setupEnv  func(prefix string) map[string]string
		expected  bool
	}{
		{
			name:      "success_detected_with_service_host",
			envPrefix: "TEST_AZURE_K8S_1_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "KUBERNETES_SERVICE_HOST": "10.0.0.1",
				}
			},
			expected: false, // Will be false unless AKS-specific indicators are present
		},
		{
			name:      "success_detected_with_aks_cluster_name",
			envPrefix: "TEST_AZURE_K8S_AKS_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "KUBERNETES_SERVICE_HOST": "10.0.0.1",
					prefix + "AKS_CLUSTER_NAME":        "my-aks-cluster",
				}
			},
			expected: true,
		},
		{
			name:      "success_detected_with_azure_container_instance_id",
			envPrefix: "TEST_AZURE_K8S_CONTAINER_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "KUBERNETES_SERVICE_HOST":     "10.0.0.1",
					prefix + "AZURE_CONTAINER_INSTANCE_ID": "container-123",
				}
			},
			expected: true,
		},
		{
			name:      "success_not_detected_without_indicators",
			envPrefix: "TEST_AZURE_K8S_2_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{}
			},
			expected: false,
		},
		{
			name:      "success_not_detected_with_empty_service_host",
			envPrefix: "TEST_AZURE_K8S_3_",
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

			detector := &IdsecAzureCloudEnvDetector{
				httpClient:   &http.Client{Timeout: 200 * time.Millisecond},
				envVarPrefix: tt.envPrefix,
			}
			result := detector.isAKS()

			if result != tt.expected {
				t.Errorf("Expected isAKS() to return %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestIdsecAzureCloudEnvDetector_fallbackRegion(t *testing.T) {
	tests := []struct {
		name           string
		envPrefix      string
		setupEnv       func(prefix string) map[string]string
		expectedRegion string
	}{
		{
			name:      "success_returns_azure_region",
			envPrefix: "TEST_AZURE_REGION_1_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "AZURE_REGION": "eastus",
				}
			},
			expectedRegion: "eastus",
		},
		{
			name:      "success_returns_region_name_when_azure_region_not_set",
			envPrefix: "TEST_AZURE_REGION_2_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "REGION_NAME": "westus",
				}
			},
			expectedRegion: "westus",
		},
		{
			name:      "success_returns_location_when_others_not_set",
			envPrefix: "TEST_AZURE_REGION_3_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "LOCATION": "northeurope",
				}
			},
			expectedRegion: "northeurope",
		},
		{
			name:      "success_prefers_azure_region_over_others",
			envPrefix: "TEST_AZURE_REGION_4_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "AZURE_REGION": "eastus",
					prefix + "REGION_NAME":  "westus",
					prefix + "LOCATION":     "northeurope",
				}
			},
			expectedRegion: "eastus",
		},
		{
			name:      "success_prefers_region_name_over_location",
			envPrefix: "TEST_AZURE_REGION_5_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "REGION_NAME": "westus2",
					prefix + "LOCATION":    "southeurope",
				}
			},
			expectedRegion: "westus2",
		},
		{
			name:      "success_returns_unknown_when_no_env_vars",
			envPrefix: "TEST_AZURE_REGION_6_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{}
			},
			expectedRegion: "unknown",
		},
		{
			name:      "success_returns_unknown_when_empty_env_vars",
			envPrefix: "TEST_AZURE_REGION_7_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "AZURE_REGION": "",
					prefix + "REGION_NAME":  "",
					prefix + "LOCATION":     "",
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

			detector := &IdsecAzureCloudEnvDetector{envVarPrefix: tt.envPrefix}
			region := detector.fallbackRegion()

			if region != tt.expectedRegion {
				t.Errorf("Expected region '%s', got '%s'", tt.expectedRegion, region)
			}
		})
	}
}

func TestIdsecAzureCloudEnvDetector_fallbackSubscriptionID(t *testing.T) {
	tests := []struct {
		name                   string
		envPrefix              string
		setupEnv               func(prefix string) map[string]string
		expectedSubscriptionID string
	}{
		{
			name:      "success_returns_azure_subscription_id",
			envPrefix: "TEST_AZURE_SUB_1_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "AZURE_SUBSCRIPTION_ID": "sub-123",
				}
			},
			expectedSubscriptionID: "sub-123",
		},
		{
			name:      "success_returns_subscription_id_when_azure_subscription_id_not_set",
			envPrefix: "TEST_AZURE_SUB_2_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "SUBSCRIPTION_ID": "sub-456",
				}
			},
			expectedSubscriptionID: "sub-456",
		},
		{
			name:      "success_prefers_azure_subscription_id_over_subscription_id",
			envPrefix: "TEST_AZURE_SUB_3_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "AZURE_SUBSCRIPTION_ID": "sub-111",
					prefix + "SUBSCRIPTION_ID":       "sub-222",
				}
			},
			expectedSubscriptionID: "sub-111",
		},
		{
			name:      "success_returns_unknown_when_no_env_vars",
			envPrefix: "TEST_AZURE_SUB_4_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{}
			},
			expectedSubscriptionID: "unknown",
		},
		{
			name:      "success_returns_unknown_when_empty_env_vars",
			envPrefix: "TEST_AZURE_SUB_5_",
			setupEnv: func(prefix string) map[string]string {
				return map[string]string{
					prefix + "AZURE_SUBSCRIPTION_ID": "",
					prefix + "SUBSCRIPTION_ID":       "",
				}
			},
			expectedSubscriptionID: "unknown",
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

			detector := &IdsecAzureCloudEnvDetector{envVarPrefix: tt.envPrefix}
			subscriptionID := detector.fallbackSubscriptionID()

			if subscriptionID != tt.expectedSubscriptionID {
				t.Errorf("Expected subscriptionID '%s', got '%s'", tt.expectedSubscriptionID, subscriptionID)
			}
		})
	}
}

func TestIdsecAzureCloudEnvDetector_Timeout(t *testing.T) {
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

			detector := NewIdsecAzureCloudDetector()
			azureDetector := detector.(*IdsecAzureCloudEnvDetector)

			if azureDetector.httpClient.Timeout != tt.expectedTimeout {
				t.Errorf("Expected timeout of %v, got %v", tt.expectedTimeout, azureDetector.httpClient.Timeout)
			}
		})
	}
}
