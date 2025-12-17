package cloud

import (
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/telemetry/detectors"
)

func TestNewIdsecCloudEnvDetector(t *testing.T) {
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

			detector := NewIdsecCloudEnvDetector()

			if detector == nil {
				t.Error("Expected non-nil detector")
			}

			if _, ok := detector.(*IdsecCloudEnvDetector); !ok && tt.expected {
				t.Error("Expected detector to be of type *IdsecCloudEnvDetector")
			}

			cloudDetector := detector.(*IdsecCloudEnvDetector)
			if cloudDetector.detectors == nil {
				t.Error("Expected non-nil detectors slice")
			}

			if len(cloudDetector.detectors) != 3 {
				t.Errorf("Expected 3 detectors, got %d", len(cloudDetector.detectors))
			}
		})
	}
}

func TestIdsecCloudEnvDetector_Detect(t *testing.T) {
	tests := []struct {
		name               string
		mockDetectors      []detectors.IdsecEnvDetector
		expectedDetected   bool
		expectedProvider   string
		expectedEnv        string
		expectedRegion     string
		expectedAccountID  string
		expectedInstanceID string
	}{
		{
			name: "success_first_detector_detects_aws",
			mockDetectors: []detectors.IdsecEnvDetector{
				&mockDetector{
					shouldDetect: true,
					ctx: &detectors.IdsecEnvContext{
						Provider:    "aws",
						Environment: "ec2",
						Region:      "us-east-1",
						AccountID:   "123456789012",
						InstanceID:  "i-1234567890abcdef0",
					},
				},
				&mockDetector{shouldDetect: false},
				&mockDetector{shouldDetect: false},
			},
			expectedDetected:   true,
			expectedProvider:   "aws",
			expectedEnv:        "ec2",
			expectedRegion:     "us-east-1",
			expectedAccountID:  "123456789012",
			expectedInstanceID: "i-1234567890abcdef0",
		},
		{
			name: "success_second_detector_detects_azure",
			mockDetectors: []detectors.IdsecEnvDetector{
				&mockDetector{shouldDetect: false},
				&mockDetector{
					shouldDetect: true,
					ctx: &detectors.IdsecEnvContext{
						Provider:    "azure",
						Environment: "vm",
						Region:      "eastus",
						AccountID:   "sub-12345",
						InstanceID:  "vm-67890",
					},
				},
				&mockDetector{shouldDetect: false},
			},
			expectedDetected:   true,
			expectedProvider:   "azure",
			expectedEnv:        "vm",
			expectedRegion:     "eastus",
			expectedAccountID:  "sub-12345",
			expectedInstanceID: "vm-67890",
		},
		{
			name: "success_third_detector_detects_gcp",
			mockDetectors: []detectors.IdsecEnvDetector{
				&mockDetector{shouldDetect: false},
				&mockDetector{shouldDetect: false},
				&mockDetector{
					shouldDetect: true,
					ctx: &detectors.IdsecEnvContext{
						Provider:    "gcp",
						Environment: "gce",
						Region:      "us-central1",
						AccountID:   "project-123",
						InstanceID:  "instance-456",
					},
				},
			},
			expectedDetected:   true,
			expectedProvider:   "gcp",
			expectedEnv:        "gce",
			expectedRegion:     "us-central1",
			expectedAccountID:  "project-123",
			expectedInstanceID: "instance-456",
		},
		{
			name: "success_no_detector_detects_returns_on_premise",
			mockDetectors: []detectors.IdsecEnvDetector{
				&mockDetector{shouldDetect: false},
				&mockDetector{shouldDetect: false},
				&mockDetector{shouldDetect: false},
			},
			expectedDetected:   false,
			expectedProvider:   "on-premise",
			expectedEnv:        "on-premise",
			expectedRegion:     "unknown",
			expectedAccountID:  "unknown",
			expectedInstanceID: "unknown",
		},
		{
			name: "success_first_detector_priority_over_others",
			mockDetectors: []detectors.IdsecEnvDetector{
				&mockDetector{
					shouldDetect: true,
					ctx: &detectors.IdsecEnvContext{
						Provider:    "aws",
						Environment: "ecs",
						Region:      "us-west-2",
						AccountID:   "111111111111",
						InstanceID:  "task-123",
					},
				},
				&mockDetector{
					shouldDetect: true,
					ctx: &detectors.IdsecEnvContext{
						Provider:    "azure",
						Environment: "functions",
						Region:      "westus",
						AccountID:   "sub-99999",
						InstanceID:  "func-456",
					},
				},
				&mockDetector{
					shouldDetect: true,
					ctx: &detectors.IdsecEnvContext{
						Provider:    "gcp",
						Environment: "cloudrun",
						Region:      "europe-west1",
						AccountID:   "project-789",
						InstanceID:  "run-999",
					},
				},
			},
			expectedDetected:   true,
			expectedProvider:   "aws",
			expectedEnv:        "ecs",
			expectedRegion:     "us-west-2",
			expectedAccountID:  "111111111111",
			expectedInstanceID: "task-123",
		},
		{
			name:               "success_empty_detectors_slice_returns_on_premise",
			mockDetectors:      []detectors.IdsecEnvDetector{},
			expectedDetected:   false,
			expectedProvider:   "on-premise",
			expectedEnv:        "on-premise",
			expectedRegion:     "unknown",
			expectedAccountID:  "unknown",
			expectedInstanceID: "unknown",
		},
		{
			name: "success_partial_context_from_detector",
			mockDetectors: []detectors.IdsecEnvDetector{
				&mockDetector{
					shouldDetect: true,
					ctx: &detectors.IdsecEnvContext{
						Provider:    "aws",
						Environment: "lambda",
						Region:      "unknown",
						AccountID:   "unknown",
						InstanceID:  "unknown",
					},
				},
			},
			expectedDetected:   true,
			expectedProvider:   "aws",
			expectedEnv:        "lambda",
			expectedRegion:     "unknown",
			expectedAccountID:  "unknown",
			expectedInstanceID: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := &IdsecCloudEnvDetector{
				detectors: tt.mockDetectors,
			}

			ctx, detected := detector.Detect()

			if detected != tt.expectedDetected {
				t.Errorf("Expected detected to be %v, got %v", tt.expectedDetected, detected)
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

func TestIdsecCloudEnvDetector_DetectorOrder(t *testing.T) {
	tests := []struct {
		name             string
		setupDetectors   func() []detectors.IdsecEnvDetector
		expectedProvider string
	}{
		{
			name: "success_aws_detector_checked_first",
			setupDetectors: func() []detectors.IdsecEnvDetector {
				return []detectors.IdsecEnvDetector{
					&mockDetector{
						shouldDetect: true,
						ctx: &detectors.IdsecEnvContext{
							Provider:    "aws",
							Environment: "ec2",
						},
					},
					&mockDetector{
						shouldDetect: true,
						ctx: &detectors.IdsecEnvContext{
							Provider:    "azure",
							Environment: "vm",
						},
					},
				}
			},
			expectedProvider: "aws",
		},
		{
			name: "success_azure_detector_checked_when_aws_fails",
			setupDetectors: func() []detectors.IdsecEnvDetector {
				return []detectors.IdsecEnvDetector{
					&mockDetector{shouldDetect: false},
					&mockDetector{
						shouldDetect: true,
						ctx: &detectors.IdsecEnvContext{
							Provider:    "azure",
							Environment: "appservice",
						},
					},
				}
			},
			expectedProvider: "azure",
		},
		{
			name: "success_gcp_detector_checked_when_others_fail",
			setupDetectors: func() []detectors.IdsecEnvDetector {
				return []detectors.IdsecEnvDetector{
					&mockDetector{shouldDetect: false},
					&mockDetector{shouldDetect: false},
					&mockDetector{
						shouldDetect: true,
						ctx: &detectors.IdsecEnvContext{
							Provider:    "gcp",
							Environment: "functions",
						},
					},
				}
			},
			expectedProvider: "gcp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detector := &IdsecCloudEnvDetector{
				detectors: tt.setupDetectors(),
			}

			ctx, detected := detector.Detect()

			if !detected {
				t.Error("Expected environment to be detected")
				return
			}

			if ctx.Provider != tt.expectedProvider {
				t.Errorf("Expected provider '%s', got '%s'", tt.expectedProvider, ctx.Provider)
			}
		})
	}
}

func TestIdsecCloudEnvDetector_DetectorCount(t *testing.T) {
	tests := []struct {
		name          string
		expectedCount int
		validateFunc  func(t *testing.T, detectors []detectors.IdsecEnvDetector)
	}{
		{
			name:          "success_has_three_detectors",
			expectedCount: 3,
			validateFunc: func(t *testing.T, detectors []detectors.IdsecEnvDetector) {
				if len(detectors) != 3 {
					t.Errorf("Expected 3 detectors, got %d", len(detectors))
				}

				// Verify detector types (AWS, Azure, GCP)
				if _, ok := detectors[0].(*IdsecAWSCloudEnvDetector); !ok {
					t.Error("Expected first detector to be AWS detector")
				}

				if _, ok := detectors[1].(*IdsecAzureCloudEnvDetector); !ok {
					t.Error("Expected second detector to be Azure detector")
				}

				if _, ok := detectors[2].(*IdsecGCPCloudEnvDetector); !ok {
					t.Error("Expected third detector to be GCP detector")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			detector := NewIdsecCloudEnvDetector()
			cloudDetector := detector.(*IdsecCloudEnvDetector)

			if tt.validateFunc != nil {
				tt.validateFunc(t, cloudDetector.detectors)
			}
		})
	}
}

// mockDetector is a test helper for mocking cloud environment detectors
type mockDetector struct {
	shouldDetect bool
	ctx          *detectors.IdsecEnvContext
}

func (m *mockDetector) Detect() (*detectors.IdsecEnvContext, bool) {
	if m.shouldDetect {
		return m.ctx, true
	}
	return &detectors.IdsecEnvContext{}, false
}
