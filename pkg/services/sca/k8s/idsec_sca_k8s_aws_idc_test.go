package k8s

import (
	"fmt"
	"os"
	"strings"
	"testing"

	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

func TestIsAWSIDCPermissionSetRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		roleID string
		want   bool
	}{
		{
			roleID: "arn:aws:sso:::permissionSet/ssoins-abc/ps-def",
			want:   true,
		},
		{
			roleID: "arn:aws:iam::123456789012:role/k8s_custom_role",
			want:   false,
		},
		{roleID: "", want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.roleID, func(t *testing.T) {
			t.Parallel()
			if got := IsAWSIDCPermissionSetRole(tt.roleID); got != tt.want {
				t.Fatalf("IsAWSIDCPermissionSetRole(%q) = %v, want %v", tt.roleID, got, tt.want)
			}
		})
	}
}

func TestNeedsAWSIDCDeviceRegistration(t *testing.T) {
	t.Parallel()

	valid := &k8smodels.IdsecSCAK8sElevateResult{
		RoleID:      "arn:aws:sso:::permissionSet/ssoins-abc/ps-def",
		RoleName:    "MyPermissionSet",
		WorkspaceID: "201316147283",
		ClientDetails: &k8smodels.IdsecSCAK8sElevateClientDetails{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			StartURL:     "https://d-abc.awsapps.com/start",
			SSORegion:    "us-east-1",
		},
	}

	tests := []struct {
		name   string
		result *k8smodels.IdsecSCAK8sElevateResult
		want   bool
	}{
		{name: "valid permission set", result: valid, want: true},
		{name: "nil result", result: nil, want: false},
		{
			name: "iam role arn",
			result: &k8smodels.IdsecSCAK8sElevateResult{
				RoleID: "arn:aws:iam::123:role/foo",
				ClientDetails: &k8smodels.IdsecSCAK8sElevateClientDetails{
					ClientID: "x", ClientSecret: "y", StartURL: "z", SSORegion: "us-east-1",
				},
			},
			want: false,
		},
		{
			name: "missing sso region",
			result: &k8smodels.IdsecSCAK8sElevateResult{
				RoleID: valid.RoleID,
				ClientDetails: &k8smodels.IdsecSCAK8sElevateClientDetails{
					ClientID: "x", ClientSecret: "y", StartURL: "z",
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := NeedsAWSIDCDeviceRegistration(tt.result); got != tt.want {
				t.Fatalf("NeedsAWSIDCDeviceRegistration() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateAWSIDCDeviceRegistration(t *testing.T) {
	t.Parallel()

	valid := &k8smodels.IdsecSCAK8sElevateResult{
		WorkspaceID: "201316147283",
		RoleID:      "arn:aws:sso:::permissionSet/ssoins-abc/ps-def",
		RoleName:    "MyPermissionSet",
		ClientDetails: &k8smodels.IdsecSCAK8sElevateClientDetails{
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			StartURL:     "https://d-abc.awsapps.com/start",
			SSORegion:    "us-east-1",
		},
	}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		if err := ValidateAWSIDCDeviceRegistration(valid); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("iam role skips validation", func(t *testing.T) {
		t.Parallel()
		err := ValidateAWSIDCDeviceRegistration(&k8smodels.IdsecSCAK8sElevateResult{
			RoleID: "arn:aws:iam::123:role/foo",
		})
		if err != nil {
			t.Fatalf("unexpected error for IAM role: %v", err)
		}
	})

	t.Run("permission set missing fields fails fast", func(t *testing.T) {
		t.Parallel()
		err := ValidateAWSIDCDeviceRegistration(&k8smodels.IdsecSCAK8sElevateResult{
			RoleID: "arn:aws:sso:::permissionSet/ssoins-abc/ps-def",
		})
		if err == nil {
			t.Fatal("expected validation error")
		}
		if !strings.Contains(err.Error(), "missing:") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("permission set accepts ssoRegion fallback", func(t *testing.T) {
		t.Parallel()
		err := ValidateAWSIDCDeviceRegistration(&k8smodels.IdsecSCAK8sElevateResult{
			WorkspaceID: "201316147283",
			RoleID:      "arn:aws:sso:::permissionSet/ssoins-abc/ps-def",
			RoleName:    "MyPermissionSet",
			ClientDetails: &k8smodels.IdsecSCAK8sElevateClientDetails{
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				StartURL:     "https://d-abc.awsapps.com/start",
				SSORegion:    "us-east-1",
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestMarshalAWSAccessCredentials(t *testing.T) {
	t.Parallel()

	encoded, err := MarshalAWSAccessCredentials(&k8smodels.IdsecSCAK8sAWSAccessCredentials{
		AWSAccessKey:       "AKIA",
		AWSSecretAccessKey: "secret",
		AWSSessionToken:    "token",
	})
	if err != nil {
		t.Fatalf("MarshalAWSAccessCredentials: %v", err)
	}
	if encoded == "" {
		t.Fatal("expected non-empty encoded credentials")
	}
}

// TestDebugAWSIDCDeviceAuthorization exercises the live AWS IDC device-registration
// flow using elevate response fixtures. Run from VS Code via launch config
// "AWS IDC Device Auth (SDK)" (sets IDSEC_DEBUG_AWS_IDC=1).
func TestDebugAWSIDCDeviceAuthorization(t *testing.T) {
	if os.Getenv("IDSEC_DEBUG_AWS_IDC") != "1" {
		t.Skip("set IDSEC_DEBUG_AWS_IDC=1 to run live AWS IDC device authorization")
	}

	elevateResult, err := debugAWSIDCElevateResultFromEnv()
	if err != nil {
		t.Fatalf("debug fixture: %v", err)
	}
	if !NeedsAWSIDCDeviceRegistration(elevateResult) {
		t.Fatal("debug elevate fixture should require AWS IDC device registration")
	}

	creds, _, _, _, err := EnsureAWSIDCAccessCredentials(elevateResult, true, nil)
	if err != nil {
		t.Fatalf("EnsureAWSIDCAccessCredentials: %v", err)
	}
	if creds.AWSAccessKey == "" || creds.AWSSecretAccessKey == "" {
		t.Fatal("expected non-empty STS credentials from GetRoleCredentials")
	}
	t.Logf("obtained AWS STS credentials (access key prefix %s…)", creds.AWSAccessKey[:min(len(creds.AWSAccessKey), 4)])
}

func debugAWSIDCElevateResultFromEnv() (*k8smodels.IdsecSCAK8sElevateResult, error) {
	required := map[string]string{
		"IDSEC_DEBUG_AWS_IDC_CLIENT_ID":     os.Getenv("IDSEC_DEBUG_AWS_IDC_CLIENT_ID"),
		"IDSEC_DEBUG_AWS_IDC_CLIENT_SECRET": os.Getenv("IDSEC_DEBUG_AWS_IDC_CLIENT_SECRET"),
		"IDSEC_DEBUG_AWS_IDC_START_URL":     os.Getenv("IDSEC_DEBUG_AWS_IDC_START_URL"),
		"IDSEC_DEBUG_AWS_IDC_SSO_REGION":    os.Getenv("IDSEC_DEBUG_AWS_IDC_SSO_REGION"),
		"IDSEC_DEBUG_AWS_IDC_ROLE_NAME":     os.Getenv("IDSEC_DEBUG_AWS_IDC_ROLE_NAME"),
		"IDSEC_DEBUG_AWS_IDC_WORKSPACE_ID":  os.Getenv("IDSEC_DEBUG_AWS_IDC_WORKSPACE_ID"),
		"IDSEC_DEBUG_AWS_IDC_ROLE_ID":       os.Getenv("IDSEC_DEBUG_AWS_IDC_ROLE_ID"),
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("%s is required for live debug test", name)
		}
	}

	return &k8smodels.IdsecSCAK8sElevateResult{
		WorkspaceID: strings.TrimSpace(required["IDSEC_DEBUG_AWS_IDC_WORKSPACE_ID"]),
		RoleID:      strings.TrimSpace(required["IDSEC_DEBUG_AWS_IDC_ROLE_ID"]),
		RoleName:    strings.TrimSpace(required["IDSEC_DEBUG_AWS_IDC_ROLE_NAME"]),
		ClientDetails: &k8smodels.IdsecSCAK8sElevateClientDetails{
			ClientID:     strings.TrimSpace(required["IDSEC_DEBUG_AWS_IDC_CLIENT_ID"]),
			ClientSecret: strings.TrimSpace(required["IDSEC_DEBUG_AWS_IDC_CLIENT_SECRET"]),
			StartURL:     strings.TrimSpace(required["IDSEC_DEBUG_AWS_IDC_START_URL"]),
			SSORegion:    strings.TrimSpace(required["IDSEC_DEBUG_AWS_IDC_SSO_REGION"]),
		},
	}, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
