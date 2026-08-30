package models_test

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	applicationsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/applications/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/validation"
)

// baseAuthMethod satisfies every unconditional rule, so each case below only exercises the
// conditional one it sets up.
func baseAuthMethod() *applicationsmodels.IdsecPCloudCreateApplicationAuthMethod {
	return &applicationsmodels.IdsecPCloudCreateApplicationAuthMethod{
		AppID:     "my-app",
		AuthType:  applicationsmodels.ApplicationAuthMethodHash,
		AuthValue: "myhashvalue",
	}
}

func strPtr(s string) *string { return &s }

// withKubernetesExtras fills the four fields required by the Kubernetes auth type.
func withKubernetesExtras(m *applicationsmodels.IdsecPCloudCreateApplicationAuthMethod) {
	m.Namespace = strPtr("default")
	m.Image = strPtr("myrepo/myimage:1.0")
	m.EnvVarName = strPtr("MY_VAR")
	m.EnvVarValue = strPtr("my-value")
}

// TestCreateApplicationAuthMethodValidation exercises the validate tags on the auth method creation
// request model; as struct tags, this test is their only guard.
func TestCreateApplicationAuthMethodValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*applicationsmodels.IdsecPCloudCreateApplicationAuthMethod)
		wantErr bool
	}{
		{
			name:   "supported_auth_type_is_accepted",
			mutate: func(m *applicationsmodels.IdsecPCloudCreateApplicationAuthMethod) {},
		},
		{
			name:    "unsupported_auth_type_is_rejected",
			mutate:  func(m *applicationsmodels.IdsecPCloudCreateApplicationAuthMethod) { m.AuthType = "invalid_type" },
			wantErr: true,
		},
		{
			name:    "missing_auth_type_is_rejected",
			mutate:  func(m *applicationsmodels.IdsecPCloudCreateApplicationAuthMethod) { m.AuthType = "" },
			wantErr: true,
		},
		{
			name:    "missing_app_id_is_rejected",
			mutate:  func(m *applicationsmodels.IdsecPCloudCreateApplicationAuthMethod) { m.AppID = "" },
			wantErr: true,
		},
		{
			name:    "missing_auth_value_is_rejected",
			mutate:  func(m *applicationsmodels.IdsecPCloudCreateApplicationAuthMethod) { m.AuthValue = "" },
			wantErr: true,
		},
		{
			// certificateattr identifies the application by certificate attributes, not a single value,
			// so it is the one type that does not need auth_value.
			name: "certificateattr_without_auth_value_is_accepted",
			mutate: func(m *applicationsmodels.IdsecPCloudCreateApplicationAuthMethod) {
				m.AuthType = applicationsmodels.ApplicationAuthMethodCertificateAttr
				m.AuthValue = ""
			},
		},
		{
			name: "kubernetes_without_extras_is_rejected",
			mutate: func(m *applicationsmodels.IdsecPCloudCreateApplicationAuthMethod) {
				m.AuthType = applicationsmodels.ApplicationAuthMethodKubernetes
			},
			wantErr: true,
		},
		{
			name: "kubernetes_with_all_extras_is_accepted",
			mutate: func(m *applicationsmodels.IdsecPCloudCreateApplicationAuthMethod) {
				m.AuthType = applicationsmodels.ApplicationAuthMethodKubernetes
				withKubernetesExtras(m)
			},
		},
		{
			name: "kubernetes_missing_one_extra_is_rejected",
			mutate: func(m *applicationsmodels.IdsecPCloudCreateApplicationAuthMethod) {
				m.AuthType = applicationsmodels.ApplicationAuthMethodKubernetes
				withKubernetesExtras(m)
				m.EnvVarValue = nil
			},
			wantErr: true,
		},
		{
			name: "kubernetes_extras_are_not_required_for_other_types",
			mutate: func(m *applicationsmodels.IdsecPCloudCreateApplicationAuthMethod) {
				m.AuthType = applicationsmodels.ApplicationAuthMethodPath
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			authMethod := baseAuthMethod()
			tc.mutate(authMethod)

			err := validation.ValidateStruct(authMethod)
			if tc.wantErr && err == nil {
				t.Fatalf("ValidateStruct(%+v) = nil, want an error", authMethod)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("ValidateStruct(%+v) = %v, want nil", authMethod, err)
			}
		})
	}
}

// TestEverySupportedAuthTypeIsAccepted tests that the oneof rule accepts every type the service supports.
func TestEverySupportedAuthTypeIsAccepted(t *testing.T) {
	t.Parallel()

	for _, authType := range applicationsmodels.ApplicationAuthMethodTypes {
		t.Run(authType, func(t *testing.T) {
			t.Parallel()

			authMethod := baseAuthMethod()
			authMethod.AuthType = authType
			switch authType {
			case applicationsmodels.ApplicationAuthMethodKubernetes:
				withKubernetesExtras(authMethod)
			case applicationsmodels.ApplicationAuthMethodCertificateAttr:
				authMethod.AuthValue = ""
			}

			if err := validation.ValidateStruct(authMethod); err != nil {
				t.Fatalf("ValidateStruct(auth_type=%q) = %v, want nil", authType, err)
			}
		})
	}
}

// TestAuthTypeOneofMatchesSupportedTypes tests that the oneof tag has not drifted from ApplicationAuthMethodTypes.
func TestAuthTypeOneofMatchesSupportedTypes(t *testing.T) {
	t.Parallel()

	field, ok := reflect.TypeOf(applicationsmodels.IdsecPCloudCreateApplicationAuthMethod{}).FieldByName("AuthType")
	if !ok {
		t.Fatal("AuthType field not found")
	}

	var tagged []string
	for _, rule := range strings.Split(field.Tag.Get("validate"), ",") {
		if param, found := strings.CutPrefix(rule, "oneof="); found {
			tagged = strings.Fields(param)
		}
	}
	if tagged == nil {
		t.Fatalf("AuthType has no oneof rule, validate tag is %q", field.Tag.Get("validate"))
	}

	want := append([]string(nil), applicationsmodels.ApplicationAuthMethodTypes...)
	sort.Strings(want)
	sort.Strings(tagged)
	if !reflect.DeepEqual(tagged, want) {
		t.Fatalf("oneof values = %v, want %v", tagged, want)
	}
}
