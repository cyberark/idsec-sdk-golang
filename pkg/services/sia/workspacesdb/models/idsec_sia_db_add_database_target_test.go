package models

import (
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/cyberark/idsec-sdk-golang/pkg/validation"
)

// The values the database target models advertise as accepted for their enum-backed fields.
const (
	targetPlatformChoices   = "AWS,AZURE,GCP,ON-PREMISE"
	targetAuthMethodChoices = "ad_ephemeral_user,local_ephemeral_user,rds_iam_authentication"
	targetFamilyChoices     = "MySQL,MSSQL,Postgres,MariaDB,DB2,Oracle,Mongo"
)

// choicesTag returns the `choices` struct-tag value of the named field on the
// given struct type, failing the test if the field or the tag is missing.
func choicesTag(t *testing.T, typ reflect.Type, fieldName string) string {
	t.Helper()
	field, ok := typ.FieldByName(fieldName)
	if !ok {
		t.Fatalf("field %q not found on %s", fieldName, typ.Name())
	}
	choices, ok := field.Tag.Lookup("choices")
	if !ok {
		t.Fatalf("field %q on %s has no `choices` tag", fieldName, typ.Name())
	}
	return choices
}

// slicesContainsChoice reports whether a comma-separated `choices` tag value
// contains the given member.
func slicesContainsChoice(choices, member string) bool {
	for _, c := range strings.Split(choices, ",") {
		if c == member {
			return true
		}
	}
	return false
}

// assertTargetChoices checks that a database target onboarding model offers only the platforms
// and auth methods that can actually be onboarded through the database-onboarding new API.
func assertTargetChoices(t *testing.T, targetType reflect.Type) {
	t.Helper()

	t.Run("platform", func(t *testing.T) {
		t.Parallel()
		got := choicesTag(t, targetType, "Platform")
		if got != targetPlatformChoices {
			t.Fatalf("Platform choices = %q, want %q", got, targetPlatformChoices)
		}
		for _, unsupported := range []string{"ATLAS", "SNOWFLAKE"} {
			if slicesContainsChoice(got, unsupported) {
				t.Fatalf("Platform choices %q must not offer %q", got, unsupported)
			}
		}
	})

	t.Run("auth_method", func(t *testing.T) {
		t.Parallel()
		got := choicesTag(t, targetType, "ConfiguredAuthMethodType")
		if got != targetAuthMethodChoices {
			t.Fatalf("ConfiguredAuthMethodType choices = %q, want %q", got, targetAuthMethodChoices)
		}
		if slicesContainsChoice(got, "atlas_ephemeral_user") {
			t.Fatalf("ConfiguredAuthMethodType choices %q must not offer %q", got, "atlas_ephemeral_user")
		}
	})
}

// TestAddDatabaseTargetChoices covers the values offered when onboarding a database target.
func TestAddDatabaseTargetChoices(t *testing.T) {
	t.Parallel()
	assertTargetChoices(t, reflect.TypeOf(IdsecSIADBAddDatabaseTarget{}))
}

// TestUpdateDatabaseTargetChoices covers the values offered when updating a database target,
// which are the same ones accepted when onboarding it.
func TestUpdateDatabaseTargetChoices(t *testing.T) {
	t.Parallel()
	assertTargetChoices(t, reflect.TypeOf(IdsecSIADBUpdateDatabaseTarget{}))
}

// TestDatabaseTargetsFilterFamilyChoices covers the families offered when listing database
// targets: only families that can be onboarded through the database-onboarding new API.
func TestDatabaseTargetsFilterFamilyChoices(t *testing.T) {
	t.Parallel()

	got := choicesTag(t, reflect.TypeOf(IdsecSIADBDatabaseTargetsFilter{}), "ProviderFamily")
	if got != targetFamilyChoices {
		t.Fatalf("ProviderFamily choices = %q, want %q", got, targetFamilyChoices)
	}
	for _, unsupported := range []string{"Unknown", "Cassandra"} {
		if slicesContainsChoice(got, unsupported) {
			t.Fatalf("ProviderFamily choices %q must not offer %q", got, unsupported)
		}
	}
}

// TestAddDatabaseChoicesUnchanged covers the deprecated onboarding model, which keeps accepting
// the ATLAS platform and the Atlas auth method.
func TestAddDatabaseChoicesUnchanged(t *testing.T) {
	t.Parallel()

	databaseType := reflect.TypeOf(IdsecSIADBAddDatabase{})
	if got := choicesTag(t, databaseType, "Platform"); !slicesContainsChoice(got, "ATLAS") {
		t.Errorf("IdsecSIADBAddDatabase.Platform choices = %q, want it to still offer ATLAS", got)
	}
	if got := choicesTag(t, databaseType, "ConfiguredAuthMethodType"); !slicesContainsChoice(got, "atlas_ephemeral_user") {
		t.Errorf("IdsecSIADBAddDatabase.ConfiguredAuthMethodType choices = %q, want it to still offer atlas_ephemeral_user", got)
	}
}

// validationCase mutates one field of an otherwise acceptable payload and states whether
// validating that payload is expected to fail.
type validationCase[T any] struct {
	name       string
	mutate     func(target *T)
	wantReject bool
}

func runValidationCases[T any](t *testing.T, newTarget func() *T, cases []validationCase[T]) {
	t.Helper()

	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			target := newTarget()
			testCase.mutate(target)

			err := validation.ValidateStruct(target)
			if testCase.wantReject && err == nil {
				t.Fatal("expected the payload to be rejected, got no error")
			}
			if !testCase.wantReject && err != nil {
				t.Fatalf("expected the payload to be accepted, got %v", err)
			}
		})
	}
}

// validAddDatabaseTarget returns the minimal payload accepted for onboarding, so each case can
// mutate exactly one field.
func validAddDatabaseTarget() *IdsecSIADBAddDatabaseTarget {
	return &IdsecSIADBAddDatabaseTarget{
		Name:                     "test-db",
		ProviderEngine:           EngineTypeMSSQLAWSRDS,
		ReadWriteEndpoint:        "db.example.com",
		ConfiguredAuthMethodType: "local_ephemeral_user",
		Port:                     1433,
	}
}

// TestAddDatabaseTargetValidation covers which onboarding payloads are accepted: mandatory
// fields must be present, text fields must not be padded with whitespace or exceed their
// length, endpoints must hold no whitespace at all and the port must be a valid one.
func TestAddDatabaseTargetValidation(t *testing.T) {
	t.Parallel()

	runValidationCases(t, validAddDatabaseTarget, []validationCase[IdsecSIADBAddDatabaseTarget]{
		{name: "minimal_payload", mutate: func(*IdsecSIADBAddDatabaseTarget) {}},
		{
			name:       "missing_name",
			mutate:     func(target *IdsecSIADBAddDatabaseTarget) { target.Name = "" },
			wantReject: true,
		},
		{
			name:       "blank_name",
			mutate:     func(target *IdsecSIADBAddDatabaseTarget) { target.Name = "   " },
			wantReject: true,
		},
		{
			name:       "name_with_leading_whitespace",
			mutate:     func(target *IdsecSIADBAddDatabaseTarget) { target.Name = " test-db" },
			wantReject: true,
		},
		{
			name:       "name_with_trailing_whitespace",
			mutate:     func(target *IdsecSIADBAddDatabaseTarget) { target.Name = "test-db " },
			wantReject: true,
		},
		{
			name:   "name_with_inner_whitespace",
			mutate: func(target *IdsecSIADBAddDatabaseTarget) { target.Name = "test db" },
		},
		{
			name:   "longest_allowed_name",
			mutate: func(target *IdsecSIADBAddDatabaseTarget) { target.Name = strings.Repeat("a", 256) },
		},
		{
			name:       "name_above_length_limit",
			mutate:     func(target *IdsecSIADBAddDatabaseTarget) { target.Name = strings.Repeat("a", 257) },
			wantReject: true,
		},
		{
			name:       "missing_read_write_endpoint",
			mutate:     func(target *IdsecSIADBAddDatabaseTarget) { target.ReadWriteEndpoint = "" },
			wantReject: true,
		},
		{
			name:       "read_write_endpoint_with_inner_whitespace",
			mutate:     func(target *IdsecSIADBAddDatabaseTarget) { target.ReadWriteEndpoint = "db .example.com" },
			wantReject: true,
		},
		{
			name:       "read_only_endpoint_with_trailing_whitespace",
			mutate:     func(target *IdsecSIADBAddDatabaseTarget) { target.ReadOnlyEndpoint = "ro.example.com " },
			wantReject: true,
		},
		{
			name:   "read_only_endpoint",
			mutate: func(target *IdsecSIADBAddDatabaseTarget) { target.ReadOnlyEndpoint = "ro.example.com" },
		},
		{
			name:       "domain_with_leading_whitespace",
			mutate:     func(target *IdsecSIADBAddDatabaseTarget) { target.Domain = " example.com" },
			wantReject: true,
		},
		{
			name: "organizational_unit_with_trailing_whitespace",
			mutate: func(target *IdsecSIADBAddDatabaseTarget) {
				target.DomainControllerOrganizationalUnit = "OU=db,DC=example,DC=com "
			},
			wantReject: true,
		},
		{
			name: "organizational_unit",
			mutate: func(target *IdsecSIADBAddDatabaseTarget) {
				target.DomainControllerOrganizationalUnit = "OU=db,DC=example,DC=com"
			},
		},
		{
			name:       "service_with_leading_whitespace",
			mutate:     func(target *IdsecSIADBAddDatabaseTarget) { target.Services = []string{"ORCL", " ORCL2"} },
			wantReject: true,
		},
		{
			name:   "services",
			mutate: func(target *IdsecSIADBAddDatabaseTarget) { target.Services = []string{"ORCL", "ORCL2"} },
		},
		{
			name:       "malformed_secret_id",
			mutate:     func(target *IdsecSIADBAddDatabaseTarget) { target.SecretID = "not-a-uuid" },
			wantReject: true,
		},
		{
			name:   "secret_id",
			mutate: func(target *IdsecSIADBAddDatabaseTarget) { target.SecretID = uuid.NewString() },
		},
		{
			name:   "lowest_allowed_port",
			mutate: func(target *IdsecSIADBAddDatabaseTarget) { target.Port = 1 },
		},
		{
			name:   "highest_allowed_port",
			mutate: func(target *IdsecSIADBAddDatabaseTarget) { target.Port = 65535 },
		},
		{
			name:   "omitted_port",
			mutate: func(target *IdsecSIADBAddDatabaseTarget) { target.Port = 0 },
		},
		{
			name:       "port_above_range",
			mutate:     func(target *IdsecSIADBAddDatabaseTarget) { target.Port = 70000 },
			wantReject: true,
		},
		{
			name:       "negative_port",
			mutate:     func(target *IdsecSIADBAddDatabaseTarget) { target.Port = -1 },
			wantReject: true,
		},
	})
}

// TestUpdateDatabaseTargetValidation covers which update payloads are accepted: every field is
// optional, but the ones that are supplied must satisfy the same constraints as when onboarding.
func TestUpdateDatabaseTargetValidation(t *testing.T) {
	t.Parallel()

	newTarget := func() *IdsecSIADBUpdateDatabaseTarget {
		return &IdsecSIADBUpdateDatabaseTarget{ID: uuid.NewString()}
	}

	runValidationCases(t, newTarget, []validationCase[IdsecSIADBUpdateDatabaseTarget]{
		{name: "no_field_to_update", mutate: func(*IdsecSIADBUpdateDatabaseTarget) {}},
		{
			name:   "new_name",
			mutate: func(target *IdsecSIADBUpdateDatabaseTarget) { target.NewName = "renamed-db" },
		},
		{
			name:       "blank_new_name",
			mutate:     func(target *IdsecSIADBUpdateDatabaseTarget) { target.NewName = " " },
			wantReject: true,
		},
		{
			name:       "new_name_with_trailing_whitespace",
			mutate:     func(target *IdsecSIADBUpdateDatabaseTarget) { target.NewName = "renamed-db " },
			wantReject: true,
		},
		{
			name:       "new_name_above_length_limit",
			mutate:     func(target *IdsecSIADBUpdateDatabaseTarget) { target.NewName = strings.Repeat("a", 257) },
			wantReject: true,
		},
		{
			name:       "name_with_leading_whitespace",
			mutate:     func(target *IdsecSIADBUpdateDatabaseTarget) { target.Name = " test-db" },
			wantReject: true,
		},
		{
			name:       "read_write_endpoint_with_inner_whitespace",
			mutate:     func(target *IdsecSIADBUpdateDatabaseTarget) { target.ReadWriteEndpoint = "db .example.com" },
			wantReject: true,
		},
		{
			name:   "read_write_endpoint",
			mutate: func(target *IdsecSIADBUpdateDatabaseTarget) { target.ReadWriteEndpoint = "db.example.com" },
		},
		{
			name: "organizational_unit_with_leading_whitespace",
			mutate: func(target *IdsecSIADBUpdateDatabaseTarget) {
				target.DomainControllerOrganizationalUnit = " OU=db,DC=example,DC=com"
			},
			wantReject: true,
		},
		{
			name:   "highest_allowed_port",
			mutate: func(target *IdsecSIADBUpdateDatabaseTarget) { target.Port = 65535 },
		},
		{
			name:       "port_above_range",
			mutate:     func(target *IdsecSIADBUpdateDatabaseTarget) { target.Port = 70000 },
			wantReject: true,
		},
		{
			name:       "malformed_secret_id",
			mutate:     func(target *IdsecSIADBUpdateDatabaseTarget) { target.SecretID = "not-a-uuid" },
			wantReject: true,
		},
	})
}
