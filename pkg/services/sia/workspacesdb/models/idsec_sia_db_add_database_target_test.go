package models

import (
	"reflect"
	"strings"
	"testing"
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

// TestAddDatabaseTargetChoicesAlignedWithPublicAPI locks in that the public
// onboarding request model exposes only the platforms and auth methods actually
// supported by the adb-resources-manager public /api/database-targets API.
//
// The allow-lists live in the `choices` struct tags (there is no runtime
// validator), so a behavioral CreateTarget call would not catch a regression -
// this tag-assertion test is the guard. ATLAS / SNOWFLAKE platforms and the
// atlas_ephemeral_user auth method must NOT be advertised here.
func TestAddDatabaseTargetChoicesAlignedWithPublicAPI(t *testing.T) {
	t.Parallel()

	targetType := reflect.TypeOf(IdsecSIADBAddDatabaseTarget{})

	t.Run("platform_choices_are_supported_subset", func(t *testing.T) {
		t.Parallel()
		got := choicesTag(t, targetType, "Platform")
		const want = "AWS,AZURE,GCP,ON-PREMISE"
		if got != want {
			t.Fatalf("Platform choices = %q, want %q", got, want)
		}
		for _, forbidden := range []string{"ATLAS", "SNOWFLAKE"} {
			if slicesContainsChoice(got, forbidden) {
				t.Fatalf("Platform choices %q must not expose %q", got, forbidden)
			}
		}
	})

	t.Run("auth_method_choices_are_supported_subset", func(t *testing.T) {
		t.Parallel()
		got := choicesTag(t, targetType, "ConfiguredAuthMethodType")
		const want = "ad_ephemeral_user,local_ephemeral_user,rds_iam_authentication"
		if got != want {
			t.Fatalf("ConfiguredAuthMethodType choices = %q, want %q", got, want)
		}
		if slicesContainsChoice(got, "atlas_ephemeral_user") {
			t.Fatalf("ConfiguredAuthMethodType choices %q must not expose %q", got, "atlas_ephemeral_user")
		}
	})
}

// TestAddDatabaseLegacyModelUnchanged ensures the legacy internal-API model is
// left untouched: it still supports the ATLAS platform, so narrowing the public
// target model must not have narrowed it too.
func TestAddDatabaseLegacyModelUnchanged(t *testing.T) {
	t.Parallel()

	legacyType := reflect.TypeOf(IdsecSIADBAddDatabase{})
	got := choicesTag(t, legacyType, "Platform")
	if !slicesContainsChoice(got, "ATLAS") {
		t.Fatalf("legacy IdsecSIADBAddDatabase.Platform choices = %q, expected it to still contain ATLAS", got)
	}
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
