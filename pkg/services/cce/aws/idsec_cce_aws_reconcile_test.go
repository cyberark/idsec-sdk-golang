package aws

import (
	"testing"

	"github.com/stretchr/testify/require"
	cceinternal "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/internal"
)

// TestServiceParamsChanged_UnsetOptionalIsNotAChange reproduces the regression that caused a 501
// FEATURE_NOT_IMPLEMENTED on an add-services call. When SCA is onboarded with SSO disabled, the module
// emits `ssoRegion = null`. On the desired side that key survives (as nil) while the stored/API side drops
// it, so a naive "desired key missing from current => changed" check would re-send the unchanged SCA
// service and trip the org add-services feature gate. An unset optional value must NOT be treated as a
// change.
//
// serviceParamsChanged and isEmptyParamValue now live in the shared pkg/services/cce/internal package
// (as ServiceParamsChanged / IsEmptyParamValue) so this fix and its coverage apply to every CCE platform
// (AWS, Azure, GCP, ...), not just AWS.
func TestServiceParamsChanged_UnsetOptionalIsNotAChange(t *testing.T) {
	// desired uses the caller's key casing (camelCase); ServiceParamsChanged normalizes to snake_case.
	desired := map[string]interface{}{
		"scaPowerRoleArn":    "arn:aws:iam::107760995777:role/SCARole",
		"ssoEnable":          "false",
		"ssoRegion":          nil, // SSO disabled -> unset optional
		"sca_service_region": "us-east-1",
	}
	// current is what the org GET returns (snake_case), with the unset optional dropped.
	current := map[string]interface{}{
		"sca_power_role_arn": "arn:aws:iam::107760995777:role/SCARole",
		"sso_enable":         "false",
		"sca_service_region": "us-east-1",
	}

	require.False(t, cceinternal.ServiceParamsChanged(desired, current),
		"an unchanged service whose only 'diff' is an unset optional (ssoRegion=null) must not be re-sent")
}

// TestServiceParamsChanged_EmptyStringAndCollectionsAreNotChanges guards the other empty-value shapes.
func TestServiceParamsChanged_EmptyStringAndCollectionsAreNotChanges(t *testing.T) {
	desired := map[string]interface{}{
		"presentKey": "value",
		"emptyStr":   "",
		"emptyMap":   map[string]interface{}{},
		"emptyList":  []interface{}{},
	}
	current := map[string]interface{}{
		"present_key": "value",
	}

	require.False(t, cceinternal.ServiceParamsChanged(desired, current),
		"empty-valued desired keys absent from current must not count as a change")
}

// TestServiceParamsChanged_RealValueChangeDetected ensures the hardening does not suppress genuine changes.
func TestServiceParamsChanged_RealValueChangeDetected(t *testing.T) {
	desired := map[string]interface{}{"scaPowerRoleArn": "arn:aws:iam::111111111111:role/New"}
	current := map[string]interface{}{"sca_power_role_arn": "arn:aws:iam::222222222222:role/Old"}

	require.True(t, cceinternal.ServiceParamsChanged(desired, current),
		"a changed value on a shared key must be detected as a change")
}

// TestServiceParamsChanged_NonEmptyKeyMissingIsChange ensures a newly-set (non-empty) key that the current
// state lacks is still treated as a change.
func TestServiceParamsChanged_NonEmptyKeyMissingIsChange(t *testing.T) {
	desired := map[string]interface{}{"ssoRegion": "us-east-2"}
	current := map[string]interface{}{}

	require.True(t, cceinternal.ServiceParamsChanged(desired, current),
		"a non-empty desired key missing from current must be treated as a change")
}

func TestIsEmptyParamValue(t *testing.T) {
	empty := []interface{}{
		nil,
		"",
		map[string]interface{}{},
		[]interface{}{},
	}
	for _, v := range empty {
		require.True(t, cceinternal.IsEmptyParamValue(v), "expected %#v to be empty", v)
	}

	nonEmpty := []interface{}{
		"false",
		"value",
		0,
		false,
		map[string]interface{}{"k": "v"},
		[]interface{}{"a"},
	}
	for _, v := range nonEmpty {
		require.False(t, cceinternal.IsEmptyParamValue(v), "expected %#v to be non-empty", v)
	}
}
