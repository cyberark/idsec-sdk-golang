package vm

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy/vm/models"
)

// wrapMsg is the actionable prefix wrapAccessApprovalNotSupportedErr adds.
const wrapMsg = "dual control (access_approval.required=true) is not enabled for this tenant"

// notSupportedErr is the real backend rejection for access_approval.required=true
// on a tenant without the enable_vm_access_approval flag.
var notSupportedErr = errors.New(`failed to create policy - [400] - [[{"description":"Unable to create an Authorization Policy. Error(s): Access approval is not supported"}]]`)

func required(v bool) *policycommonmodels.IdsecPolicyAccessApprovalCondition {
	return &policycommonmodels.IdsecPolicyAccessApprovalCondition{Required: v}
}

// vmPolicy returns the smallest VM policy Serialize() accepts, with the given
// AccessApproval plugged in.
func vmPolicy(approval *policycommonmodels.IdsecPolicyAccessApprovalCondition) *models.IdsecPolicyVMAccessPolicy {
	p := &models.IdsecPolicyVMAccessPolicy{
		Targets: models.IdsecPolicyVMPlatformTargets{FQDNIPResource: &models.IdsecPolicyVMFQDNIPResource{}},
	}
	p.Metadata.PolicyEntitlement.LocationType = commonmodels.WorkspaceTypeFQDNIP
	p.Conditions.AccessApproval = approval
	return p
}

// TestWrapAccessApprovalNotSupportedErr rewrites the backend's "not supported"
// rejection into an actionable error only when the caller asked for dual
// control; every other error is returned untouched (and stays errors.Is-reachable).
func TestWrapAccessApprovalNotSupportedErr(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		approval *policycommonmodels.IdsecPolicyAccessApprovalCondition
		wantWrap bool
	}{
		{"nil error passes through", nil, required(true), false},
		{"nil approval never wraps", notSupportedErr, nil, false},
		{"required=false never wraps", notSupportedErr, required(false), false},
		{"required=true wraps the rejection", notSupportedErr, required(true), true},
		{"unrelated error not wrapped", errors.New("some other 400"), required(true), false},
		{"network error not wrapped", errors.New("connection refused"), required(true), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := wrapAccessApprovalNotSupportedErr(tt.err, tt.approval)
			switch {
			case tt.err == nil:
				require.NoError(t, got)
			case tt.wantWrap:
				require.ErrorContains(t, got, wrapMsg)
				require.ErrorIs(t, got, tt.err) // original stays reachable
			default:
				require.Same(t, tt.err, got) // returned unchanged, not wrapped
			}
		})
	}
}

// A nil AccessApproval must be omitted from the request entirely (not sent as
// {required:false}), so non-dual-control callers keep byte-identical payloads.
func TestAccessApprovalOmittedWhenNil(t *testing.T) {
	tests := []struct {
		name     string
		approval *policycommonmodels.IdsecPolicyAccessApprovalCondition
		want     bool
	}{
		{"nil is omitted", nil, false},
		{"set is present", required(true), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serialized, err := vmPolicy(tt.approval).Serialize()
			require.NoError(t, err)

			conditions, ok := serialized["conditions"].(map[string]interface{})
			require.True(t, ok)
			_, present := conditions["accessApproval"]
			require.Equal(t, tt.want, present)
		})
	}
}

// TestSerializeVMPolicy_ApproversCamelCased is a regression test for the bug
// that motivated switching Serialize() to common.SerializeJSONCamelSchema:
// mapstructure.Decode left slice-of-struct fields (like access_approval.approvers)
// as typed Go structs, which ConvertToCamelCase's map/slice-only type-switch
// silently skipped, sending approver keys to the backend still snake_case.
func TestSerializeVMPolicy_ApproversCamelCased(t *testing.T) {
	approval := &policycommonmodels.IdsecPolicyAccessApprovalCondition{
		Required: true,
		Approvers: []policycommonmodels.IdsecPolicyPrincipal{
			{
				ID:                  "approver-id",
				Name:                "approver@cyberark.cloud.12345",
				Type:                policycommonmodels.PrincipalTypeUser,
				SourceDirectoryName: "CyberArk",
				SourceDirectoryID:   "12345",
			},
		},
	}

	serialized, err := vmPolicy(approval).Serialize()
	require.NoError(t, err)

	conditions, ok := serialized["conditions"].(map[string]interface{})
	require.True(t, ok)
	accessApproval, ok := conditions["accessApproval"].(map[string]interface{})
	require.True(t, ok)
	approvers, ok := accessApproval["approvers"].([]interface{})
	require.True(t, ok)
	require.Len(t, approvers, 1)
	approver, ok := approvers[0].(map[string]interface{})
	require.True(t, ok)

	require.Equal(t, "approver-id", approver["id"])
	require.Equal(t, "CyberArk", approver["sourceDirectoryName"])
	require.Equal(t, "12345", approver["sourceDirectoryId"])
	_, stillSnakeCase := approver["source_directory_id"]
	require.False(t, stillSnakeCase, "approver fields must be camelCased, not left snake_case")
}
