package db

import (
	"testing"

	"github.com/stretchr/testify/require"

	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/policy/db/models"
)

func required(v bool) *policycommonmodels.IdsecPolicyAccessApprovalCondition {
	return &policycommonmodels.IdsecPolicyAccessApprovalCondition{Required: v}
}

func TestCheckAccessApprovalNotSupported(t *testing.T) {
	tests := []struct {
		name     string
		approval *policycommonmodels.IdsecPolicyAccessApprovalCondition
		wantErr  bool
	}{
		{"nil approval passes", nil, false},
		{"required=false passes", required(false), false},
		{"required=true returns error", required(true), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkAccessApprovalNotSupported(tt.approval)
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), "dual control (access_approval.required=true) is not supported for DB policies")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCreatePolicy_RejectsAccessApprovalRequired(t *testing.T) {
	s := &IdsecPolicyDBService{}
	policy := &models.IdsecPolicyDBAccessPolicy{}
	policy.Conditions.AccessApproval = required(true)

	_, err := s.CreatePolicy(policy)
	require.Error(t, err)
	require.Contains(t, err.Error(), "dual control (access_approval.required=true) is not supported for DB policies")
}

func TestUpdatePolicy_RejectsAccessApprovalRequired(t *testing.T) {
	s := &IdsecPolicyDBService{}
	policy := &models.IdsecPolicyDBAccessPolicy{}
	policy.Conditions.AccessApproval = required(true)

	_, err := s.UpdatePolicy(policy)
	require.Error(t, err)
	require.Contains(t, err.Error(), "dual control (access_approval.required=true) is not supported for DB policies")
}
