package models

import (
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
)

// IdsecPolicyCloudAccessFilters exposes Cloud Access–specific filter helpers built atop the shared policy filters.
//
// You can set the following fields:
//
//   - TargetCategory: []common.IdsecCategoryType
//     A list of target categories to filter the policies by.
//
//   - PolicyType: []common.IdsecPolicyPolicyType
//     A list of policy types to filter the policies by.
//
//   - PolicyTags: []string
//     A list of policy tags to filter the policies by.
//
//   - Identities: []string
//     A list of identities to filter the policies by.
//
//   - Status: []common.IdsecPolicyStatusType
//     A list of policy statuses to filter the policies by.
//
//   - TextSearch: *string
//     A text value to apply as a search filter across policies.
//
//   - ShowEditablePolicies: *bool
//     Whether to show only policies that are editable by the current user.
type IdsecPolicyCloudAccessFilters struct {
	policycommonmodels.IdsecPolicyFilters `mapstructure:",squash"`
}
