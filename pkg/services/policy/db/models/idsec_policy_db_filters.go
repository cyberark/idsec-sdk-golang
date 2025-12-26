package models

import (
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
)

// IdsecPolicyDBFilters defines filters specific to the SIA DB policies within the policies service.
//
// You can set the following fields:
//
//   - policy_type: Optional[List[IdsecPolicyType]]
//     A list of policy types to filter the policies by.
//
//   - policy_tags: Optional[List[string]]
//     A list of policy tags to filter the policies by.
//
//   - identities: Optional[List[string]]
//     A list of identities to filter the policies by.
//
//   - status: Optional[List[IdsecStatusType]]
//     A list of policy statuses to filter the policies by.
//
//   - text_search: Optional[string]
//     A text value to apply as a search filter across policies.
//
//   - show_editable_policies: Optional[bool]
//     Whether to show only policies that are editable by the current user.
type IdsecPolicyDBFilters struct {
	policycommonmodels.IdsecPolicyFilters `mapstructure:",squash"`
}
