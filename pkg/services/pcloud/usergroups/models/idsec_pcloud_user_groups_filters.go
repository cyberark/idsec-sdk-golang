// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package models

// IdsecPCloudUserGroupsFilters represents the filters for listing Vault user groups.
type IdsecPCloudUserGroupsFilters struct {
	Search                 string `json:"search,omitempty"                   mapstructure:"search"                   desc:"Searches according to the group name. Search is performed according to the REST standard"`
	GroupType              string `json:"group_type,omitempty"               mapstructure:"group_type"               desc:"Restricts the results to a single group type"                                        choices:"Vault,Directory"`
	IncludePredefinedUsers bool   `json:"include_predefined_users,omitempty" mapstructure:"include_predefined_users" desc:"Whether the predefined Vault groups are included in the results"`
	Sort                   string `json:"sort,omitempty"                     mapstructure:"sort"                     desc:"Sorts according to the groupName property in ascending order (default) or descending order" choices:"groupName asc,groupName desc"`
	Offset                 int    `json:"offset,omitempty"                   mapstructure:"offset"                   desc:"Offset of the first group that is returned in the collection of results"              validate:"min=0"`
	Limit                  int    `json:"limit,omitempty"                    mapstructure:"limit"                    desc:"The maximum number of groups that are returned"                                      validate:"min=1"`
}
