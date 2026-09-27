// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package models

// IdsecPCloudLocalGroupsFilters represents the filters for listing Vault local groups.
type IdsecPCloudLocalGroupsFilters struct {
	Search                 string `json:"search,omitempty"                  mapstructure:"search"                  flag:"search"                   desc:"Searches by group name"`
	Sort                   string `json:"sort,omitempty"                    mapstructure:"sort"                    flag:"sort"                     desc:"Sorts results by groupName ascending or descending"          choices:"groupName asc,groupName desc"`
	Offset                 int    `json:"offset,omitempty"                  mapstructure:"offset"                  flag:"offset"                   desc:"Offset of the first group returned"                          validate:"min=0"`
	Limit                  int    `json:"limit,omitempty"                   mapstructure:"limit"                   flag:"limit"                    desc:"Maximum number of groups returned"                           validate:"min=1"`
	IncludePredefinedUsers bool   `json:"include_predefined_users,omitempty" mapstructure:"include_predefined_users" flag:"include-predefined-users" desc:"When true, includes built-in Vault groups (Vault Admins, Auditors, etc.) in results"`
}
