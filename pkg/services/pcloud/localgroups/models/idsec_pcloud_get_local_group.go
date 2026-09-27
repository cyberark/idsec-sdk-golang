// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package models

// IdsecPCloudGetLocalGroup represents the input for retrieving a single Vault local group.
//
// Supply GroupID, GroupName, or both: the name narrows the server-side search and the ID, when
// set, selects the exact match from the results.
type IdsecPCloudGetLocalGroup struct {
	GroupID   string `json:"group_id"   mapstructure:"group_id"   flag:"group-id"   desc:"ID of the Vault local group to retrieve"`
	GroupName string `json:"group_name" mapstructure:"group_name" flag:"group-name" desc:"Name of the Vault local group to retrieve"`
}
