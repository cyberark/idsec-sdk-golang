// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package models

// IdsecPCloudGetUserGroup represents the input for retrieving a single Vault user group.
//
// PVWA exposes no GET /PasswordVault/API/UserGroups/{id} on every supported version, so the
// service resolves a group through the filtered list endpoint. Supply GroupName, GroupID, or
// both: the name narrows the server-side search and the ID, when set, selects the match.
type IdsecPCloudGetUserGroup struct {
	GroupID   int    `json:"group_id"   mapstructure:"group_id"   flag:"group-id"   desc:"Numeric ID of the Vault user group to retrieve"`
	GroupName string `json:"group_name" mapstructure:"group_name" flag:"group-name" desc:"Name of the Vault user group to retrieve"`
}
