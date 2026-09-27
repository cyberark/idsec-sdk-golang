// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package models

// IdsecPCloudUpdateLocalGroup represents the input for updating a Vault local group
// via PUT /PasswordVault/API/UserGroups/{groupId}.
//
// PVWA's EditUserGroup accepts BaseUserGroup which carries groupName, description, and location,
// but the underlying logic only calls EditGroup(oldName, newGroupName) — description and location
// are not persisted by the update. GroupName is therefore the only field that has effect; when
// omitted the service fetches the existing name automatically so the required PVWA field is still
// sent.
type IdsecPCloudUpdateLocalGroup struct {
	GroupID     string `json:"group_id"              mapstructure:"group_id"    flag:"group-id"     desc:"ID of the Vault local group to update"   validate:"required"`
	GroupName   string `json:"group_name,omitempty"  mapstructure:"group_name"  flag:"group-name"   desc:"New name for the Vault local group"       maxlength:"255"`
	Description string `json:"description,omitempty" mapstructure:"description" flag:"description"  desc:"Description of the Vault local group" maxlength:"100"`
	Location    string `json:"location,omitempty"    mapstructure:"location"    flag:"location"     desc:"Location of the Vault local group"`
}
