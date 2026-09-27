// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package models

// IdsecPCloudDeleteLocalGroupMember represents the input for removing a member from a Vault local
// group via DELETE /PasswordVault/API/UserGroups/{groupId}/Members/{memberName}.
type IdsecPCloudDeleteLocalGroupMember struct {
	GroupID    string `json:"group_id"    mapstructure:"group_id"    flag:"group-id"    desc:"ID of the Vault local group"                                          validate:"required"`
	MemberName string `json:"member_name" mapstructure:"member_name" flag:"member-name" desc:"Name of the user or group to remove from the group"                validate:"required"`
}
