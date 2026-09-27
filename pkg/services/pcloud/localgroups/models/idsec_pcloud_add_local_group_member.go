// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package models

// IdsecPCloudAddLocalGroupMember represents the input for adding a member to a Vault local group
// via POST /PasswordVault/API/UserGroups/{groupId}/Members.
type IdsecPCloudAddLocalGroupMember struct {
	GroupID    string `json:"group_id"    mapstructure:"group_id"    flag:"group-id"    desc:"ID of the Vault local group"                          validate:"required"`
	MemberName string `json:"member_name" mapstructure:"member_name" flag:"member-name" desc:"Name of the user or group to add as a member"          validate:"required"`
	MemberType string `json:"member_type" mapstructure:"member_type" flag:"member-type" desc:"Type of the member being added (Vault or Domain)"      choices:"Vault,Domain" default:"Vault"`
}
