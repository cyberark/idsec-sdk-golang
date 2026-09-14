// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package models

// IdsecPCloudUserGroupMember represents the state of a Vault user group membership.
//
// MemberName is the identifier the membership is addressed by, both when adding and when
// removing. MemberID is the numeric identifier the Vault assigns to the member and reports back
// in the response; it is output-only and is not accepted as an input by either call.
type IdsecPCloudUserGroupMember struct {
	GroupID    int    `json:"group_id"    mapstructure:"group_id"    desc:"Numeric ID of the Vault user group"`
	MemberName string `json:"member_name" mapstructure:"member_name" desc:"Vault user name, or name of the nested group, that is a member of the group"`
	MemberID   int    `json:"member_id"   mapstructure:"member_id"   desc:"Numeric ID the Vault reports for the member"`
	MemberType string `json:"member_type" mapstructure:"member_type" desc:"Type of the member (Vault or Domain)"`
}
