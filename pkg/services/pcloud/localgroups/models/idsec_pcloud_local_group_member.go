// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package models

// IdsecPCloudLocalGroupMember represents the state of a Vault local group membership.
//
// MembershipID is the unique identifier of the membership record. MemberName is the user or
// group name that is a member; MemberType distinguishes users from nested groups.
//
// Note: PVWA does not return MemberType in read responses (the wire shape has only "username"
// and "id"). GetMember always yields MemberType == "". Callers (e.g. Terraform provider) must
// preserve MemberType from config/state and never overwrite it from a read.
type IdsecPCloudLocalGroupMember struct {
	MembershipID string `json:"membership_id" mapstructure:"membership_id" desc:"Unique ID of the membership record"`
	GroupID      string `json:"group_id"      mapstructure:"group_id"      desc:"ID of the Vault local group"`
	MemberName   string `json:"member_name"   mapstructure:"member_name"   desc:"Name of the member (user or group)"`
	MemberType   string `json:"member_type"   mapstructure:"member_type"   desc:"Type of the member (User or Group); never populated by read responses"`
}
