package models

import (
	"html"
)

// IdsecPolicyMetadata represents metadata for a policy in the policy service.
type IdsecPolicyMetadata struct {
	PolicyID          string                 `json:"policy_id,omitempty" mapstructure:"policy_id,omitempty" flag:"policy-id" desc:"The unique identifier of the access policy - minLength: 0, maxLength: 99" validate:"max=99"`
	Name              string                 `json:"name" validate:"required,min=1,max=200" mapstructure:"name" flag:"name" desc:"A unique name for the access policy - minLength: 1, maxLength: 200"`
	Description       string                 `json:"description,omitempty" validate:"max=200" mapstructure:"description,omitempty" flag:"description" desc:"A short description about the policy - maximum 200 characters"`
	Status            IdsecPolicyStatus      `json:"status" mapstructure:"status" flag:"status" desc:"The status of the policy"`
	TimeFrame         IdsecPolicyTimeFrame   `json:"time_frame,omitempty" mapstructure:"time_frame,omitempty" flag:"time-frame" desc:"The timeframe that the policy is active. For an unlimited timeframe, leave empty - maxLength: 50"`
	PolicyEntitlement IdsecPolicyEntitlement `json:"policy_entitlement" validate:"required" mapstructure:"policy_entitlement" flag:"policy-entitlement" desc:"The policy target category, location type, and policy type"`
	CreatedBy         IdsecPolicyChangeInfo  `json:"created_by,omitempty" mapstructure:"created_by,omitempty" flag:"created-by" desc:"The user who created the policy and when"`
	UpdatedOn         IdsecPolicyChangeInfo  `json:"updated_on,omitempty" mapstructure:"updated_on,omitempty" flag:"updated-on" desc:"The user who updated the policy, and when"`
	PolicyTags        []string               `json:"policy_tags" validate:"max=20" mapstructure:"policy_tags" flag:"policy-tags" desc:"Customized tags to help identify the policy and those similar to it - maximum 20 tags per policy"`
	TimeZone          string                 `json:"time_zone" validate:"max=50,regexp=^\\w+$" mapstructure:"time_zone" flag:"time-zone" desc:"The time zone identifier - maxLength: 50, Default: GMT" default:"GMT"`
}

// FilterNonePolicyTags filters out `nil` values from the PolicyTags field.
func (metadata *IdsecPolicyMetadata) FilterNonePolicyTags(tags []string) []string {
	var filteredTags []string
	for _, tag := range tags {
		if tag != "" {
			filteredTags = append(filteredTags, tag)
		}
	}
	return filteredTags
}

// EncodeName escapes HTML characters in the Name field.
func (metadata *IdsecPolicyMetadata) EncodeName(name string) string {
	if name == "" {
		return name
	}
	return html.EscapeString(name)
}

// EncodeDescription escapes HTML characters in the Description field.
func (metadata *IdsecPolicyMetadata) EncodeDescription(description string) string {
	if description == "" {
		return description
	}
	return html.EscapeString(description)
}
