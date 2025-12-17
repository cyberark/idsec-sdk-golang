package models

import (
	"html"
)

// IdsecUAPMetadata represents metadata for a policy.
type IdsecUAPMetadata struct {
	PolicyID          string                    `json:"policy_id,omitempty" mapstructure:"policy_id,omitempty" flag:"policy-id" desc:"Policy id" validate:"max=99"`
	Name              string                    `json:"name" validate:"required,min=1,max=200" mapstructure:"name" flag:"name" desc:"Name of the policy"`
	Description       string                    `json:"description,omitempty" validate:"max=200" mapstructure:"description,omitempty" flag:"description" desc:"Description of the policy"`
	Status            IdsecUAPPolicyStatus      `json:"status" mapstructure:"status" flag:"status" desc:"Status of the policy"`
	TimeFrame         IdsecUAPTimeFrame         `json:"time_frame,omitempty" mapstructure:"time_frame,omitempty" flag:"time-frame" desc:"The time that the policy is active"`
	PolicyEntitlement IdsecUAPPolicyEntitlement `json:"policy_entitlement" mapstructure:"policy_entitlement" flag:"policy-entitlement" desc:"The policy target category, location type and policy type"`
	CreatedBy         IdsecUAPChangeInfo        `json:"created_by,omitempty" mapstructure:"created_by,omitempty" flag:"created-by" desc:"The user who created the policy, and the creation time"`
	UpdatedOn         IdsecUAPChangeInfo        `json:"updated_on,omitempty" mapstructure:"updated_on,omitempty" flag:"updated-on" desc:"The user who updated the policy, and the update time"`
	PolicyTags        []string                  `json:"policy_tags" validate:"max=20" mapstructure:"policy_tags" flag:"policy-tags" desc:"List of tags that related to the policy"`
	TimeZone          string                    `json:"time_zone" validate:"max=50,regexp=^\\w+$" mapstructure:"time_zone" flag:"time-zone" desc:"The time zone of the policy, default is GMT" default:"GMT"`
}

// FilterNonePolicyTags filters out `nil` values from the PolicyTags field.
func (metadata *IdsecUAPMetadata) FilterNonePolicyTags(tags []string) []string {
	var filteredTags []string
	for _, tag := range tags {
		if tag != "" {
			filteredTags = append(filteredTags, tag)
		}
	}
	return filteredTags
}

// EncodeName escapes HTML characters in the Name field.
func (metadata *IdsecUAPMetadata) EncodeName(name string) string {
	if name == "" {
		return name
	}
	return html.EscapeString(name)
}

// EncodeDescription escapes HTML characters in the Description field.
func (metadata *IdsecUAPMetadata) EncodeDescription(description string) string {
	if description == "" {
		return description
	}
	return html.EscapeString(description)
}
