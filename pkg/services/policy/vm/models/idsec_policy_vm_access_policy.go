package models

import (
	"reflect"

	"github.com/mitchellh/mapstructure"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
)

// IdsecPolicyVMAccessPolicy represents a VM access policy for infrastructure.
type IdsecPolicyVMAccessPolicy struct {
	policycommonmodels.IdsecPolicyInfraCommonAccessPolicy `mapstructure:",squash"`
	Targets                                               IdsecPolicyVMPlatformTargets `json:"targets,omitempty" mapstructure:"targets,omitempty" flag:"targets" desc:"The targets of the VM access policy. This is a list of platform targets to which the policy applies."`
	Behavior                                              IdsecPolicyVMBehavior        `json:"behavior,omitempty" mapstructure:"behavior,omitempty" flag:"behavior" desc:"The behavior of the VM access policy, including SSH and RDP profiles."`
}

// Serialize converts the VM access policy into the camelCase, wire-ready map
// the backend expects. Most fields (including nested slice-of-struct fields
// like conditions.access_approval.approvers) convert automatically via the
// shared, schema-aware JSON round-trip (SerializeJSONCamelSchema), but Targets
// and Behavior need structural reshaping (workspace-keyed resource selection,
// "connectAs" wrapping) that a casing-only conversion can't produce, so they're
// overwritten with their own Serialize() output afterward.
func (p *IdsecPolicyVMAccessPolicy) Serialize() (map[string]interface{}, error) {
	policyType := reflect.TypeOf(p)
	data, err := common.SerializeJSONCamelSchema(p, &policyType)
	if err != nil {
		return nil, err
	}
	data["targets"], err = p.Targets.Serialize(p.Metadata.PolicyEntitlement.LocationType)
	if err != nil {
		return nil, err
	}
	data["behavior"] = p.Behavior.Serialize()
	return data, err
}

// Deserialize populates the VM access policy from a map.
func (p *IdsecPolicyVMAccessPolicy) Deserialize(data map[string]interface{}) error {
	dataWithoutTargetsBehaviors := make(map[string]interface{})
	for key, value := range data {
		if key != "targets" && key != "behavior" {
			dataWithoutTargetsBehaviors[key] = value
		}
	}
	err := mapstructure.Decode(dataWithoutTargetsBehaviors, p)
	if err != nil {
		return err
	}

	if targetsData, ok := data["targets"].(map[string]interface{}); ok {
		p.Targets = IdsecPolicyVMPlatformTargets{}
		if err = p.Targets.Deserialize(targetsData, p.Metadata.PolicyEntitlement.LocationType); err != nil {
			return err
		}
	}

	if behaviorData, ok := data["behavior"].(map[string]interface{}); ok {
		p.Behavior = IdsecPolicyVMBehavior{}
		if err = p.Behavior.Deserialize(behaviorData); err != nil {
			return err
		}
	}

	return nil
}
