package models

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

var errEmptyMandatoryFields = errors.New("empty mandatory field(s)")

// IdsecPolicyGroupAccessTarget is a wrapper holding the group targets of a group access policy.
//
// Fields:
//   - Targets: Entra ID (Azure) group targets, used when the policy location_type is Azure.
//   - GCPTargets: Google (GCP) group targets, used when the policy location_type is GCP.
//
// Exactly one of the lists must be populated, matching the policy location_type. The API receives
// both kinds as a single flat targets array; SerializeTargets and DeserializeTargets convert between
// the typed lists and that array.
//
// Example:
//
//	targets := IdsecPolicyGroupAccessTarget{Targets: []IdsecPolicyGroupAccessAzureTarget{item}}
//	gcpTargets := IdsecPolicyGroupAccessTarget{GCPTargets: []IdsecPolicyGroupAccessGCPTarget{gcpItem}}
//
// Concurrency: Safe for read-only concurrent access; copy before mutation.
type IdsecPolicyGroupAccessTarget struct { //nolint:revive
	Targets    []IdsecPolicyGroupAccessAzureTarget `json:"targets" mapstructure:"targets" flag:"targets" desc:"List of Entra ID group targets, used when 'location_type' is Azure"`
	GCPTargets []IdsecPolicyGroupAccessGCPTarget   `json:"gcp_targets,omitempty" mapstructure:"gcp_targets,omitempty" flag:"gcp-targets" desc:"List of Google group targets, used when 'location_type' is GCP"`
}

// NewIdsecPolicyGroupAccessTarget constructs a new target wrapper from provided Azure items slice.
// Parameters:
//   - items: Slice of IdsecPolicyGroupAccessAzureTarget; must be non-empty and each item must have all mandatory fields populated.
//
// Returns pointer to IdsecPolicyGroupAccessTarget or error if validation fails.
func NewIdsecPolicyGroupAccessTarget(items []IdsecPolicyGroupAccessAzureTarget) (*IdsecPolicyGroupAccessTarget, error) { //nolint:revive
	if len(items) == 0 {
		return nil, fmt.Errorf("targets cannot be empty")
	}
	for i := range items {
		if err := items[i].Validate(); err != nil {
			return nil, fmt.Errorf("target index %d has %w", i, err)
		}
	}
	return &IdsecPolicyGroupAccessTarget{Targets: items}, nil
}

// NewIdsecPolicyGroupAccessGCPTarget constructs a new target wrapper from provided GCP items slice.
// Parameters:
//   - items: Slice of IdsecPolicyGroupAccessGCPTarget; must be non-empty and each item must have all mandatory fields populated.
//
// Returns pointer to IdsecPolicyGroupAccessTarget or error if validation fails.
func NewIdsecPolicyGroupAccessGCPTarget(items []IdsecPolicyGroupAccessGCPTarget) (*IdsecPolicyGroupAccessTarget, error) { //nolint:revive
	if len(items) == 0 {
		return nil, fmt.Errorf("gcp_targets cannot be empty")
	}
	for i := range items {
		if err := items[i].Validate(); err != nil {
			return nil, fmt.Errorf("gcp_targets index %d has %w", i, err)
		}
	}
	return &IdsecPolicyGroupAccessTarget{GCPTargets: items}, nil
}

// Serialize converts the Azure targets into a map with a camelCase 'targets' key holding an array of item write payloads.
func (t *IdsecPolicyGroupAccessTarget) Serialize() (map[string]interface{}, error) { //nolint:revive
	if t == nil || len(t.Targets) == 0 {
		return nil, fmt.Errorf("targets cannot be empty")
	}
	serialized := make([]interface{}, 0, len(t.Targets))
	for i := range t.Targets {
		itemMap, err := t.Targets[i].Serialize()
		if err != nil {
			return nil, fmt.Errorf("target index %d has %w", i, err)
		}
		serialized = append(serialized, itemMap)
	}
	return map[string]interface{}{"targets": serialized}, nil
}

// Deserialize populates the Azure targets from a map containing a 'targets' key with array of item maps.
func (t *IdsecPolicyGroupAccessTarget) Deserialize(data map[string]interface{}) error { //nolint:revive
	if data == nil {
		return fmt.Errorf("data cannot be nil")
	}
	arr, ok := data["targets"].([]interface{})
	if !ok {
		return fmt.Errorf("targets missing or not an array")
	}
	items := make([]IdsecPolicyGroupAccessAzureTarget, 0, len(arr))
	for i, raw := range arr {
		m, ok := raw.(map[string]interface{})
		if !ok {
			return fmt.Errorf("target index %d is not a map", i)
		}
		var item IdsecPolicyGroupAccessAzureTarget
		if err := item.Deserialize(m); err != nil {
			return fmt.Errorf("target index %d has %w", i, err)
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		return fmt.Errorf("targets cannot be empty")
	}
	t.Targets = items
	return nil
}

// SerializeTargets converts the typed target lists into the API payload shape for the given policy location type.
//
// The result is a map with a 'targets' key holding one flat array of target items. Azure items keep the
// same camelCase shape the policy API has always received; GCP items carry only their write fields.
// Returns an error when both or neither lists are set, or when the populated list does not match locationType.
func (t *IdsecPolicyGroupAccessTarget) SerializeTargets(locationType string) (map[string]interface{}, error) {
	if t == nil || (len(t.Targets) == 0 && len(t.GCPTargets) == 0) {
		return nil, fmt.Errorf("targets cannot be empty")
	}
	if len(t.Targets) > 0 && len(t.GCPTargets) > 0 {
		return nil, fmt.Errorf("targets and gcp_targets cannot both be set; a group access policy targets a single cloud provider")
	}
	switch {
	case strings.EqualFold(locationType, commonmodels.WorkspaceTypeAzure):
		if len(t.Targets) == 0 {
			return nil, fmt.Errorf("location_type %s requires targets, got gcp_targets", commonmodels.WorkspaceTypeAzure)
		}
		serialized := make([]interface{}, 0, len(t.Targets))
		for i := range t.Targets {
			if err := t.Targets[i].Validate(); err != nil {
				return nil, fmt.Errorf("target index %d has %w", i, err)
			}
			itemMap, err := common.SerializeJSONCamel(t.Targets[i])
			if err != nil {
				return nil, err
			}
			serialized = append(serialized, itemMap)
		}
		return map[string]interface{}{"targets": serialized}, nil
	case strings.EqualFold(locationType, commonmodels.WorkspaceTypeGCP):
		if len(t.GCPTargets) == 0 {
			return nil, fmt.Errorf("location_type %s requires gcp_targets, got targets", commonmodels.WorkspaceTypeGCP)
		}
		serialized := make([]interface{}, 0, len(t.GCPTargets))
		for i := range t.GCPTargets {
			itemMap, err := t.GCPTargets[i].Serialize()
			if err != nil {
				return nil, fmt.Errorf("gcp_targets index %d has %w", i, err)
			}
			serialized = append(serialized, itemMap)
		}
		return map[string]interface{}{"targets": serialized}, nil
	default:
		return nil, fmt.Errorf("unsupported location_type %q for group access policy, expected %s or %s", locationType, commonmodels.WorkspaceTypeAzure, commonmodels.WorkspaceTypeGCP)
	}
}

// DeserializeTargets routes the API targets array into the typed list matching the policy location type.
//
// For GCP policies the items are parsed into GCPTargets and Targets is cleared. For any other location type
// the targets already decoded into Targets are left unchanged. A payload without targets (e.g. partial list
// results) is a no-op.
func (t *IdsecPolicyGroupAccessTarget) DeserializeTargets(data map[string]interface{}, locationType string) error {
	if !strings.EqualFold(locationType, commonmodels.WorkspaceTypeGCP) {
		return nil
	}
	rawTargets, exists := data["targets"]
	if !exists || rawTargets == nil {
		return nil
	}
	arr, ok := rawTargets.([]interface{})
	if !ok {
		return fmt.Errorf("targets is not an array")
	}
	items := make([]IdsecPolicyGroupAccessGCPTarget, 0, len(arr))
	for i, raw := range arr {
		m, ok := raw.(map[string]interface{})
		if !ok {
			return fmt.Errorf("gcp_targets index %d is not a map", i)
		}
		var item IdsecPolicyGroupAccessGCPTarget
		if err := item.Deserialize(m); err != nil {
			return fmt.Errorf("gcp_targets index %d has %w", i, err)
		}
		items = append(items, item)
	}
	t.Targets = nil
	t.GCPTargets = items
	return nil
}

// targetStringField reads the first non-empty string among alternate JSON keys (snake_case and camelCase).
func targetStringField(data map[string]interface{}, keys ...string) string {
	for _, k := range keys {
		if s, ok := data[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}
