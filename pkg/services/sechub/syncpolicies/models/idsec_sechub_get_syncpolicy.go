package models

// Projection query values for sync policy read operations (Secrets Hub API).
const (
	// IdsecSecHubSyncPolicyProjectionExtend requests the extended representation (JSON:API–aligned full resource graph).
	IdsecSecHubSyncPolicyProjectionExtend = "EXTEND"
	// IdsecSecHubSyncPolicyProjectionRegular requests the regular (compact) representation.
	IdsecSecHubSyncPolicyProjectionRegular = "REGULAR"
)

// IdsecSecHubGetSyncPolicy contains the policy id for the policy to retrieve
type IdsecSecHubGetSyncPolicy struct {
	PolicyID   string `json:"id" mapstructure:"id" desc:"Unique identifier of the referenced policy" flag:"policy-id" validate:"required"`
	Projection string `json:"projection" mapstructure:"projection" desc:"Data representation method (EXTEND, REGULAR)" default:"EXTEND" flag:"projection" choices:"EXTEND,REGULAR"`
	// Transformation is optional on the get request. When Predefined is non-empty it is merged onto the
	// returned policy because the extended GET response may omit predefined (empty Predefined is valid when omitted).
	Transformation IdsecSecHubPolicyTransformation `json:"transformation,omitzero" mapstructure:"transformation,omitempty" desc:"Transformation reference"`
}
