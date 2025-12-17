package models

//
// NOTE: All struct tags below use snake_case for both json and mapstructure.
//

// IdsecSecHubPolicy represents a synchronization policy with detailed source, target, filter, status, and state.
type IdsecSecHubPolicy struct {
	ID             string                          `json:"id" mapstructure:"id" desc:"Unique identifier of the policy"`
	Name           string                          `json:"name" mapstructure:"name" desc:"Name of the policy"`
	Description    string                          `json:"description,omitempty" mapstructure:"description,omitempty" desc:"Description of the policy"`
	CreatedAt      string                          `json:"created_at" mapstructure:"created_at" desc:"Timestamp when the policy was created"`
	UpdatedAt      string                          `json:"updated_at" mapstructure:"updated_at" desc:"Timestamp when the policy was last updated"`
	CreatedBy      string                          `json:"created_by" mapstructure:"created_by" desc:"User who created the policy"`
	UpdatedBy      string                          `json:"updated_by" mapstructure:"updated_by" desc:"User who last updated the policy"`
	Source         IdsecSecHubPolicyStore          `json:"source" mapstructure:"source" desc:"Source store reference"`
	Target         IdsecSecHubPolicyStore          `json:"target" mapstructure:"target" desc:"Target store reference"`
	Filter         IdsecSecHubPolicyFilter         `json:"filter" mapstructure:"filter" desc:"Filter reference"`
	Transformation IdsecSecHubPolicyTransformation `json:"transformation,omitzero" mapstructure:"transformation,omitempty" desc:"Transformation reference"`
	State          IdsecSecHubPolicyState          `json:"state" mapstructure:"state" desc:"Current state of the policy"`
	Status         IdsecSecHubPolicyStatus         `json:"status,omitzero" mapstructure:"status,omitempty" desc:"Status of the policy"`
}

// IdsecSecHubPolicyStore represents a reference to a store with details.
type IdsecSecHubPolicyStore struct {
	ID              string                 `json:"id" mapstructure:"id" desc:"Unique identifier of the store"`
	Type            string                 `json:"type,omitempty" mapstructure:"type,omitempty" desc:"Type of the store"`
	Behaviors       []string               `json:"behaviors,omitempty" mapstructure:"behaviors,omitempty" desc:"Behaviors of the store"`
	CreatedAt       string                 `json:"created_at,omitempty" mapstructure:"created_at,omitempty" desc:"Timestamp when the store was created"`
	CreatedBy       string                 `json:"created_by,omitempty" mapstructure:"created_by,omitempty" desc:"User who created the store"`
	Data            map[string]interface{} `json:"data,omitempty" mapstructure:"data,omitempty" desc:"Store-specific data"`
	Description     string                 `json:"description,omitempty" mapstructure:"description,omitempty" desc:"Description of the store"`
	Name            string                 `json:"name,omitempty" mapstructure:"name,omitempty" desc:"Name of the store"`
	UpdatedAt       string                 `json:"updated_at,omitempty" mapstructure:"updated_at,omitempty" desc:"Timestamp when the store was last updated"`
	UpdatedBy       string                 `json:"updated_by,omitempty" mapstructure:"updated_by,omitempty" desc:"User who last updated the store"`
	CreationDetails string                 `json:"creation_details,omitempty" mapstructure:"creation_details,omitempty" desc:"Creation details"`
	State           string                 `json:"state,omitempty" mapstructure:"state,omitempty" desc:"Current state of the store"`
}

// IdsecSecHubPolicyFilter represents a reference to a filter with details.
type IdsecSecHubPolicyFilter struct {
	ID        string                 `json:"id" mapstructure:"id" desc:"Unique identifier of the filter"`
	Type      string                 `json:"type,omitempty" mapstructure:"type,omitempty" desc:"Type of the filter"`
	Data      map[string]interface{} `json:"data,omitempty" mapstructure:"data,omitempty" desc:"Filter-specific data"`
	CreatedAt string                 `json:"created_at,omitempty" mapstructure:"created_at,omitempty" desc:"Timestamp when the filter was created"`
	UpdatedAt string                 `json:"updated_at,omitempty" mapstructure:"updated_at,omitempty" desc:"Timestamp when the filter was last updated"`
	CreatedBy string                 `json:"created_by,omitempty" mapstructure:"created_by,omitempty" desc:"User who created the filter"`
	UpdatedBy string                 `json:"updated_by,omitempty" mapstructure:"updated_by,omitempty" desc:"User who last updated the filter"`
}

// IdsecSecHubPolicyTransformation represents a reference to a transformation.
type IdsecSecHubPolicyTransformation struct {
	ID string `json:"id,omitempty" mapstructure:"id,omitempty" desc:"Unique identifier of the transformation"`
}

// IdsecSecHubPolicyState represents the current state of the policy.
type IdsecSecHubPolicyState struct {
	Current      string                         `json:"current" mapstructure:"current" desc:"Current state value (e.g., ENABLED)"`
	StateDetails *IdsecSecHubPolicyStateDetails `json:"state_details,omitempty" mapstructure:"state_details,omitempty" desc:"Details about the state transition"`
}

// IdsecSecHubPolicyStateDetails provides details about the state transition.
type IdsecSecHubPolicyStateDetails struct {
	Status    string `json:"status,omitempty" mapstructure:"status,omitempty" desc:"Status of the state transition"`
	FromState string `json:"from_state,omitempty" mapstructure:"from_state,omitempty" desc:"Previous state"`
	ToState   string `json:"to_state,omitempty" mapstructure:"to_state,omitempty" desc:"New state"`
}

// IdsecSecHubPolicyStatus represents the status of the policy.
type IdsecSecHubPolicyStatus struct {
	PolicyID        string `json:"policy_id,omitempty" mapstructure:"policy_id,omitempty" desc:"ID of the policy"`
	PolicyStatus    string `json:"policy_status,omitempty" mapstructure:"policy_status,omitempty" desc:"Status of the policy"`
	IsRunning       bool   `json:"is_running,omitempty" mapstructure:"is_running,omitempty" desc:"Whether the policy is currently running"`
	LastRun         string `json:"last_run,omitempty" mapstructure:"last_run,omitempty" desc:"Timestamp of the last run"`
	LastSuccessTime string `json:"last_success_time,omitempty" mapstructure:"last_success_time,omitempty" desc:"Timestamp of the last successful run"`
}
