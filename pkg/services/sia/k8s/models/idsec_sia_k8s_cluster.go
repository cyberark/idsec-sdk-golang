package models

// IdsecSIAK8SCluster represents a single K8S cluster that is available for the current user to access.
//
// The json tags are camelCase (matching the API wire format and the ark-sdk-python reference
// implementation's clusters file format), while the mapstructure/flag tags stay snake_case/kebab-case
// per this SDK's CLI conventions.
type IdsecSIAK8SCluster struct {
	ClusterAddress   string `json:"clusterAddress" mapstructure:"cluster_address" flag:"cluster-address" desc:"Address of the K8s cluster."`
	ClusterUsername  string `json:"clusterUsername" mapstructure:"cluster_username" flag:"cluster-username" desc:"Username used to connect to the K8s cluster."`
	IsReasonRequired bool   `json:"isReasonRequired" mapstructure:"is_reason_required" flag:"is-reason-required" desc:"Whether a reason is required in order to access this cluster." default:"false"`
	Reason           string `json:"reason,omitempty" mapstructure:"reason,omitempty" flag:"reason" desc:"Reason for accessing the cluster, required when generating cluster access and IsReasonRequired is true."`
}
