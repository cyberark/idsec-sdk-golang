package models

// IdsecSIAK8SGenerateClusterConfig is a struct that represents the request for generating a kubeconfig
// file for a specific set of K8s clusters and access reasons from the Idsec SIA K8S service.
type IdsecSIAK8SGenerateClusterConfig struct {
	ClustersFile string `json:"clusters_file" mapstructure:"clusters_file" flag:"clusters-file" desc:"Path to a JSON file containing the clusters to include in the generated kubeconfig, in the format returned by list-clusters. Add a reason when isReasonRequired is set to true."`
	Folder       string `json:"folder,omitempty" mapstructure:"folder,omitempty" flag:"folder" desc:"The output folder in which the kubeconfig is written." default:"~/.kube"`
	ReasonToAll  string `json:"reason_to_all,omitempty" mapstructure:"reason_to_all,omitempty" flag:"reason-to-all" desc:"If set, use this reason for every cluster, ignoring any per-cluster reason values in the clusters file."`
}
