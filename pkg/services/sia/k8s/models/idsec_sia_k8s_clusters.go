package models

// IdsecSIAK8SClusters represents a list of K8S clusters.
type IdsecSIAK8SClusters struct {
	Clusters []IdsecSIAK8SCluster `json:"clusters" mapstructure:"clusters" flag:"clusters" desc:"List of K8s clusters."`
}
