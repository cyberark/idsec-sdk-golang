package models

// IdsecSIAK8SListClusters is a struct that represents the request for listing the K8s clusters
// that are available for the current user to access, from the Idsec SIA K8S service.
type IdsecSIAK8SListClusters struct {
	OutputFile string `json:"output_file,omitempty" mapstructure:"output_file,omitempty" flag:"output-file" desc:"Save the clusters list as a JSON file to this path."`
}
