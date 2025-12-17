package models

// IdsecSIAK8SGenerateKubeconfig is a struct that represents the request for generating a kubeconfig file from the Idsec SIA K8S service.
type IdsecSIAK8SGenerateKubeconfig struct {
	Folder string `json:"folder" mapstructure:"folder" flag:"folder" desc:"Output folder to write the kubeconfig to" default:"~/.kube"`
}
