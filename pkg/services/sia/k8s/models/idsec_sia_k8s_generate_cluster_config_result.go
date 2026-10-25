package models

// IdsecSIAK8SGenerateClusterConfigResult is a struct that represents the result of generating a
// kubeconfig file for a set of K8s clusters, as returned by IdsecSIAK8SService.GenerateClusterConfig.
//
// This is a dedicated output-only struct (rather than reusing IdsecSIAK8SGenerateClusterConfig, the
// request model) so that callers that convert the action's result into Terraform state via
// reflection (see internal/schemas.StructToStateObject) have a struct to reflect over instead of a
// bare string, which panics on reflect.Type.NumField().
type IdsecSIAK8SGenerateClusterConfigResult struct {
	KubeconfigPath string `json:"kubeconfig_path" mapstructure:"kubeconfig_path" flag:"kubeconfig-path" desc:"Full path to the generated kubeconfig file."`
}
