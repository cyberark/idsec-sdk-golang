package models

// IdsecSCAK8sGenerateKubeconfigRequest is the CLI schema for generate-kubeconfig (cobra flags / action wiring).
type IdsecSCAK8sGenerateKubeconfigRequest struct {
	CSP                string `json:"csp,omitempty" mapstructure:"csp,omitempty" flag:"csp" desc:"Cloud provider filter (aws | azure | gcp). Omit to generate for all CSPs."`
	All                string `json:"all,omitempty" mapstructure:"all,omitempty" flag:"all" default:"true" desc:"Generate kubeconfig for all CSPs: only \"true\" or \"false\" (default: true). Use --all true, --all false, or bare --all for true. Sent as the API all query param; a valid --csp still limits the response to that CSP."`
	KubeconfigLocation string `json:"kubeconfig_location,omitempty" mapstructure:"kubeconfig_location,omitempty" flag:"kubeconfig-location" desc:"Custom file path to write the kubeconfig. Overrides default ~/.kube/idsec-cli/<csp>.yaml"`
}

// IdsecSCAK8sGenerateKubeconfigResponse maps lowercase CSP name to kubeconfig YAML string.
type IdsecSCAK8sGenerateKubeconfigResponse map[string]string
