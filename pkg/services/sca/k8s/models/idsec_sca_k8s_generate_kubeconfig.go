package models

import "strings"

// IdsecSCAK8sGenerateKubeconfigRequest is the CLI schema for generate-kubeconfig (cobra flags / action wiring).
type IdsecSCAK8sGenerateKubeconfigRequest struct {
	CSP                string `json:"csp,omitempty" mapstructure:"csp,omitempty" flag:"csp" desc:"Cloud provider filter (aws | azure). Omit (with --all true) to generate for all CSPs."`
	All                string `json:"all,omitempty" mapstructure:"all,omitempty" flag:"all" default:"true" desc:"Generate kubeconfig for all CSPs: only \"true\" or \"false\" (default: true). Use --all true, --all false, or bare --all for true. A valid --csp still limits the response to that CSP."`
	KubeconfigLocation string `json:"kubeconfig_location,omitempty" mapstructure:"kubeconfig_location,omitempty" flag:"kubeconfig-location" desc:"Custom file path to write the kubeconfig. Overrides default ~/.kube/idsec-cli/<csp>.yaml"`
}

// IdsecSCAK8sGenerateKubeconfigResponse maps lowercase CSP name to kubeconfig YAML string.
type IdsecSCAK8sGenerateKubeconfigResponse map[string]string

// IdsecSCAK8sKubeconfigOutcome represents the result of a single CSP's kubeconfig
// generation within a parallel execution batch.
type IdsecSCAK8sKubeconfigOutcome struct {
	// CSP is the cloud provider for this outcome (lowercase: aws, azure).
	CSP string `json:"csp"`

	// Kubeconfig contains the generated YAML on success; empty on failure.
	Kubeconfig string `json:"kubeconfig,omitempty"`

	// Error contains the error message on failure; empty on success.
	Error string `json:"error,omitempty"`
}

// IsSuccess returns true if the kubeconfig generation succeeded (no error).
func (o *IdsecSCAK8sKubeconfigOutcome) IsSuccess() bool {
	return o.Error == ""
}

// IdsecSCAK8sGenerateKubeconfigParallelResponse aggregates results from parallel
// kubeconfig generation requests, separating successes from failures for easy
// handling of partial success scenarios.
//
// Callers should check HasFailures() to determine if any generations failed,
// and can iterate Succeeded/Failed slices independently.
type IdsecSCAK8sGenerateKubeconfigParallelResponse struct {
	// Succeeded contains all outcomes that completed without error.
	Succeeded []IdsecSCAK8sKubeconfigOutcome `json:"succeeded"`

	// Failed contains all outcomes that encountered an error.
	Failed []IdsecSCAK8sKubeconfigOutcome `json:"failed"`
}

// HasFailures returns true if any kubeconfig generation requests failed.
func (r *IdsecSCAK8sGenerateKubeconfigParallelResponse) HasFailures() bool {
	return len(r.Failed) > 0
}

// HasSuccesses returns true if any kubeconfig generation requests succeeded.
func (r *IdsecSCAK8sGenerateKubeconfigParallelResponse) HasSuccesses() bool {
	return len(r.Succeeded) > 0
}

// TotalCount returns the total number of generation attempts.
func (r *IdsecSCAK8sGenerateKubeconfigParallelResponse) TotalCount() int {
	return len(r.Succeeded) + len(r.Failed)
}

// SuccessCount returns the number of successful generations.
func (r *IdsecSCAK8sGenerateKubeconfigParallelResponse) SuccessCount() int {
	return len(r.Succeeded)
}

// FailureCount returns the number of failed generations.
func (r *IdsecSCAK8sGenerateKubeconfigParallelResponse) FailureCount() int {
	return len(r.Failed)
}

// ToMap converts the parallel response to the legacy map[csp]string format.
// For successful outcomes, the value is the kubeconfig YAML.
// For failed outcomes, the value is the error message prefixed with "API call failed: ".
func (r *IdsecSCAK8sGenerateKubeconfigParallelResponse) ToMap() IdsecSCAK8sGenerateKubeconfigResponse {
	result := make(IdsecSCAK8sGenerateKubeconfigResponse, r.TotalCount())
	for _, outcome := range r.Succeeded {
		result[strings.ToLower(outcome.CSP)] = outcome.Kubeconfig
	}
	for _, outcome := range r.Failed {
		result[strings.ToLower(outcome.CSP)] = "API call failed: " + outcome.Error
	}
	return result
}
