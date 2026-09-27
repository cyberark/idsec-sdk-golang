package common

// ErrNotFound is a sentinel that SDK services wrap when a requested resource does not exist.
// Provider Read handlers check for this via errors.Is to call resp.State.RemoveResource
// instead of surfacing an error diagnostic — which is the standard Terraform drift-detection
// contract: a resource that disappears outside Terraform is detected on the next plan and
// scheduled for recreation rather than causing a hard error.
var ErrNotFound = newNotFoundError()

type notFoundError struct{}

func newNotFoundError() *notFoundError { return &notFoundError{} }
func (e *notFoundError) Error() string { return "resource not found" }
