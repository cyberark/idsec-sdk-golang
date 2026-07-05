package common

// IdsecPartialStateError is returned when an operation partially succeeds:
// the resource was created or updated in the backend but did not reach its target
// active state. The PartialResult field contains the resource as fetched from the
// API and should be persisted to Terraform state so the resource is not orphaned.
type IdsecPartialStateError struct {
	Err           error
	PartialResult interface{}
}

func (e *IdsecPartialStateError) Error() string {
	return e.Err.Error()
}

func (e *IdsecPartialStateError) Unwrap() error {
	return e.Err
}

// NewPartialStateError wraps an activation error together with the partial resource result.
func NewPartialStateError(err error, partialResult interface{}) *IdsecPartialStateError {
	return &IdsecPartialStateError{Err: err, PartialResult: partialResult}
}
