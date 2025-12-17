package models

// IdsecSCAJobStatusResponse represents the polled status of an ongoing SCA discovery job.
//
// Fields:
//   - JobID: Identifier of the job being polled.
//   - Operation: Backend operation name (optional).
//   - Status: Current job state (e.g. running, success, failure).
//   - LastUpdated: Timestamp of last status update (format defined by backend).
//   - AlreadyRunning: Indicates a similar job was already in progress when started.
//   - TotalExecuted: Arbitrary execution metrics map returned by backend.
//   - AdditionalInfo: Arbitrary additional information map returned by backend.
//   - Error: Populated when Status indicates failure.
//
// NOTE: File relocated from pkg/services/uap/sca/models/idsec_sca_job_status.go.
// Import path updated to github.com/cyberark/idsec-sdk-golang/pkg/services/sca/models.
type IdsecSCAJobStatusResponse struct {
	JobID          string                 `json:"job_id,omitempty" mapstructure:"job_id,omitempty" flag:"job-id" desc:"Identifier of the job being polled."`
	Operation      string                 `json:"operation,omitempty" mapstructure:"operation,omitempty" flag:"operation" desc:"Backend operation name (optional)."`
	Status         string                 `json:"status,omitempty" mapstructure:"status,omitempty" flag:"status" desc:"Current job state (running | success | failure)."`
	LastUpdated    string                 `json:"last_updated,omitempty" mapstructure:"last_updated,omitempty" flag:"last-updated" desc:"Timestamp of last status update (backend defined format)."`
	AlreadyRunning bool                   `json:"already_running,omitempty" mapstructure:"already_running,omitempty" flag:"already-running" desc:"Indicates a similar job was already in progress when started."`
	TotalExecuted  map[string]interface{} `json:"total_executed,omitempty" mapstructure:"total_executed,omitempty" flag:"total-executed" desc:"Execution metrics map returned by backend."`
	AdditionalInfo map[string]interface{} `json:"additional_info,omitempty" mapstructure:"additional_info,omitempty" flag:"additional-info" desc:"Additional information map returned by backend."`
	Error          string                 `json:"error,omitempty" mapstructure:"error,omitempty" flag:"error" desc:"Failure details populated when status indicates failure."`
}
