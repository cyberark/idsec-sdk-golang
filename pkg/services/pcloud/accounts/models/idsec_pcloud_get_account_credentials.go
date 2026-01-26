package models

// Possible values for ActionType
const (
	Show    = "show"
	Copy    = "copy"
	Connect = "connect"
)

// IdsecPCloudGetAccountCredentials represents the details required to retrieve account credentials.
type IdsecPCloudGetAccountCredentials struct {
	AccountID           string `json:"account_id" mapstructure:"account_id" desc:"The ID of the account for which to retrieve the account secret" flag:"account-id" validate:"required"`
	Reason              string `json:"reason,omitempty" mapstructure:"reason,omitempty" desc:"Reason for retrieving the the account's secrets (password or SSH key)" flag:"reason"`
	TicketingSystemName string `json:"ticketing_system_name,omitempty" mapstructure:"ticketing_system_name,omitempty" desc:"Ticketing system name to use to retrieve the account secret" flag:"ticketing-system-name"`
	TicketID            string `json:"ticket_id,omitempty" mapstructure:"ticket_id,omitempty" desc:"Ticket ID of the ticketing system for retrieval of the secret" flag:"ticket-id"`
	Version             string `json:"version,omitempty" mapstructure:"version,omitempty" desc:"The version of the required secret. If there are no previous versions, the current password/key version is returned" flag:"version"`
	ActionType          string `json:"action_type" mapstructure:"action_type" desc:"The action the secret will be used for (show,copy,connect)" flag:"action-type" default:"show" choices:"show,copy,connect"`
	Machine             string `json:"machine,omitempty" mapstructure:"machine,omitempty" desc:"The address of the remote machine to which the account will connect" flag:"machine"`
}
