package connections

import (
	connectionsmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common/connections"
)

// IdsecConnection is an interface that defines methods for managing Idsec connections.
type IdsecConnection interface {
	// Connect establishes a connection using the provided connection details.
	Connect(connectionDetails *connectionsmodels.IdsecConnectionDetails) error
	// Disconnect closes the connection.
	Disconnect() error
	// SuspendConnection suspends the connection, making any command unable to run but will not close the connection
	SuspendConnection() error
	// RestoreConnection restores the connection, making commands runnable again
	RestoreConnection() error
	// IsSuspended checks if the connection is suspended.
	IsSuspended() bool
	// IsConnected checks if the connection is established.
	IsConnected() bool
	// RunCommand executes a command on the connected system.
	RunCommand(command *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error)
}
