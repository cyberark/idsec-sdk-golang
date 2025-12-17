// Package winrm provides Windows Remote Management (WinRM) connection capabilities
// for the IDSEC SDK Golang. This package implements the IdsecConnection interface
// to enable secure command execution on Windows machines using the WinRM protocol.
//
// The package supports HTTPS connections with optional certificate validation,
// automatic retry mechanisms, and handles large command execution through
// file-based chunking when commands exceed size limits.
//
// Key features:
//   - Secure WinRM HTTPS connections
//   - Automatic retry with connection failure detection
//   - Large command handling with UTF-16 encoding
//   - PowerShell script execution
//   - Connection suspend/restore functionality
//
// Example:
//
//	conn := NewIdsecWinRMConnection()
//	err := conn.Connect(&connectionsmodels.IdsecConnectionDetails{
//		Address: "windows-server.example.com",
//		Port:    5986,
//		Credentials: &connectionsmodels.IdsecConnectionCredentials{
//			User:     "administrator",
//			Password: "password",
//		},
//	})
//	if err != nil {
//		// handle error
//	}
//	defer conn.Disconnect()
//
//	result, err := conn.RunCommand(&connectionsmodels.IdsecConnectionCommand{
//		Command:    "Get-Process",
//		ExpectedRC: 0,
//	})
package winrm

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/masterzen/winrm"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/connections"
	connectionsmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common/connections"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/common/connections/connectiondata"
	"golang.org/x/text/encoding/unicode"
)

const (
	// WinRMHTTPSPort is the default port for WinRM HTTPS connections.
	WinRMHTTPSPort = 5986

	// WinRMHTTPPort is the default port for WinRM HTTP connections.
	WinRMHTTPPort = 5985
)

const (
	// winrmConnectionTimeout defines the maximum time to wait for WinRM connection establishment.
	winrmConnectionTimeout = 60 * time.Second

	// maxSingleCommandSize defines the maximum size in bytes for a single WinRM command
	// before it needs to be split into chunks and executed via a temporary file.
	maxSingleCommandSize = 2000

	// maxChunkSize defines the maximum size in bytes for each chunk when splitting
	// large commands for file-based execution.
	maxChunkSize = 4000
)

// IdsecWinRMConnection is a struct that implements the IdsecConnection interface for WinRM connections.
//
// It provides secure Windows Remote Management functionality including connection management,
// command execution, and automatic retry mechanisms. The connection supports both simple
// commands and large command execution through temporary file creation when commands
// exceed the maximum size limit.
//
// The struct maintains connection state and provides suspend/restore functionality
// for connection lifecycle management.
type IdsecWinRMConnection struct {
	connections.IdsecConnection
	isConnected bool
	isSuspended bool
	winrmClient *winrm.Client
	winrmShell  *winrm.Shell
	logger      *common.IdsecLogger

	runCommandMock func(command *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error)
}

// NewIdsecWinRMConnection creates a new instance of IdsecWinRMConnection.
//
// Creates and initializes a new WinRM connection instance with default settings.
// The connection is created in a disconnected state and must be explicitly
// connected using the Connect method before use.
//
// Returns a pointer to the newly created IdsecWinRMConnection instance with
// isConnected and isSuspended set to false, and a logger configured for
// WinRM operations.
//
// Example:
//
//	conn := NewIdsecWinRMConnection()
//	err := conn.Connect(connectionDetails)
//	if err != nil {
//		// handle connection error
//	}
func NewIdsecWinRMConnection() *IdsecWinRMConnection {
	return &IdsecWinRMConnection{
		isConnected: false,
		isSuspended: false,
		logger:      common.GetLogger("IdsecWinRMConnection", common.Unknown),
	}
}

func (c *IdsecWinRMConnection) isConnectionTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	return false
}

// Connect establishes a WinRM connection using the provided connection details.
//
// Establishes a secure WinRM HTTPS connection to the target Windows machine
// using the provided connection details. The method handles certificate
// validation, retry logic, and creates both the WinRM client and shell
// required for command execution.
//
// If the connection is already established, this method returns immediately
// without error. The method uses the default HTTPS port (5986) if no port
// is specified in the connection details.
//
// Parameters:
//   - connectionDetails: Connection configuration including address, port,
//     credentials, retry settings, and optional certificate settings
//
// Returns an error if the connection cannot be established, including cases
// where credentials are missing, certificate files cannot be read, or the
// WinRM client/shell creation fails.
//
// The method supports automatic retry with configurable retry count and
// tick period. Connection failures are detected and retried up to the
// specified limit.
//
// Example:
//
//	details := &connectionsmodels.IdsecConnectionDetails{
//		Address: "windows-server.example.com",
//		Port:    5986,
//		Credentials: &connectionsmodels.IdsecConnectionCredentials{
//			User:     "administrator",
//			Password: "password",
//		},
//		ConnectionRetries: 3,
//		RetryTickPeriod:   5,
//	}
//	err := conn.Connect(details)
//	if err != nil {
//		// handle connection error
//	}
func (c *IdsecWinRMConnection) Connect(connectionDetails *connectionsmodels.IdsecConnectionDetails) error {
	if c.isConnected {
		return nil
	}

	targetPort := WinRMHTTPSPort
	if connectionDetails.Port != 0 {
		targetPort = connectionDetails.Port
	}
	if connectionDetails.ConnectionRetries == 0 {
		connectionDetails.ConnectionRetries = 1
	}
	var err error
	var certData []byte
	certPath := ""
	trustCert := false
	if winrmData, ok := connectionDetails.ConnectionData.(*connectiondata.IdsecWinRMConnectionData); ok {
		certPath = winrmData.CertificatePath
		trustCert = winrmData.TrustCertificate
	}
	if certPath != "" {
		certData, err = os.ReadFile(certPath)
		if err != nil {
			return fmt.Errorf("failed to read certificate file: %w", err)
		}
	}
	isHTTPS := true
	if winrmData, ok := connectionDetails.ConnectionData.(*connectiondata.IdsecWinRMConnectionData); ok {
		if winrmData.Protocol == "http" {
			isHTTPS = false
		}
	}
	c.logger.Debug("Connecting to WinRM server [%s] on port [%d]", connectionDetails.Address, targetPort)
	endpoint := winrm.NewEndpoint(
		connectionDetails.Address,
		targetPort,
		isHTTPS,
		trustCert,
		certData,
		nil,
		nil,
		winrmConnectionTimeout,
	)
	if connectionDetails.Credentials == nil {
		return fmt.Errorf("missing credentials for WinRM connection")
	}

	var client *winrm.Client
	var shell *winrm.Shell
	for i := 0; i < connectionDetails.ConnectionRetries; i++ {
		params := winrm.DefaultParameters
		params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
		client, err = winrm.NewClientWithParameters(endpoint, connectionDetails.Credentials.User, connectionDetails.Credentials.Password, params)
		if err != nil {
			if (common.IsConnectionRefused(err) || c.isConnectionTimeoutError(err)) && i < connectionDetails.ConnectionRetries-1 {
				c.logger.Info("Failed to create WinRM client: %s - Retrying...", err.Error())
				time.Sleep(time.Duration(connectionDetails.RetryTickPeriod) * time.Second)
				continue
			}
			return fmt.Errorf("failed to create WinRM client: %w", err)
		}
		shell, err = client.CreateShell()
		if err != nil {
			if (common.IsConnectionRefused(err) || c.isConnectionTimeoutError(err) || strings.Contains(err.Error(), "invalid content type")) && i < connectionDetails.ConnectionRetries-1 {
				c.logger.Info("Failed to create WinRM shell: %s - Retrying...", err.Error())
				time.Sleep(time.Duration(connectionDetails.RetryTickPeriod) * time.Second)
				continue
			}
			return fmt.Errorf("failed to create WinRM shell: %w", err)
		}
		break
	}
	c.logger.Debug("WinRM client and shell created successfully for [%s]", connectionDetails.Address)
	c.winrmClient = client
	c.winrmShell = shell
	c.isConnected = true
	c.isSuspended = false
	return nil
}

// Disconnect closes the WinRM connection.
//
// Closes the active WinRM shell and cleans up the connection resources.
// If the connection is not currently established, this method returns
// immediately without error.
//
// The method attempts to close the WinRM shell gracefully. If the shell
// closure fails, a warning is logged but the method continues to clean
// up the connection state.
//
// After successful completion, the connection state is reset to disconnected
// and not suspended.
//
// Returns an error only in exceptional circumstances. Shell closure errors
// are logged as warnings but do not cause the method to fail.
//
// Example:
//
//	err := conn.Disconnect()
//	if err != nil {
//		// handle disconnect error (rare)
//	}
func (c *IdsecWinRMConnection) Disconnect() error {
	if !c.isConnected {
		return nil
	}
	err := c.winrmShell.Close()
	if err != nil {
		c.logger.Warning("failed to close WinRM shell: %s", err.Error())
	}
	c.winrmShell = nil
	c.winrmClient = nil
	c.isConnected = false
	c.isSuspended = false
	return nil
}

// SuspendConnection suspends the WinRM connection.
//
// Marks the connection as suspended without actually closing the underlying
// WinRM connection. When suspended, the connection will refuse to execute
// commands until it is restored using RestoreConnection.
//
// This is useful for temporarily disabling command execution while keeping
// the underlying network connection alive.
//
// Returns nil as this operation always succeeds.
//
// Example:
//
//	err := conn.SuspendConnection()
//	// Commands will now fail until RestoreConnection is called
func (c *IdsecWinRMConnection) SuspendConnection() error {
	c.isSuspended = true
	return nil
}

// RestoreConnection restores the WinRM connection.
//
// Restores a previously suspended connection, allowing command execution
// to resume. This method clears the suspended state without affecting
// the underlying WinRM connection.
//
// Returns nil as this operation always succeeds.
//
// Example:
//
//	err := conn.RestoreConnection()
//	// Commands can now be executed again
func (c *IdsecWinRMConnection) RestoreConnection() error {
	c.isSuspended = false
	return nil
}

// IsSuspended checks if the WinRM connection is suspended.
//
// Returns the current suspension state of the connection. When suspended,
// the connection will refuse to execute commands even if the underlying
// WinRM connection is still active.
//
// Returns true if the connection is currently suspended, false otherwise.
//
// Example:
//
//	if conn.IsSuspended() {
//		// Connection is suspended, restore before running commands
//		conn.RestoreConnection()
//	}
func (c *IdsecWinRMConnection) IsSuspended() bool {
	return c.isSuspended
}

// IsConnected checks if the WinRM connection is established.
//
// Returns the current connection state indicating whether a WinRM connection
// has been successfully established and is ready for use. This does not
// check the network connectivity, only the internal connection state.
//
// Returns true if the connection is established, false otherwise.
//
// Example:
//
//	if !conn.IsConnected() {
//		err := conn.Connect(connectionDetails)
//		if err != nil {
//			// handle connection error
//		}
//	}
func (c *IdsecWinRMConnection) IsConnected() bool {
	return c.isConnected
}

// runCommand executes a command on the remote machine using WinRM.
//
// This internal method handles the actual command execution logic, including
// splitting large commands into chunks and writing them to a temporary
// PowerShell script file if necessary.
//
// Parameters:
//   - command: The command configuration including the command string,
//     expected return code, and optional extra data for execution control
//
// Returns the command execution result containing stdout, stderr, and return
// code, or an error if the command cannot be executed or returns an unexpected
// return code.
//
// The method automatically handles commands larger than maxSingleCommandSize
// (2000 bytes) by splitting them into chunks, writing them to a temporary
// file on the remote machine, executing that file, and cleaning up afterward.
// Smaller commands are executed directly using PowerShell's encoded command
// feature with UTF-16 encoding.
//
// Example:
//
//	cmd := &connectionsmodels.IdsecConnectionCommand{
//		Command:    "Get-Process | Where-Object {$_.ProcessName -eq 'notepad'}",
func (c *IdsecWinRMConnection) runCommand(command *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
	c.logger.Debug("Running command [%s]", command.Command)

	if len(command.Command) > maxSingleCommandSize || (command.ExtraCommandData != nil && command.ExtraCommandData["force_command_split"] == true) {
		encoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
		utf16EncodedString, err := encoder.String(command.Command)
		if err != nil {
			return nil, fmt.Errorf("failed to encode string: %w", err)
		}
		encodedCommand := []byte(utf16EncodedString)
		maxSize := maxChunkSize
		var chunks [][]byte
		for i := 0; i < len(encodedCommand); i += maxSize {
			end := i + maxSize
			if end > len(encodedCommand) {
				end = len(encodedCommand)
			}
			chunks = append(chunks, encodedCommand[i:end])
		}

		commandUniqueFileName := strings.ReplaceAll(uuid.New().String(), "-", "")
		commandFile := fmt.Sprintf("C:\\%s.ps1", commandUniqueFileName)

		// Write chunks to the file
		for _, chunk := range chunks {
			c.logger.Debug("Running chunk write to file [%s]", commandFile)
			base64utf16EncodedString := base64.StdEncoding.EncodeToString(chunk)
			cmd, err := c.winrmShell.ExecuteWithContext(context.Background(), fmt.Sprintf(
				`powershell -Command "[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('%s')) | Add-Content -Path %s -Encoding Unicode -NoNewline"`,
				base64utf16EncodedString, commandFile))
			if err != nil {
				return nil, fmt.Errorf("failed to write chunk to file: %w", err)
			}
			cmd.Wait()
			c.logger.Debug("Chunk write rc: [%d]", cmd.ExitCode())
		}

		// Execute the PowerShell script
		c.logger.Debug("Executing command file [%s]", commandFile)
		commandOutput, err := c.winrmShell.ExecuteWithContext(context.Background(), fmt.Sprintf("powershell -File %s", commandFile))
		if err != nil {
			return nil, fmt.Errorf("failed to execute command: %w", err)
		}

		stdout := &bytes.Buffer{}
		stderr := &bytes.Buffer{}
		go io.Copy(stdout, commandOutput.Stdout) //nolint:errcheck
		go io.Copy(stderr, commandOutput.Stderr) //nolint:errcheck
		commandOutput.Wait()
		// Clean up the temporary file
		c.logger.Debug("Deleting command file [%s]", commandFile)
		_, _ = c.winrmShell.ExecuteWithContext(context.Background(), fmt.Sprintf("del /f %s", commandFile))
		if !command.IgnoreRC && command.ExpectedRC != commandOutput.ExitCode() {
			return nil, fmt.Errorf("failed to execute command [%s] - [%d] - [%s]", command.Command, commandOutput.ExitCode(), stderr.String())
		}

		c.logger.Debug("Command rc: [%d]", commandOutput.ExitCode())
		c.logger.Debug("Command stdout: [%s]", stdout)
		c.logger.Debug("Command stderr: [%s]", stderr)

		return &connectionsmodels.IdsecConnectionResult{
			Stdout: stdout.String(),
			Stderr: stderr.String(),
			RC:     commandOutput.ExitCode(),
		}, nil
	}

	encoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	utf16EncodedString, err := encoder.String(command.Command)
	if err != nil {
		return nil, fmt.Errorf("failed to encode string: %w", err)
	}
	base64utf16EncodedString := base64.StdEncoding.EncodeToString([]byte(utf16EncodedString))
	encodedCommand := fmt.Sprintf("powershell -encodedcommand \"%s\"", base64utf16EncodedString)
	commandOutput, err := c.winrmShell.ExecuteWithContext(context.Background(), encodedCommand)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %w", err)
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	go io.Copy(stdout, commandOutput.Stdout) //nolint:errcheck
	go io.Copy(stderr, commandOutput.Stderr) //nolint:errcheck
	commandOutput.Wait()
	if command.ExpectedRC != commandOutput.ExitCode() {
		return nil, fmt.Errorf("failed to execute command [%s] - [%d] - [%s]", command.Command, commandOutput.ExitCode(), stderr.String())
	}

	c.logger.Debug("Command rc: [%d]", commandOutput.ExitCode())
	c.logger.Debug("Command stdout: [%s]", stdout)
	c.logger.Debug("Command stderr: [%s]", stderr)

	return &connectionsmodels.IdsecConnectionResult{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
		RC:     commandOutput.ExitCode(),
	}, nil
}

func (c *IdsecWinRMConnection) getRunCommand() func(command *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
	if c.runCommandMock != nil {
		return c.runCommandMock
	}
	return c.runCommand
}

// RunCommand executes a command on the remote machine using WinRM.
//
// Executes the specified command on the remote Windows machine through the
// established WinRM connection. The method handles both small and large
// commands automatically, using different execution strategies based on
// command size.
//
// For commands smaller than maxSingleCommandSize (2000 bytes), the command
// is executed directly using PowerShell's encoded command feature with
// UTF-16 encoding. For larger commands, the method splits the command into
// chunks, writes them to a temporary PowerShell script file on the remote
// machine, executes the file, and cleans up afterward.
//
// The method can be forced to use the file-based approach for any command
// by setting ExtraCommandData["force_command_split"] to true.
//
// Parameters:
//   - command: The command configuration including the command string,
//     expected return code, and optional extra data for execution control
//
// Returns the command execution result containing stdout, stderr, and return
// code, or an error if the command cannot be executed or returns an unexpected
// return code.
//
// The method validates that the connection is active and not suspended before
// execution. Commands that return a different exit code than expected will
// result in an error.
//
// Example:
//
//	cmd := &connectionsmodels.IdsecConnectionCommand{
//		Command:    "Get-Process | Where-Object {$_.ProcessName -eq 'notepad'}",
//		ExpectedRC: 0,
//	}
//	result, err := conn.RunCommand(cmd)
//	if err != nil {
//		// handle execution error
//	}
//	fmt.Printf("Output: %s\n", result.Stdout)
//
// For large commands:
//
//	cmd := &connectionsmodels.IdsecConnectionCommand{
//		Command:    veryLargeScript,
//		ExpectedRC: 0,
//		ExtraCommandData: map[string]interface{}{
//			"force_command_split": true,
//		},
//	}
//	result, err := conn.RunCommand(cmd)
func (c *IdsecWinRMConnection) RunCommand(command *connectionsmodels.IdsecConnectionCommand) (*connectionsmodels.IdsecConnectionResult, error) {
	if !c.isConnected || c.isSuspended {
		return nil, fmt.Errorf("cannot run command while not being connected")
	}
	var result *connectionsmodels.IdsecConnectionResult
	var err error
	retryErr := common.RetryCall(
		func() error {
			result, err = c.getRunCommand()(command)
			return err
		},
		command.RetryCount,
		command.RetryDelay,
		nil,
		1,
		nil,
		nil,
	)
	if retryErr != nil {
		return nil, retryErr
	}
	return result, err
}
