package common

import (
	"os"
	"os/exec"
	"runtime"
)

// ExecuteCommand executes a shell command on the local system.
//
// ExecuteCommand runs the provided command line string using the appropriate
// shell for the current operating system. On Windows, it uses cmd.exe with /C flag,
// and on Unix-like systems (Linux, macOS), it uses sh with -c flag.
//
// The command's stdin, stdout, and stderr are connected to the current process's
// standard streams, allowing for interactive command execution.
//
// Parameters:
//   - commandLine: The command line string to execute (e.g., "psql -h host -U user")
//
// Returns an error if the command execution fails or if the command returns a non-zero exit code.
//
// Example:
//
//	err := ExecuteCommand("psql -h localhost -U postgres -d mydb")
//	if err != nil {
//		// handle error
//	}
func ExecuteCommand(commandLine string) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd.exe", "/C", commandLine)
	} else {
		cmd = exec.Command("sh", "-c", commandLine)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}
