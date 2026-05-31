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

// ExecuteCommandArgs executes a binary directly (no shell) with the provided arguments.
//
// ExecuteCommandArgs spawns the given executable as a direct child process and
// wires its stdin, stdout, and stderr to the current process's standard streams.
// Because it does not go through a shell, callers do not need to worry about
// shell quoting/escaping of arguments that contain special characters such as
// '#', '@', spaces, or quotes — every element of args is passed as a single,
// separate argv entry to the binary.
//
// This is the preferred way to spawn interactive clients (such as `ssh`,
// `psql`, etc.) whose arguments include connection strings with shell-special
// characters. Use ExecuteCommand instead when a shell command line with shell
// features (pipes, redirections, expansion) is needed.
//
// Parameters:
//   - name: The executable name or absolute path (e.g., "ssh", "/usr/bin/ssh").
//   - args: The arguments to pass to the executable.
//
// Returns an error if the command execution fails or if the command returns a
// non-zero exit code.
//
// Example:
//
//	err := ExecuteCommandArgs("ssh", "-i", "/path/to/key", "user@host", "uname -a")
//	if err != nil {
//		// handle error
//	}
func ExecuteCommandArgs(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}
