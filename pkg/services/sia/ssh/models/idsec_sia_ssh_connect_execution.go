package models

// IdsecSIASSHConnectExecution defines the structure for connecting to a target
// host through the SIA SSH gateway. When Command is empty the call opens an
// interactive terminal session (stdin/stdout/stderr wired to the current
// process, matching the UX of the DB service's interactive clients). When
// Command is non-empty the call runs that single command on the remote host
// and streams its stdin/stdout/stderr through the current process.
//
// The short-lived SSH key issued by the SSO service is never written to a
// user-visible folder; it lives only for the duration of the spawned SSH
// child process. Enable AllowCaching to reuse a previously-issued key from
// the SSO keyring cache rather than fetching a fresh one on every call.
type IdsecSIASSHConnectExecution struct {
	IdsecSIASSHBaseExecution `mapstructure:",squash"`
	Command                  string   `json:"command,omitempty" mapstructure:"command,omitempty" flag:"command" desc:"Optional single command to execute on the remote host. If empty, an interactive terminal session is opened."`
	ForceTTY                 bool     `json:"force_tty,omitempty" mapstructure:"force_tty,omitempty" flag:"force-tty" desc:"Force pseudo-terminal allocation (adds -t to the SSH client). Useful for single commands that require a TTY (e.g. sudo with password prompt)." default:"false"`
	AllowCaching             bool     `json:"allow_caching,omitempty" mapstructure:"allow_caching,omitempty" flag:"allow-caching" desc:"Reuse a cached short-lived SSH key from the SSO keyring (when present and not expired) instead of fetching a fresh one." default:"false"`
	ExtraArgs                []string `json:"extra_args,omitempty" mapstructure:"extra_args,omitempty" flag:"extra-args" desc:"Additional arguments passed through to the SSH client (e.g. -L, -o BatchMode=yes)."`
}
