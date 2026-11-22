// Package helper pre-selects the elevated user on the `az login` sign-in page: az is given this
// executable as $BROWSER, which drops prompt and adds login_hint before opening the real browser.
// Best-effort: if the helper does not run, az shows its normal account picker.
package helper

import (
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"

	scak8sazurecommonhelper "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/azure/common"
)

var azureBrowserHintEnabled atomic.Bool

// EnableAzureBrowserHint lets `az login` use the running executable as its $BROWSER.
// Call it only from an executable that checks IsAzureBrowserHelperInvocation at startup
// and then runs RunAzureBrowserHelper.
func EnableAzureBrowserHint() {
	azureBrowserHintEnabled.Store(true)
}

// DisableAzureBrowserHint reverses EnableAzureBrowserHint.
func DisableAzureBrowserHint() {
	azureBrowserHintEnabled.Store(false)
}

// IsBrowserHintEnabled reports whether EnableAzureBrowserHint has been called.
func IsBrowserHintEnabled() bool {
	return azureBrowserHintEnabled.Load()
}

const (
	azureBrowserHelperEnv = "IDSEC_AZ_BROWSER_HINT"
	// Passed in the environment, not argv, so the user name is not visible in process listings.
	azureBrowserHelperUserEnv = "IDSEC_AZ_BROWSER_HINT_USER"
)

// Only links on these hosts are rewritten, so the helper never redirects anywhere else.
var azureLoginHosts = map[string]bool{
	"login.microsoftonline.com": true,
	"login.microsoftonline.us":  true,
	"login.chinacloudapi.cn":    true,
}

var azureAuthorizePathSuffixes = []string{"/oauth2/v2.0/authorize", "/oauth2/authorize"}

// RewriteAzureAuthorizeURL removes prompt and sets login_hint on an https Entra authorize URL;
// any other URL, or an empty loginHint, is returned unchanged.
func RewriteAzureAuthorizeURL(raw, loginHint string) string {
	loginHint = strings.TrimSpace(loginHint)
	if loginHint == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !azureLoginHosts[strings.ToLower(u.Hostname())] {
		return raw
	}
	isAuthorize := false
	for _, suffix := range azureAuthorizePathSuffixes {
		if strings.HasSuffix(u.Path, suffix) {
			isAuthorize = true
			break
		}
	}
	if !isAuthorize {
		return raw
	}

	q := u.Query()
	q.Del("prompt")
	q.Set("login_hint", loginHint)
	u.RawQuery = q.Encode()
	return u.String()
}

// IsAzureBrowserHelperInvocation reports whether az started this process as its $BROWSER.
func IsAzureBrowserHelperInvocation(args []string) bool {
	if os.Getenv(azureBrowserHelperEnv) != "1" || len(args) != 1 {
		return false
	}
	lower := strings.ToLower(args[0])
	return strings.HasPrefix(lower, "https://") || strings.HasPrefix(lower, "http://")
}

// RunAzureBrowserHelper opens the rewritten link and returns the exit code (non-zero lets az
// fall back). It must not print: stdout and stderr belong to az and kubectl.
func RunAzureBrowserHelper(args []string) int {
	if len(args) != 1 {
		return 1
	}
	return runAzureBrowserHelper(args[0], os.Getenv(azureBrowserHelperUserEnv), openBrowser)
}

func runAzureBrowserHelper(rawURL, loginHint string, open func(string) error) int {
	// xdg-open honours $BROWSER; leaving it set would start this helper again.
	_ = os.Unsetenv("BROWSER")
	_ = os.Unsetenv(azureBrowserHelperEnv)
	_ = os.Unsetenv(azureBrowserHelperUserEnv)

	if err := open(RewriteAzureAuthorizeURL(rawURL, loginHint)); err != nil {
		return 1
	}
	return 0
}

// openBrowser does not wait for the launcher: Python's webbrowser blocks until $BROWSER exits,
// and az cannot start its localhost redirect listener until then.
func openBrowser(url string) error {
	name, args := browserCommand(runtime.GOOS, url, os.Getenv("SystemRoot"))
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = cmd.Process.Release()
	return nil
}

// On Windows rundll32 avoids `cmd /c start`, which parses & and %VAR% in the URL, and is
// called by absolute path so a rundll32.exe on PATH cannot replace it.
func browserCommand(goos, url, systemRoot string) (string, []string) {
	switch goos {
	case "windows":
		name := "rundll32"
		if systemRoot != "" {
			name = strings.TrimRight(systemRoot, `\/`) + `\System32\rundll32.exe`
		}
		return name, []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		return "/usr/bin/open", []string{url}
	default:
		return "xdg-open", []string{url}
	}
}

// AzureBrowserHelperEnvVars returns the env entries that make az use exe as its $BROWSER,
// or nil when the inputs fail the safety checks.
func AzureBrowserHelperEnvVars(exe, cloudUserName string, userBrowserSet bool) []string {
	cloudUserName = strings.TrimSpace(cloudUserName)
	switch {
	case cloudUserName == "", exe == "", userBrowserSet:
		return nil
	// $BROWSER containing whitespace is not run as a single command.
	case strings.ContainsAny(exe, " \t\r\n"):
		return nil
	case strings.ContainsAny(cloudUserName, "\x00\r\n"):
		return nil
	}

	// Over SSH or on headless Linux, setting $BROWSER disables az's device-code fallback.
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" || os.Getenv("SSH_CLIENT") != "" {
		return nil
	}
	if runtime.GOOS == "linux" && os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return nil
	}

	return []string{
		"BROWSER=" + exe,
		azureBrowserHelperEnv + "=1",
		azureBrowserHelperUserEnv + "=" + azureLoginHintFor(cloudUserName),
	}
}

// azureLoginHintFor returns the home-address form of a B2B guest UPN so Entra pre-selects
// the right account ("<user>_<homedomain>#EXT#@<tenant>" → "<user>@<homedomain>").
// Regular UPNs are returned unchanged.
func azureLoginHintFor(upn string) string {
	if !strings.Contains(strings.ToUpper(upn), scak8sazurecommonhelper.GuestUPNMarker) {
		return upn
	}
	if variants := scak8sazurecommonhelper.UPNVariants(upn); len(variants) >= 2 {
		return variants[1]
	}
	return upn
}
