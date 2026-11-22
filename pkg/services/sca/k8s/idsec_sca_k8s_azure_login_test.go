package k8s

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	scak8sazurehelper "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/azure/helper"
)

// fakeAzCapturingEnv puts a stub `az` first on PATH that records the env it was started with.
func fakeAzCapturingEnv(t *testing.T) func() map[string]string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell script stub is not available on Windows")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "env.txt")
	script := "#!/bin/sh\n" +
		"printf 'BROWSER=%s\\nIDSEC_AZ_BROWSER_HINT=%s\\nIDSEC_AZ_BROWSER_HINT_USER=%s\\nARGS=%s\\n' " +
		"\"$BROWSER\" \"$IDSEC_AZ_BROWSER_HINT\" \"$IDSEC_AZ_BROWSER_HINT_USER\" \"$*\" > '" + out + "'\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "az"), []byte(script), 0o700))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	return func() map[string]string {
		raw, err := os.ReadFile(out)
		require.NoError(t, err)
		seen := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			k, v, _ := strings.Cut(line, "=")
			seen[k] = v
		}
		return seen
	}
}

func enableAzureBrowserHintForTest(t *testing.T) {
	t.Helper()
	scak8sazurehelper.EnableAzureBrowserHint()
	t.Cleanup(scak8sazurehelper.DisableAzureBrowserHint)
}

func TestRunAzLogin_NotEnabledDoesNotSetTheHelper(t *testing.T) {
	t.Setenv("BROWSER", "")
	require.NoError(t, os.Unsetenv("BROWSER"))
	seen := fakeAzCapturingEnv(t)

	require.NoError(t, runAzLogin("alex@contoso.com"))

	got := seen()
	require.Empty(t, got["BROWSER"])
	require.Empty(t, got["IDSEC_AZ_BROWSER_HINT"])
	require.Empty(t, got["IDSEC_AZ_BROWSER_HINT_USER"])
}

func TestRunAzLogin_GivesAzTheBrowserHelper(t *testing.T) {
	enableAzureBrowserHintForTest(t)
	exe, err := os.Executable()
	require.NoError(t, err)
	if strings.ContainsAny(exe, " \t") {
		t.Skip("test binary path contains whitespace, so the helper is intentionally not used")
	}
	clearSSHAndDisplayEnv(t)
	// Unset, not emptied: an empty-but-set $BROWSER counts as the user's own choice.
	t.Setenv("BROWSER", "")
	require.NoError(t, os.Unsetenv("BROWSER"))
	seen := fakeAzCapturingEnv(t)

	require.NoError(t, runAzLogin("alex@contoso.com"))

	got := seen()
	require.Equal(t, exe, got["BROWSER"])
	require.Equal(t, "1", got["IDSEC_AZ_BROWSER_HINT"])
	require.Equal(t, "alex@contoso.com", got["IDSEC_AZ_BROWSER_HINT_USER"])
	require.Equal(t, "login", got["ARGS"])
}

func TestRunAzLogin_WithoutElevatedUserDoesNotSetTheHelper(t *testing.T) {
	enableAzureBrowserHintForTest(t)
	t.Setenv("BROWSER", "")
	require.NoError(t, os.Unsetenv("BROWSER"))
	seen := fakeAzCapturingEnv(t)

	require.NoError(t, runAzLogin(""))

	got := seen()
	require.Empty(t, got["BROWSER"])
	require.Empty(t, got["IDSEC_AZ_BROWSER_HINT"])
	require.Empty(t, got["IDSEC_AZ_BROWSER_HINT_USER"])
}

func TestRunAzLogin_KeepsTheUsersOwnBrowser(t *testing.T) {
	enableAzureBrowserHintForTest(t)
	t.Setenv("BROWSER", "/usr/bin/my-browser")
	seen := fakeAzCapturingEnv(t)

	require.NoError(t, runAzLogin("alex@contoso.com"))

	got := seen()
	require.Equal(t, "/usr/bin/my-browser", got["BROWSER"])
	require.Empty(t, got["IDSEC_AZ_BROWSER_HINT"])
}

func clearSSHAndDisplayEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	t.Setenv("SSH_CLIENT", "")
	t.Setenv("DISPLAY", ":99")
	t.Setenv("WAYLAND_DISPLAY", "")
}
