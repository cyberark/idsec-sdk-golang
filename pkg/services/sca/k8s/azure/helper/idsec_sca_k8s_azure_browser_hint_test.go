package helper

import (
	"errors"
	"net/url"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

const testAzureAuthorizeURL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize" +
	"?client_id=04b07795-8ddb-461a-bbee-02f9e1bf7b46&response_type=code" +
	"&redirect_uri=http%3A%2F%2Flocalhost%3A51234&scope=https%3A%2F%2Fmanagement.core.windows.net%2F%2F.default" +
	"&prompt=select_account&state=abc&code_challenge=xyz&code_challenge_method=S256"

func TestRewriteAzureAuthorizeURL_DropsPromptAndSetsLoginHint(t *testing.T) {
	got := RewriteAzureAuthorizeURL(testAzureAuthorizeURL, "alex@contoso.com")

	u, err := url.Parse(got)
	require.NoError(t, err)
	q := u.Query()
	require.Empty(t, q["prompt"])
	require.Equal(t, "alex@contoso.com", q.Get("login_hint"))
	require.Equal(t, "04b07795-8ddb-461a-bbee-02f9e1bf7b46", q.Get("client_id"))
	require.Equal(t, "http://localhost:51234", q.Get("redirect_uri"))
	require.Equal(t, "abc", q.Get("state"))
	require.Equal(t, "xyz", q.Get("code_challenge"))
	require.Equal(t, "S256", q.Get("code_challenge_method"))
	require.Equal(t, "https", u.Scheme)
	require.Equal(t, "login.microsoftonline.com", u.Host)
	require.Equal(t, "/common/oauth2/v2.0/authorize", u.Path)
}

func TestRewriteAzureAuthorizeURL_ReplacesExistingLoginHint(t *testing.T) {
	got := RewriteAzureAuthorizeURL(testAzureAuthorizeURL+"&login_hint=someone@else.com", "alex@contoso.com")

	u, err := url.Parse(got)
	require.NoError(t, err)
	require.Equal(t, []string{"alex@contoso.com"}, u.Query()["login_hint"])
}

func TestRewriteAzureAuthorizeURL_EncodesSpecialCharactersInUser(t *testing.T) {
	user := "a+b&c=d#e@contoso.com"
	got := RewriteAzureAuthorizeURL(testAzureAuthorizeURL, user)

	u, err := url.Parse(got)
	require.NoError(t, err)
	require.Equal(t, user, u.Query().Get("login_hint"))
	require.Empty(t, u.Query().Get("c"))
	require.Empty(t, u.Fragment)
}

func TestRewriteAzureAuthorizeURL_LeavesOtherURLsUnchanged(t *testing.T) {
	tests := map[string]string{
		"not microsoft host":   "https://evil.example.com/oauth2/v2.0/authorize?prompt=select_account",
		"lookalike host":       "https://login.microsoftonline.com.evil.example/oauth2/v2.0/authorize?prompt=select_account",
		"http scheme":          "http://login.microsoftonline.com/common/oauth2/v2.0/authorize?prompt=select_account",
		"not authorize path":   "https://login.microsoftonline.com/common/oauth2/v2.0/token?prompt=select_account",
		"device login page":    "https://microsoft.com/devicelogin",
		"unparseable":          "https://login.microsoftonline.com/%zz",
		"empty":                "",
		"custom scheme":        "file:///etc/passwd",
		"missing host":         "https:///oauth2/v2.0/authorize",
		"authorize in a query": "https://login.microsoftonline.com/common/other?x=/oauth2/v2.0/authorize",
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, raw, RewriteAzureAuthorizeURL(raw, "alex@contoso.com"))
		})
	}
}

func TestRewriteAzureAuthorizeURL_EmptyUserLeavesURLUnchanged(t *testing.T) {
	require.Equal(t, testAzureAuthorizeURL, RewriteAzureAuthorizeURL(testAzureAuthorizeURL, ""))
	require.Equal(t, testAzureAuthorizeURL, RewriteAzureAuthorizeURL(testAzureAuthorizeURL, "   "))
}

func TestRewriteAzureAuthorizeURL_SovereignCloudHosts(t *testing.T) {
	for _, host := range []string{"login.microsoftonline.us", "login.chinacloudapi.cn"} {
		raw := "https://" + host + "/common/oauth2/v2.0/authorize?prompt=select_account&state=s"
		u, err := url.Parse(RewriteAzureAuthorizeURL(raw, "alex@contoso.com"))
		require.NoError(t, err)
		require.Empty(t, u.Query()["prompt"], host)
		require.Equal(t, "alex@contoso.com", u.Query().Get("login_hint"), host)
	}
}

func TestIsAzureBrowserHelperInvocation(t *testing.T) {
	link := "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?x=1"

	t.Run("marker unset", func(t *testing.T) {
		t.Setenv(azureBrowserHelperEnv, "")
		require.False(t, IsAzureBrowserHelperInvocation([]string{link}))
	})
	t.Run("marker with one URL", func(t *testing.T) {
		t.Setenv(azureBrowserHelperEnv, "1")
		require.True(t, IsAzureBrowserHelperInvocation([]string{link}))
	})
	t.Run("marker with an http URL", func(t *testing.T) {
		t.Setenv(azureBrowserHelperEnv, "1")
		require.True(t, IsAzureBrowserHelperInvocation([]string{"http://localhost:1234/x"}))
	})
	t.Run("marker with a non-web scheme", func(t *testing.T) {
		t.Setenv(azureBrowserHelperEnv, "1")
		require.False(t, IsAzureBrowserHelperInvocation([]string{"file:///etc/passwd"}))
	})
	t.Run("marker wrong value", func(t *testing.T) {
		t.Setenv(azureBrowserHelperEnv, "true")
		require.False(t, IsAzureBrowserHelperInvocation([]string{link}))
	})
	t.Run("no arguments", func(t *testing.T) {
		t.Setenv(azureBrowserHelperEnv, "1")
		require.False(t, IsAzureBrowserHelperInvocation(nil))
	})
	t.Run("more than one argument", func(t *testing.T) {
		t.Setenv(azureBrowserHelperEnv, "1")
		require.False(t, IsAzureBrowserHelperInvocation([]string{link, "extra"}))
	})
	t.Run("argument is a command not a URL", func(t *testing.T) {
		t.Setenv(azureBrowserHelperEnv, "1")
		require.False(t, IsAzureBrowserHelperInvocation([]string{"kubectl-login"}))
	})
}

func TestRunAzureBrowserHelper_OpensRewrittenURL(t *testing.T) {
	t.Setenv("BROWSER", "/usr/local/bin/idsec")
	t.Setenv(azureBrowserHelperEnv, "1")
	t.Setenv(azureBrowserHelperUserEnv, "alex@contoso.com")

	var opened string
	code := runAzureBrowserHelper(testAzureAuthorizeURL, "alex@contoso.com", func(s string) error {
		opened = s
		return nil
	})

	require.Equal(t, 0, code)
	u, err := url.Parse(opened)
	require.NoError(t, err)
	require.Empty(t, u.Query()["prompt"])
	require.Equal(t, "alex@contoso.com", u.Query().Get("login_hint"))
}

func TestRunAzureBrowserHelper_ClearsBrowserVariablesBeforeOpening(t *testing.T) {
	t.Setenv("BROWSER", "/usr/local/bin/idsec")
	t.Setenv(azureBrowserHelperEnv, "1")
	t.Setenv(azureBrowserHelperUserEnv, "alex@contoso.com")

	var browserAtOpen, markerAtOpen string
	runAzureBrowserHelper(testAzureAuthorizeURL, "alex@contoso.com", func(string) error {
		browserAtOpen = os.Getenv("BROWSER")
		markerAtOpen = os.Getenv(azureBrowserHelperEnv)
		return nil
	})

	require.Empty(t, browserAtOpen)
	require.Empty(t, markerAtOpen)
}

func TestRunAzureBrowserHelper_ReturnsFailureWhenBrowserCannotOpen(t *testing.T) {
	code := runAzureBrowserHelper(testAzureAuthorizeURL, "alex@contoso.com", func(string) error {
		return errors.New("no display")
	})
	require.Equal(t, 1, code)
}

func TestRunAzureBrowserHelper_NonMicrosoftURLOpenedUnchanged(t *testing.T) {
	const other = "https://example.com/page?prompt=select_account"
	var opened string
	code := runAzureBrowserHelper(other, "alex@contoso.com", func(s string) error {
		opened = s
		return nil
	})
	require.Equal(t, 0, code)
	require.Equal(t, other, opened)
}

func TestBrowserCommand(t *testing.T) {
	const link = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?a=1&b=2"

	name, args := browserCommand("darwin", link, "")
	require.Equal(t, "/usr/bin/open", name)
	require.Equal(t, []string{link}, args)

	name, args = browserCommand("linux", link, "")
	require.Equal(t, "xdg-open", name)
	require.Equal(t, []string{link}, args)

	name, args = browserCommand("windows", link, `C:\Windows`)
	require.Equal(t, `C:\Windows\System32\rundll32.exe`, name)
	require.Equal(t, []string{"url.dll,FileProtocolHandler", link}, args)

	name, _ = browserCommand("windows", link, `C:\Windows\`)
	require.Equal(t, `C:\Windows\System32\rundll32.exe`, name)

	name, _ = browserCommand("windows", link, "")
	require.Equal(t, "rundll32", name)
}

func TestRunAzureBrowserHelper_RejectsWrongArgumentCount(t *testing.T) {
	require.Equal(t, 1, RunAzureBrowserHelper(nil))
	require.Equal(t, 1, RunAzureBrowserHelper([]string{"a", "b"}))
}

func clearSSHAndDisplayEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	t.Setenv("SSH_CLIENT", "")
	t.Setenv("DISPLAY", ":99")
	t.Setenv("WAYLAND_DISPLAY", "")
}

func TestAzureBrowserHelperEnvVars(t *testing.T) {
	t.Run("sets browser, marker and user", func(t *testing.T) {
		clearSSHAndDisplayEnv(t)
		got := AzureBrowserHelperEnvVars("/usr/local/bin/idsec", "alex@contoso.com", false)
		require.Equal(t, []string{
			"BROWSER=/usr/local/bin/idsec",
			"IDSEC_AZ_BROWSER_HINT=1",
			"IDSEC_AZ_BROWSER_HINT_USER=alex@contoso.com",
		}, got)
	})
	t.Run("trims the user", func(t *testing.T) {
		clearSSHAndDisplayEnv(t)
		got := AzureBrowserHelperEnvVars("/usr/local/bin/idsec", "  alex@contoso.com ", false)
		require.Contains(t, got, "IDSEC_AZ_BROWSER_HINT_USER=alex@contoso.com")
	})

	skipped := map[string]struct {
		exe, user string
		userSet   bool
	}{
		"no elevated user":          {"/usr/local/bin/idsec", "", false},
		"blank elevated user":       {"/usr/local/bin/idsec", "   ", false},
		"no executable path":        {"", "alex@contoso.com", false},
		"user already set $BROWSER": {"/usr/local/bin/idsec", "alex@contoso.com", true},
		"path contains a space":     {"/Users/some one/bin/idsec", "alex@contoso.com", false},
		"path contains a tab":       {"/Users/some\tone/bin/idsec", "alex@contoso.com", false},
		"user contains a newline":   {"/usr/local/bin/idsec", "alex@contoso.com\nBROWSER=evil", false},
		"user contains a NUL":       {"/usr/local/bin/idsec", "alex\x00@contoso.com", false},
	}
	for name, tc := range skipped {
		t.Run("skipped: "+name, func(t *testing.T) {
			clearSSHAndDisplayEnv(t)
			require.Nil(t, AzureBrowserHelperEnvVars(tc.exe, tc.user, tc.userSet))
		})
	}

	for _, sshVar := range []string{"SSH_CONNECTION", "SSH_TTY", "SSH_CLIENT"} {
		sshVar := sshVar
		t.Run("skipped: "+sshVar+" set", func(t *testing.T) {
			clearSSHAndDisplayEnv(t)
			t.Setenv(sshVar, "10.0.0.1 1234 10.0.0.2 22")
			require.Nil(t, AzureBrowserHelperEnvVars("/usr/local/bin/idsec", "alex@contoso.com", false))
		})
	}

	if runtime.GOOS == "linux" {
		t.Run("skipped: headless Linux (no DISPLAY or WAYLAND_DISPLAY)", func(t *testing.T) {
			clearSSHAndDisplayEnv(t)
			t.Setenv("DISPLAY", "")
			t.Setenv("WAYLAND_DISPLAY", "")
			require.Nil(t, AzureBrowserHelperEnvVars("/usr/local/bin/idsec", "alex@contoso.com", false))
		})
		t.Run("active: Wayland-only Linux (WAYLAND_DISPLAY set, no DISPLAY)", func(t *testing.T) {
			clearSSHAndDisplayEnv(t)
			t.Setenv("DISPLAY", "")
			t.Setenv("WAYLAND_DISPLAY", "wayland-0")
			got := AzureBrowserHelperEnvVars("/usr/local/bin/idsec", "alex@contoso.com", false)
			require.NotNil(t, got, "Wayland-only desktops have a display and should use the browser helper")
		})
	}
}

func TestAzureLoginHintFor(t *testing.T) {
	// Regular UPN — returned unchanged.
	require.Equal(t, "alex@contoso.com", azureLoginHintFor("alex@contoso.com"))

	// B2B guest UPN — unfolded to home address so Entra pre-selects the right account.
	require.Equal(t, "alex@fabrikam.com", azureLoginHintFor("alex_fabrikam.com#EXT#@contoso.com"))

	// If UPNVariants cannot unfold (unexpected format), return the original.
	require.Equal(t, "#EXT#@contoso.com", azureLoginHintFor("#EXT#@contoso.com"))
}
