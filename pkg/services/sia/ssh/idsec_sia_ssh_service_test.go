package ssh

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	sshmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/ssh/models"
	ssomodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sso/models"
)

const (
	testSubdomain      = "acme"
	testPlatformDomain = "cyberark.cloud"
	testUniqueName     = "user@cyberark.cloud.12345"
	testGateway        = testSubdomain + ".ssh." + testPlatformDomain
	testTenantPrefix   = testUniqueName + "#" + testSubdomain // "user@cyberark.cloud.12345#acme"
)

// newTestService builds an IdsecSIASSHService with all production dependencies
// stubbed out: a real logger so the service can call s.Logger.* safely, a
// canned-claims function so JWT parsing never reaches a real ISP client, and
// no-op SSO/exec seams that tests override per-case.
func newTestService() *IdsecSIASSHService {
	return &IdsecSIASSHService{
		IdsecBaseService: &services.IdsecBaseService{
			Logger: common.GlobalLogger,
		},
		parseClaims: func() (jwt.MapClaims, error) {
			return jwt.MapClaims{
				"subdomain":       testSubdomain,
				"platform_domain": testPlatformDomain,
				"unique_name":     testUniqueName,
			}, nil
		},
		shortLivedSshKey: func(_ *ssomodels.IdsecSIASSOGetSSHKey) (string, error) {
			return "stub-key-content", nil
		},
		executeCommand: func(_ string, _ ...string) error {
			return nil
		},
	}
}

func TestProxyAddress(t *testing.T) {
	t.Parallel()
	svc := newTestService()

	got, err := svc.proxyAddress()
	require.NoError(t, err)
	require.Equal(t, testGateway, got)
}

func TestProxyAddress_ClaimsError(t *testing.T) {
	t.Parallel()
	svc := newTestService()
	svc.parseClaims = func() (jwt.MapClaims, error) {
		return nil, errors.New("invalid token")
	}

	got, err := svc.proxyAddress()
	require.Error(t, err)
	require.Equal(t, "", got)
	require.Contains(t, err.Error(), "invalid token")
}

func TestConnectionString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		targetAddress  string
		targetUsername string
		targetPort     int
		networkName    string
		expected       string
	}{
		{
			name:          "standing_access_address_only",
			targetAddress: "10.0.0.1",
			expected:      testTenantPrefix + "@10.0.0.1",
		},
		{
			name:           "vaulted_access_with_target_user",
			targetAddress:  "10.0.0.1",
			targetUsername: "ec2-user",
			expected:       testTenantPrefix + "@ec2-user@10.0.0.1",
		},
		{
			name:           "vaulted_access_with_port",
			targetAddress:  "10.0.0.1",
			targetUsername: "ec2-user",
			targetPort:     2222,
			expected:       testTenantPrefix + "@ec2-user@10.0.0.1:2222",
		},
		{
			name:           "vaulted_access_with_network",
			targetAddress:  "10.0.0.1",
			targetUsername: "ec2-user",
			networkName:    "prod-network",
			expected:       testTenantPrefix + "@ec2-user@10.0.0.1#prod-network",
		},
		{
			name:           "vaulted_access_with_port_and_network",
			targetAddress:  "10.0.0.1",
			targetUsername: "ec2-user",
			targetPort:     2222,
			networkName:    "prod-network",
			expected:       testTenantPrefix + "@ec2-user@10.0.0.1:2222#prod-network",
		},
		{
			name:          "standing_access_with_port_and_network",
			targetAddress: "10.0.0.1",
			targetPort:    2222,
			networkName:   "prod-network",
			expected:      testTenantPrefix + "@10.0.0.1:2222#prod-network",
		},
		{
			name:          "ignores_zero_port",
			targetAddress: "10.0.0.1",
			targetPort:    0,
			expected:      testTenantPrefix + "@10.0.0.1",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := newTestService()
			got, err := svc.connectionString(tc.targetAddress, tc.targetUsername, tc.targetPort, tc.networkName)
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestConnectionString_ClaimsError(t *testing.T) {
	t.Parallel()
	svc := newTestService()
	svc.parseClaims = func() (jwt.MapClaims, error) {
		return nil, errors.New("boom")
	}

	got, err := svc.connectionString("10.0.0.1", "ec2-user", 0, "")
	require.Error(t, err)
	require.Equal(t, "", got)
}

func TestBuildSSHArgs(t *testing.T) {
	t.Parallel()
	svc := newTestService()

	tests := []struct {
		name          string
		keyPath       string
		userAtGateway string
		forceTTY      bool
		extraArgs     []string
		remoteCommand string
		expected      []string
	}{
		{
			name:          "minimal_interactive",
			keyPath:       "/tmp/key",
			userAtGateway: "u@gw",
			expected:      []string{"-i", "/tmp/key", "u@gw"},
		},
		{
			name:          "force_tty",
			keyPath:       "/tmp/key",
			userAtGateway: "u@gw",
			forceTTY:      true,
			expected:      []string{"-i", "/tmp/key", "-t", "u@gw"},
		},
		{
			name:          "extra_args_only",
			keyPath:       "/tmp/key",
			userAtGateway: "u@gw",
			extraArgs:     []string{"-L", "1234:host:22", "-o", "BatchMode=yes"},
			expected:      []string{"-i", "/tmp/key", "-L", "1234:host:22", "-o", "BatchMode=yes", "u@gw"},
		},
		{
			name:          "remote_command_only",
			keyPath:       "/tmp/key",
			userAtGateway: "u@gw",
			remoteCommand: "uname -a",
			expected:      []string{"-i", "/tmp/key", "u@gw", "uname -a"},
		},
		{
			name:          "force_tty_and_extra_args_and_command",
			keyPath:       "/tmp/key",
			userAtGateway: "u@gw",
			forceTTY:      true,
			extraArgs:     []string{"-o", "StrictHostKeyChecking=accept-new"},
			remoteCommand: "id",
			expected: []string{
				"-i", "/tmp/key",
				"-t",
				"-o", "StrictHostKeyChecking=accept-new",
				"u@gw",
				"id",
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := svc.buildSSHArgs(tc.keyPath, tc.userAtGateway, tc.forceTTY, tc.extraArgs, tc.remoteCommand)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestStageEphemeralKey_Success(t *testing.T) {
	t.Parallel()
	const keyContent = "this-is-a-fake-openssh-key"

	svc := newTestService()
	var capturedReq *ssomodels.IdsecSIASSOGetSSHKey
	svc.shortLivedSshKey = func(req *ssomodels.IdsecSIASSOGetSSHKey) (string, error) {
		capturedReq = req
		return keyContent, nil
	}

	keyPath, cleanup, err := svc.stageEphemeralKey(true)
	require.NoError(t, err)
	require.NotEmpty(t, keyPath)
	require.NotNil(t, cleanup)

	// The SSO call must request raw + openssh and propagate AllowCaching.
	require.NotNil(t, capturedReq)
	require.Equal(t, ssomodels.OpenSSH, capturedReq.Format)
	require.Equal(t, ssomodels.SSHKeyOutputFormatRaw, capturedReq.OutputFormat)
	require.True(t, capturedReq.AllowCaching)

	// The file must exist with the exact SSO-returned content.
	gotContent, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	require.Equal(t, keyContent, string(gotContent))

	// And — on POSIX — be locked down to 0600 so OpenSSH will accept it.
	// Windows reports a different permission model so the bit-exact check is
	// skipped there.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(keyPath)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0600), info.Mode().Perm(), "ssh key must be 0600 to be accepted by OpenSSH")
	}

	cleanup()
	_, statErr := os.Stat(keyPath)
	require.True(t, os.IsNotExist(statErr), "cleanup must remove the temp key file")
}

func TestStageEphemeralKey_EmptyContentRejected(t *testing.T) {
	t.Parallel()
	svc := newTestService()
	svc.shortLivedSshKey = func(_ *ssomodels.IdsecSIASSOGetSSHKey) (string, error) {
		return "", nil
	}

	keyPath, cleanup, err := svc.stageEphemeralKey(false)
	require.Error(t, err)
	require.Empty(t, keyPath)
	require.Nil(t, cleanup)
	require.Contains(t, err.Error(), "empty ssh key")
}

func TestStageEphemeralKey_SSOErrorPropagates(t *testing.T) {
	t.Parallel()
	svc := newTestService()
	svc.shortLivedSshKey = func(_ *ssomodels.IdsecSIASSOGetSSHKey) (string, error) {
		return "", errors.New("sso unavailable")
	}

	keyPath, cleanup, err := svc.stageEphemeralKey(false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "sso unavailable")
	require.Empty(t, keyPath)
	require.Nil(t, cleanup)
}

func TestConnect_NilExecution(t *testing.T) {
	t.Parallel()
	svc := newTestService()
	err := svc.Connect(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "execution parameters are required")
}

func TestConnect_Interactive_SpawnsSSHWithExpectedArgv(t *testing.T) {
	t.Parallel()
	const keyContent = "ephemeral-key-1"

	svc := newTestService()
	svc.shortLivedSshKey = func(_ *ssomodels.IdsecSIASSOGetSSHKey) (string, error) {
		return keyContent, nil
	}

	var gotName string
	var gotArgs []string
	var keyAtSpawn string
	svc.executeCommand = func(name string, args ...string) error {
		gotName = name
		gotArgs = args
		// Capture the staged key path & confirm the file still exists during
		// the spawn (i.e. cleanup hasn't fired yet).
		for i, a := range args {
			if a == "-i" && i+1 < len(args) {
				keyAtSpawn = args[i+1]
				break
			}
		}
		_, statErr := os.Stat(keyAtSpawn)
		require.NoError(t, statErr, "temp key must still exist while ssh is running")
		return nil
	}

	err := svc.Connect(&sshmodels.IdsecSIASSHConnectExecution{
		IdsecSIASSHBaseExecution: sshmodels.IdsecSIASSHBaseExecution{
			TargetAddress:  "10.0.0.1",
			TargetUsername: "ec2-user",
		},
	})
	require.NoError(t, err)

	require.Equal(t, defaultSSHExecutable, gotName)
	require.NotEmpty(t, keyAtSpawn)
	require.Equal(t,
		[]string{
			"-i", keyAtSpawn,
			testTenantPrefix + "@ec2-user@10.0.0.1@" + testGateway,
		},
		gotArgs,
	)

	// After Connect returns, the deferred cleanup must have removed the key.
	_, statErr := os.Stat(keyAtSpawn)
	require.True(t, os.IsNotExist(statErr), "temp key must be removed after Connect returns")
}

func TestConnect_RemoteCommand_AppendsCommandAndForceTTY(t *testing.T) {
	t.Parallel()

	svc := newTestService()
	svc.shortLivedSshKey = func(_ *ssomodels.IdsecSIASSOGetSSHKey) (string, error) {
		return "ephemeral-key-2", nil
	}

	var gotArgs []string
	svc.executeCommand = func(_ string, args ...string) error {
		gotArgs = args
		return nil
	}

	err := svc.Connect(&sshmodels.IdsecSIASSHConnectExecution{
		IdsecSIASSHBaseExecution: sshmodels.IdsecSIASSHBaseExecution{
			TargetAddress:  "10.0.0.1",
			TargetUsername: "ec2-user",
			TargetPort:     2222,
			NetworkName:    "prod-network",
		},
		Command:   "sudo systemctl status nginx",
		ForceTTY:  true,
		ExtraArgs: []string{"-o", "StrictHostKeyChecking=accept-new"},
	})
	require.NoError(t, err)

	// Last arg must be the remote command verbatim.
	require.Equal(t, "sudo systemctl status nginx", gotArgs[len(gotArgs)-1])
	// -t must be present (after -i <key>, before extra args).
	require.Contains(t, gotArgs, "-t")
	// Connection string must include port, network, and gateway.
	expectedTarget := testTenantPrefix + "@ec2-user@10.0.0.1:2222#prod-network@" + testGateway
	require.Contains(t, gotArgs, expectedTarget)
	// Extra args must be passed through verbatim.
	require.Contains(t, strings.Join(gotArgs, " "), "-o StrictHostKeyChecking=accept-new")
}

func TestConnect_CustomSshPath(t *testing.T) {
	t.Parallel()
	svc := newTestService()

	var gotName string
	svc.executeCommand = func(name string, _ ...string) error {
		gotName = name
		return nil
	}

	err := svc.Connect(&sshmodels.IdsecSIASSHConnectExecution{
		IdsecSIASSHBaseExecution: sshmodels.IdsecSIASSHBaseExecution{
			TargetAddress: "10.0.0.1",
			SshPath:       "/usr/local/bin/ssh",
		},
	})
	require.NoError(t, err)
	require.Equal(t, "/usr/local/bin/ssh", gotName)
}

func TestConnect_PropagatesSpawnErrorAndStillCleansUp(t *testing.T) {
	t.Parallel()

	svc := newTestService()
	svc.shortLivedSshKey = func(_ *ssomodels.IdsecSIASSOGetSSHKey) (string, error) {
		return "ephemeral-key-3", nil
	}

	var keyAtSpawn string
	svc.executeCommand = func(_ string, args ...string) error {
		for i, a := range args {
			if a == "-i" && i+1 < len(args) {
				keyAtSpawn = args[i+1]
				break
			}
		}
		return fmt.Errorf("ssh exited 255")
	}

	err := svc.Connect(&sshmodels.IdsecSIASSHConnectExecution{
		IdsecSIASSHBaseExecution: sshmodels.IdsecSIASSHBaseExecution{
			TargetAddress: "10.0.0.1",
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "ssh exited 255")
	require.NotEmpty(t, keyAtSpawn)
	_, statErr := os.Stat(keyAtSpawn)
	require.True(t, os.IsNotExist(statErr), "temp key must be cleaned up even when ssh fails")
}

func TestConnect_PropagatesClaimsError_NoKeyFetched(t *testing.T) {
	t.Parallel()

	svc := newTestService()
	svc.parseClaims = func() (jwt.MapClaims, error) {
		return nil, errors.New("expired token")
	}
	keyFetched := false
	svc.shortLivedSshKey = func(_ *ssomodels.IdsecSIASSOGetSSHKey) (string, error) {
		keyFetched = true
		return "irrelevant", nil
	}
	executed := false
	svc.executeCommand = func(_ string, _ ...string) error {
		executed = true
		return nil
	}

	err := svc.Connect(&sshmodels.IdsecSIASSHConnectExecution{
		IdsecSIASSHBaseExecution: sshmodels.IdsecSIASSHBaseExecution{
			TargetAddress: "10.0.0.1",
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "expired token")
	require.False(t, keyFetched, "must short-circuit before reaching SSO when claims fail")
	require.False(t, executed, "must not spawn ssh when claims fail")
}

func TestConnect_PropagatesSSOError_NoSpawn(t *testing.T) {
	t.Parallel()

	svc := newTestService()
	svc.shortLivedSshKey = func(_ *ssomodels.IdsecSIASSOGetSSHKey) (string, error) {
		return "", errors.New("sso 503")
	}
	executed := false
	svc.executeCommand = func(_ string, _ ...string) error {
		executed = true
		return nil
	}

	err := svc.Connect(&sshmodels.IdsecSIASSHConnectExecution{
		IdsecSIASSHBaseExecution: sshmodels.IdsecSIASSHBaseExecution{
			TargetAddress: "10.0.0.1",
		},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "sso 503")
	require.False(t, executed, "ssh must not be spawned when SSO fails")
}

func TestServiceConfig(t *testing.T) {
	t.Parallel()
	svc := newTestService()
	cfg := svc.ServiceConfig()
	require.Equal(t, "sia-ssh", cfg.ServiceName)
	require.Contains(t, cfg.RequiredAuthenticatorNames, "isp")
	require.Contains(t, cfg.ActionSchemas, "connect")
}
