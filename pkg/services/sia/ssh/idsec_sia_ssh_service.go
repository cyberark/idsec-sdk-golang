package ssh

import (
	"fmt"
	"os"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	sshmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/ssh/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sso"
	ssomodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sso/models"
)

const (
	sshGatewaySubdomainPart             = "ssh"
	defaultSSHExecutable                = "ssh"
	sshKeyFileMode          os.FileMode = 0600
)

// IdsecSIASSHService is a struct that implements the IdsecService interface and
// provides functionality for the SSH service of SIA. It mirrors the structure
// of IdsecSIADBService, reusing the SSO service to obtain short-lived
// credentials and spawning a local SSH client as a child process.
//
// The unexported function fields are test seams (same pattern used by
// IdsecSIASSHCAService): production code uses the defaults wired in
// NewIdsecSIASSHService while tests inject deterministic fakes via the
// helper accessors below (claimsFn / shortLivedSshKeyFn / executeFn).
type IdsecSIASSHService struct {
	*services.IdsecBaseService
	*services.IdsecISPBaseService
	ssoService *sso.IdsecSIASSOService

	parseClaims      func() (jwt.MapClaims, error)
	shortLivedSshKey func(*ssomodels.IdsecSIASSOGetSSHKey) (string, error)
	executeCommand   func(name string, args ...string) error
}

// NewIdsecSIASSHService creates a new instance of IdsecSIASSHService with the provided authenticators.
func NewIdsecSIASSHService(authenticators ...auth.IdsecAuth) (*IdsecSIASSHService, error) {
	sshService := &IdsecSIASSHService{}
	var sshServiceInterface services.IdsecService = sshService
	baseService, err := services.NewIdsecBaseService(sshServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "dpa", ".", "", sshService.refreshSIAAuth)
	if err != nil {
		return nil, err
	}
	sshService.IdsecBaseService = baseService
	sshService.IdsecISPBaseService = ispBaseService
	sshService.ssoService, err = sso.NewIdsecSIASSOService(ispBaseService)
	if err != nil {
		return nil, err
	}
	return sshService, nil
}

func (s *IdsecSIASSHService) refreshSIAAuth(client *common.IdsecClient) error {
	return isp.RefreshClient(client, s.ISPAuth())
}

// defaultClaims parses the current ISP client's JWT and returns its claims.
// Tests override this via the parseClaims test seam (see claimsFn).
func (s *IdsecSIASSHService) defaultClaims() (jwt.MapClaims, error) {
	parsedToken, _, err := new(jwt.Parser).ParseUnverified(s.ISPClient().GetToken(), jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected jwt claims type %T", parsedToken.Claims)
	}
	return claims, nil
}

func (s *IdsecSIASSHService) claimsFn() func() (jwt.MapClaims, error) {
	if s.parseClaims != nil {
		return s.parseClaims
	}
	return s.defaultClaims
}

func (s *IdsecSIASSHService) shortLivedSshKeyFn() func(*ssomodels.IdsecSIASSOGetSSHKey) (string, error) {
	if s.shortLivedSshKey != nil {
		return s.shortLivedSshKey
	}
	return s.ssoService.ShortLivedSshKey
}

func (s *IdsecSIASSHService) executeFn() func(string, ...string) error {
	if s.executeCommand != nil {
		return s.executeCommand
	}
	return common.ExecuteCommandArgs
}

// claimString reads a string field from JWT claims, returning an empty string
// if the claim is missing or of an unexpected type. We tolerate missing
// network/subdomain fields downstream so consumers can wire the values
// directly via flags if they happen to be absent from the token.
func claimString(claims jwt.MapClaims, key string) string {
	if value, ok := claims[key].(string); ok {
		return value
	}
	return ""
}

// proxyAddress builds the SIA SSH gateway hostname for the current tenant
// (e.g. "acme.ssh.cyberark.cloud").
func (s *IdsecSIASSHService) proxyAddress() (string, error) {
	claims, err := s.claimsFn()()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%s.%s", claimString(claims, "subdomain"), sshGatewaySubdomainPart, claimString(claims, "platform_domain")), nil
}

// connectionString builds the SIA SSH connection user-part, i.e. everything to
// the left of the final '@<gateway>'. The shape follows the public SIA SSH
// gateway syntax:
//
//	<username>#<subdomain>@<target_user>@<target_address>[:port][#<network>]
//
// or, when no target_user is supplied (Zero Standing flow):
//
//	<username>#<subdomain>@<target_address>[:port][#<network>]
func (s *IdsecSIASSHService) connectionString(targetAddress string, targetUsername string, targetPort int, networkName string) (string, error) {
	claims, err := s.claimsFn()()
	if err != nil {
		return "", err
	}
	addressNetwork := targetAddress
	if targetPort > 0 {
		addressNetwork = fmt.Sprintf("%s:%d", addressNetwork, targetPort)
	}
	if networkName != "" {
		addressNetwork = fmt.Sprintf("%s#%s", addressNetwork, networkName)
	}
	uniqueName := claimString(claims, "unique_name")
	subdomain := claimString(claims, "subdomain")
	if targetUsername != "" {
		return fmt.Sprintf("%s#%s@%s@%s", uniqueName, subdomain, targetUsername, addressNetwork), nil
	}
	return fmt.Sprintf("%s#%s@%s", uniqueName, subdomain, addressNetwork), nil
}

// stageEphemeralKey fetches the short-lived OpenSSH key from the SSO service
// in-memory (no user-visible file is created) and stages it into a freshly
// created temp file with 0600 permissions so the OpenSSH client will accept
// it. The returned cleanup must be invoked once the spawned ssh process has
// exited.
//
// We can't pass the key content directly on the ssh argv (OpenSSH requires a
// file path for -i), so a temp file is the minimum-friction way to keep the
// key off the user's $HOME and bounded to the lifetime of the SSH call.
func (s *IdsecSIASSHService) stageEphemeralKey(allowCaching bool) (string, func(), error) {
	keyContent, err := s.shortLivedSshKeyFn()(&ssomodels.IdsecSIASSOGetSSHKey{
		Format:       ssomodels.OpenSSH,
		OutputFormat: ssomodels.SSHKeyOutputFormatRaw,
		AllowCaching: allowCaching,
	})
	if err != nil {
		return "", nil, err
	}
	if keyContent == "" {
		return "", nil, fmt.Errorf("sso service returned an empty ssh key")
	}
	keyFile, err := os.CreateTemp("", "sia_ssh_key_*")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp ssh key file: %w", err)
	}
	keyPath := keyFile.Name()
	cleanup := func() {
		if err := os.Remove(keyPath); err != nil && !os.IsNotExist(err) {
			s.Logger.Warning("Failed to remove temp ssh key file [%s]: %v", keyPath, err)
		}
	}
	if _, err := keyFile.Write([]byte(keyContent)); err != nil {
		_ = keyFile.Close()
		cleanup()
		return "", nil, fmt.Errorf("failed to write temp ssh key file: %w", err)
	}
	if err := keyFile.Close(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to close temp ssh key file: %w", err)
	}
	if err := os.Chmod(keyPath, sshKeyFileMode); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("failed to set permissions on temp ssh key file [%s]: %w", keyPath, err)
	}
	return keyPath, cleanup, nil
}

// buildSSHArgs builds the argv passed to the SSH client. Arguments are
// produced as separate argv entries (no shell interpolation), so the '#' and
// '@' characters embedded in the SIA connection string are safe.
func (s *IdsecSIASSHService) buildSSHArgs(keyPath string, userAtGateway string, forceTTY bool, extraArgs []string, remoteCommand string) []string {
	args := []string{
		"-i", keyPath,
	}
	if forceTTY {
		args = append(args, "-t")
	}
	args = append(args, extraArgs...)
	args = append(args, userAtGateway)
	if remoteCommand != "" {
		args = append(args, remoteCommand)
	}
	return args
}

// Connect spawns the local SSH client and connects to the target through the
// SIA SSH gateway. When execution.Command is empty an interactive terminal
// session is opened; otherwise that command is executed remotely. In both
// modes the child process' stdin/stdout/stderr are wired to the current
// process. Set ForceTTY when a single command needs a remote TTY (e.g. `sudo`
// prompting for a password).
//
// The short-lived SSH key issued by the SSO service is staged into a temp
// file with 0600 permissions for the lifetime of the spawned SSH process and
// removed once it exits.
func (s *IdsecSIASSHService) Connect(execution *sshmodels.IdsecSIASSHConnectExecution) error {
	if execution == nil {
		return fmt.Errorf("execution parameters are required")
	}
	gateway, err := s.proxyAddress()
	if err != nil {
		return err
	}
	connectionString, err := s.connectionString(execution.TargetAddress, execution.TargetUsername, execution.TargetPort, execution.NetworkName)
	if err != nil {
		return err
	}
	keyPath, cleanup, err := s.stageEphemeralKey(execution.AllowCaching)
	if err != nil {
		return err
	}
	defer cleanup()

	sshPath := execution.SshPath
	if sshPath == "" {
		sshPath = defaultSSHExecutable
	}
	userAtGateway := fmt.Sprintf("%s@%s", connectionString, gateway)
	args := s.buildSSHArgs(keyPath, userAtGateway, execution.ForceTTY, execution.ExtraArgs, execution.Command)
	if execution.Command == "" {
		s.Logger.Info("Opening interactive ssh session to %s via %s", execution.TargetAddress, gateway)
	} else {
		s.Logger.Info("Running remote command on %s via %s", execution.TargetAddress, gateway)
	}
	return s.executeFn()(sshPath, args...)
}

// ServiceConfig returns the service configuration for the IdsecSIASSHService.
func (s *IdsecSIASSHService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
