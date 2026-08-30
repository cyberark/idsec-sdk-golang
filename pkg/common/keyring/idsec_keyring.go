// Package keyring provides keyring utilities for the IDSEC SDK.
//
// This package implements cross-platform keyring support with automatic fallback mechanisms
// for different environments including Docker containers, WSL, and various operating systems.
// The keyring handles token expiration, automatic cleanup, and secure storage of authentication
// credentials for IDSEC SDK applications.
package keyring

import (
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

// Env vars and definitions
const (
	IdsecBasicKeyringOverrideEnvVar    = "IDSEC_BASIC_KEYRING"
	DBusSessionEnvVar                  = "DBUS_SESSION_BUS_ADDRESS"
	DefaultExpirationGraceDeltaSeconds = 60
	MaxKeyringRecordTimeHours          = 12
)

// ErrKeyringUnavailable indicates that no keyring backend could be initialized.
//
// Every backend is built on the basic keyring, whose constructor reports failure by
// returning nil, which happens when no home directory resolves and the keyring paths are
// not both configured explicitly. Handing that nil back as an IdsecKeyringImpl would
// produce a non-nil interface wrapping a nil pointer, which panics on first use and which
// a caller cannot detect by comparing the interface against nil, so the failure is
// reported as this sentinel instead.
//
// A caller that receives it has no credential cache available. Since the cache only ever
// saves a round trip, the reasonable response is to authenticate without one rather than
// to fail.
//
// Example:
//
//	if errors.Is(err, ErrKeyringUnavailable) {
//	    // No credential cache on this host, authenticate without caching
//	}
var ErrKeyringUnavailable = errors.New("keyring is unavailable")

// IdsecKeyringImpl defines the interface for keyring operations.
type IdsecKeyringImpl interface {
	SetPassword(serviceName string, username string, password string) error
	GetPassword(serviceName string, username string) (string, error)
	DeletePassword(serviceName string, username string) error
	ClearAllPasswords() error
	ListKeys(serviceName string) ([]string, error)
}

// IdsecKeyringInterface defines the methods for saving and loading authentication tokens
type IdsecKeyringInterface interface {
	SaveToken(profile *models.IdsecProfile, token *auth.IdsecToken, postfix string, enforceBasicKeyring bool) error
	LoadToken(profile *models.IdsecProfile, postfix string, enforceBasicKeyring bool) (*auth.IdsecToken, error)
}

// IdsecKeyring represents a keyring for storing and retrieving authentication tokens.
//
// IdsecKeyring provides a secure storage mechanism for authentication tokens with
// automatic fallback to basic keyring when system keyrings are unavailable. It
// supports different keyring backends based on the operating system and environment,
// including Docker containers and WSL environments.
//
// The keyring handles token expiration, refresh token management, and automatic
// cleanup of expired tokens based on configurable time limits.
type IdsecKeyring struct {
	serviceName string
	logger      *common.IdsecLogger
}

// NewIdsecKeyring creates a new instance of IdsecKeyring with the specified service name.
//
// The service name is used as a namespace for storing tokens in the keyring,
// allowing multiple applications or services to use the same keyring without
// conflicts.
//
// Parameters:
//   - serviceName: The name used to identify this service's tokens in the keyring
//
// Returns a new IdsecKeyring instance configured with the provided service name
// and a logger for keyring operations.
//
// Example:
//
//	keyring := NewIdsecKeyring("myapp")
func NewIdsecKeyring(serviceName string) *IdsecKeyring {
	return &IdsecKeyring{
		serviceName: serviceName,
		logger:      common.GetLogger("IdsecKeyring", common.Unknown),
	}
}

func (a *IdsecKeyring) isDocker() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		return strings.Contains(string(data), "docker")
	}
	return false
}

func (a *IdsecKeyring) isWSL() bool {
	if data, err := os.ReadFile("/proc/version"); err == nil {
		return strings.Contains(string(data), "Microsoft")
	}
	return false
}

// GetKeyring returns a keyring instance based on the operating system and environment.
//
// GetKeyring automatically selects the most appropriate keyring backend based on
// the current environment. It falls back to basic keyring in Docker containers,
// WSL environments, when the IDSEC_BASIC_KEYRING environment variable is set, or
// when enforceBasicKeyring is true. For Windows, macOS, and Linux systems with
// proper D-Bus session, it attempts to use system-specific secure storage.
//
// Every backend needs a basic keyring, either as the backend itself or as the fallback
// the OS-provided backend uses when the platform store cannot be reached, so it is built
// first and a failure to build it fails the call. Returning it instead would put a nil
// *IdsecBasicKeyring inside a non-nil IdsecKeyringImpl, which no nil check by the caller
// can detect and which panics on first use. That is reachable wherever no home directory
// resolves, such as a minimal container image, and it is exactly the graceful cache miss
// this backend exists to provide, so it is reported as ErrKeyringUnavailable instead.
//
// Parameters:
//   - enforceBasicKeyring: When true, forces the use of basic keyring regardless of environment
//
// Returns a keyring implementation configured for the current environment, or
// ErrKeyringUnavailable if no keyring could be initialized.
//
// Example:
//
//	keyring, err := idsecKeyring.GetKeyring(false)
//	if err != nil {
//	    // handle error
//	}
func (a *IdsecKeyring) GetKeyring(enforceBasicKeyring bool) (IdsecKeyringImpl, error) {
	basicKeyring := NewIdsecBasicKeyring()
	if basicKeyring == nil {
		return nil, ErrKeyringUnavailable
	}
	if a.isDocker() || a.isWSL() || os.Getenv(IdsecBasicKeyringOverrideEnvVar) != "" || enforceBasicKeyring {
		return basicKeyring, nil
	}
	if runtime.GOOS == "windows" {
		return a.osProvidedKeyring(basicKeyring)
	}
	if runtime.GOOS == "darwin" {
		return a.osProvidedKeyring(basicKeyring)
	}
	if runtime.GOOS == "linux" && os.Getenv(DBusSessionEnvVar) != "" {
		return a.osProvidedKeyring(basicKeyring)
	}
	return basicKeyring, nil
}

// osProvidedKeyring wraps a basic keyring in the OS-provided backend.
//
// The wrap is rejected rather than returned when it fails, for the same reason
// GetKeyring rejects a nil basic keyring: a nil *IdsecOSProvidedKeyring inside a non-nil
// IdsecKeyringImpl is indistinguishable from a working one until it is used.
func (a *IdsecKeyring) osProvidedKeyring(fallbackKeyring IdsecKeyringImpl) (IdsecKeyringImpl, error) {
	osKeyring := NewIdsecOSProvidedKeyring(fallbackKeyring)
	if osKeyring == nil {
		return nil, ErrKeyringUnavailable
	}
	return osKeyring, nil
}

// SaveToken saves an authentication token to the keyring for the specified profile and postfix.
//
// SaveToken stores the provided token in the keyring using a composite key format
// of "serviceName-postfix" and the profile name. The token is serialized to JSON
// before storage. If the initial save fails, it automatically falls back to basic
// keyring storage, unless the keyring that failed is already the basic keyring, in
// which case the failure is returned directly. The fallback recurses at most once,
// because it sets enforceBasicKeyring, which selects the basic keyring and so makes the
// retry return its error directly rather than fall back again.
//
// When no keyring can be initialized at all, ErrKeyringUnavailable is returned without
// any attempt to store the token and without a fallback attempt, since the fallback is
// the backend that could not be initialized.
//
// Parameters:
//   - profile: The IDSEC profile containing the profile name used as the keyring username
//   - token: The authentication token to store in the keyring
//   - postfix: A suffix added to the service name to create unique keys for different token types
//   - enforceBasicKeyring: When true, uses basic keyring without attempting system keyring first
//
// Returns an error if the token cannot be saved to any available keyring backend, or
// ErrKeyringUnavailable if no backend could be initialized.
//
// Example:
//
//	err := keyring.SaveToken(profile, token, "access", false)
//	if err != nil {
//	    // handle save error
//	}
func (a *IdsecKeyring) SaveToken(profile *models.IdsecProfile, token *auth.IdsecToken, postfix string, enforceBasicKeyring bool) error {
	a.logger.Info("Trying to save token [%s-%s] of profile [%s]", a.serviceName, postfix, profile.ProfileName)
	kr, err := a.GetKeyring(enforceBasicKeyring)
	if err != nil {
		return err
	}
	tokenData, err := json.Marshal(token)
	if err != nil {
		return err
	}
	if err := kr.SetPassword(profile.ProfileName, a.serviceName+"-"+postfix, string(tokenData)); err != nil {
		if _, isBasicKeyring := kr.(*IdsecBasicKeyring); !isBasicKeyring && !enforceBasicKeyring {
			a.logger.Warning("Falling back to basic keyring as we failed to save token with keyring [%v]", kr)
			return a.SaveToken(profile, token, postfix, true)
		}
		a.logger.Warning("Failed to save token [%v]", err)
		return err
	}
	a.logger.Info("Saved token successfully")
	return nil
}

// LoadToken loads an authentication token from the keyring for the specified profile and postfix.
//
// LoadToken retrieves and validates a stored authentication token from the keyring.
// It performs automatic token expiration checking and cleanup. For tokens without
// refresh capability that are expired beyond the grace period, the token is removed
// and nil is returned. For tokens with refresh capability that have been cached
// too long, they are also removed and nil is returned. If the initial load fails,
// it automatically falls back to basic keyring, unless the keyring that failed is
// already the basic keyring, in which case the failure is returned directly. The fallback
// recurses at most once, because it sets enforceBasicKeyring, which selects the basic
// keyring and so makes the retry return its error directly rather than fall back again.
//
// When no keyring can be initialized at all, ErrKeyringUnavailable is returned without a
// fallback attempt, since the fallback is the backend that could not be initialized.
//
// Parameters:
//   - profile: The IDSEC profile containing the profile name used as the keyring username
//   - postfix: A suffix added to the service name to match the key used during SaveToken
//   - enforceBasicKeyring: When true, uses basic keyring without attempting system keyring first
//
// Returns the loaded token if found and valid, nil if no token exists or token
// is expired, an error if the keyring operation fails, or ErrKeyringUnavailable if no
// backend could be initialized.
//
// Example:
//
//	token, err := keyring.LoadToken(profile, "access", false)
//	if err != nil {
//	    // handle load error
//	}
//	if token == nil {
//	    // no valid token found, need to authenticate
//	}
func (a *IdsecKeyring) LoadToken(profile *models.IdsecProfile, postfix string, enforceBasicKeyring bool) (*auth.IdsecToken, error) {
	a.logger.Info("Trying to load token [%s-%s] of profile [%s]", a.serviceName, postfix, profile.ProfileName)
	kr, err := a.GetKeyring(enforceBasicKeyring)
	if err != nil {
		return nil, err
	}
	tokenData, err := kr.GetPassword(profile.ProfileName, a.serviceName+"-"+postfix)
	if err != nil {
		if _, isBasicKeyring := kr.(*IdsecBasicKeyring); !isBasicKeyring && !enforceBasicKeyring {
			a.logger.Warning("Falling back to basic keyring as we failed to load token with keyring [%v]", kr)
			return a.LoadToken(profile, postfix, true)
		}
		a.logger.Warning("Failed to load cached token [%v]", err)
		return nil, err
	}
	if tokenData == "" {
		a.logger.Info("No token found")
		return nil, nil
	}
	var token auth.IdsecToken
	if err := json.Unmarshal([]byte(tokenData), &token); err != nil {
		a.logger.Info("Token failed to be parsed [%v]", err)
		return nil, err
	}
	if !time.Time(token.ExpiresIn).IsZero() {
		if token.RefreshToken == "" && token.TokenType != auth.Internal && time.Time(token.ExpiresIn).Before(time.Now().Add(-DefaultExpirationGraceDeltaSeconds*time.Second)) {
			a.logger.Info("Token is expired and no refresh token exists")
			err := kr.DeletePassword(profile.ProfileName, a.serviceName+"-"+postfix)
			if err != nil {
				return nil, err
			}
			return nil, nil
		}
		if token.RefreshToken != "" && time.Time(token.ExpiresIn).Add(MaxKeyringRecordTimeHours*time.Hour).Before(time.Now()) {
			a.logger.Info("Token is expired and has been in the cache for too long before another usage")
			err := kr.DeletePassword(profile.ProfileName, a.serviceName+"-"+postfix)
			if err != nil {
				return nil, err
			}
			return nil, nil
		}
	}
	a.logger.Info("Loaded token successfully")
	return &token, nil
}
