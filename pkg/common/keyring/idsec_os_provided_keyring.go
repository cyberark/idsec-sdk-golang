// Package keyring provides keyring utilities for the IDSEC SDK.
//
// This package contains internal implementations including a OS based keyring
// system for secure password storage. The IdsecOSProvidedKeyring
// provides OS based storage.
package keyring

import (
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/99designs/keyring"
	"github.com/danieljoos/wincred"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
)

const (
	keyringPrefix     = "idsec_sdk_golang"
	keyringItemPrefix = keyringPrefix + "_" // exact format written by SetPassword
)

// OSKeyringOpen is a variable that points to the keyring.Open function from the go-keyring package.
var OSKeyringOpen = keyring.Open

// winCredDiscoveryEnabled selects Credential Manager enumeration in ClearAllPasswords.
// It is a package-level var, not an inline runtime.GOOS check, so that tests on
// any platform can exercise the Windows path by flipping it to true.
var winCredDiscoveryEnabled = runtime.GOOS == "windows"

// winCredList enumerates Credential Manager entries whose TargetName has the given
// prefix. Swapped to a fake in tests.
var winCredList = wincred.FilteredList

// winCredDelete removes the Credential Manager generic credential with the given
// target name. Swapped to a fake in tests.
var winCredDelete = func(targetName string) error {
	return wincred.NewGenericCredential(targetName).Delete()
}

// IdsecOSProvidedKeyring provides an OS-based keyring implementation for secure password storage.
//
// IdsecOSProvidedKeyring wraps the underlying OS keyring and falls back to a basic keyring
// implementation if the OS keyring is unavailable or encounters errors. It is intended for
// use in environments where secure credential storage is required.
//
// Fields:
//   - IdsecKeyringImpl: Embedded base implementation for keyring operations.
//   - fallbackKeyring: The fallback keyring implementation used if OS keyring fails.
//   - logger: Logger instance for warning and error messages.
type IdsecOSProvidedKeyring struct {
	IdsecKeyringImpl
	fallbackKeyring IdsecKeyringImpl
	logger          *common.IdsecLogger
}

func (b *IdsecOSProvidedKeyring) keyringForService(serviceName string) (keyring.Keyring, error) {
	cfg := keyring.Config{
		ServiceName: serviceName,
		AllowedBackends: []keyring.BackendType{
			keyring.KeychainBackend,      // macOS Keychain
			keyring.WinCredBackend,       // Windows Credential Manager
			keyring.SecretServiceBackend, // Linux (libsecret/gnome-keyring)
			keyring.KWalletBackend,       // Linux KDE
			keyring.PassBackend,          // Linux 'pass'
		},
	}
	switch runtime.GOOS {
	case "darwin":
		cfg.KeychainName = "login"
		cfg.KeychainTrustApplication = true
		cfg.KeychainSynchronizable = false
	case "linux":
		cfg.LibSecretCollectionName = "default"
	}
	keyringStore, err := OSKeyringOpen(cfg)
	if err != nil {
		return nil, err
	}
	return keyringStore, nil
}

// NewIdsecOSProvidedKeyring creates a new IdsecOSProvidedKeyring instance.
//
// NewIdsecOSProvidedKeyring initializes the OS-based keyring with a fallback keyring implementation.
// The fallbackKeyring is used if the OS keyring is unavailable or encounters errors.
//
// An unusable fallback is rejected, because every error path in this type ends in the
// fallback and a keyring that cannot fall back is worse than no keyring at all: the
// failure would surface as a panic at the first platform-store error rather than as an
// error the caller can act on. The documented way to build a fallback is
// NewIdsecBasicKeyring, which reports failure by returning nil, and passing that result
// straight through produces a *IdsecBasicKeyring nil that is not equal to nil once it is
// held in an IdsecKeyringImpl. Both that case and a plainly nil interface are rejected
// here, so a caller only has to check the one result this constructor returns.
//
// Parameters:
//   - fallbackKeyring: IdsecKeyringImpl. The fallback keyring implementation to use.
//
// Returns a pointer to the initialized IdsecOSProvidedKeyring, or nil if fallbackKeyring
// is nil or is a nil *IdsecBasicKeyring.
//
// Example:
//
//	fallback := NewIdsecBasicKeyring()
//	keyring := NewIdsecOSProvidedKeyring(fallback)
//	if keyring == nil {
//	    // Handle keyring initialization failure
//	}
func NewIdsecOSProvidedKeyring(fallbackKeyring IdsecKeyringImpl) *IdsecOSProvidedKeyring {
	if fallbackKeyring == nil {
		return nil
	}
	if basicKeyring, ok := fallbackKeyring.(*IdsecBasicKeyring); ok && basicKeyring == nil {
		return nil
	}
	return &IdsecOSProvidedKeyring{
		fallbackKeyring: fallbackKeyring,
		logger:          common.GetLogger("IdsecOSProvidedKeyring", common.Unknown),
	}
}

// SetPassword stores a password in the OS keyring for the specified service and username.
//
// SetPassword attempts to securely store the password using the OS keyring. If the OS keyring
// operation fails, it logs a warning and falls back to the provided basic keyring implementation.
//
// Parameters:
//   - serviceName: string. The name of the service for which the password is stored.
//   - username: string. The username associated with the password.
//   - password: string. The password to store.
//
// Returns an error if the password could not be stored in either the OS keyring or the fallback keyring.
//
// Example:
//
//	err := keyring.SetPassword("my_service", "user1", "secret")
//	if err != nil {
//	    // handle error
//	}
func (b *IdsecOSProvidedKeyring) SetPassword(serviceName string, username string, password string) error {
	keyringStore, err := b.keyringForService(serviceName)
	if err != nil {
		b.logger.Warning("Failed to open OS keyring: %v. Falling back to basic keyring.", err)
		return b.fallbackKeyring.SetPassword(serviceName, username, password)
	}
	err = keyringStore.Set(keyring.Item{
		Key:  fmt.Sprintf("%s_%s", keyringPrefix, username),
		Data: []byte(password),
	})
	if err != nil {
		b.logger.Warning("Failed to set password in OS keyring: %v. Falling back to basic keyring.", err)
		return b.fallbackKeyring.SetPassword(serviceName, username, password)
	}
	return nil
}

// GetPassword retrieves a password from the OS keyring for the specified service and username.
//
// GetPassword attempts to retrieve the password using the OS keyring. If the OS keyring
// operation fails, it logs a warning and falls back to the provided basic keyring implementation.
//
// Parameters:
//   - serviceName: string. The name of the service for which the password is retrieved.
//   - username: string. The username associated with the password.
//
// Returns the password as a string and an error if retrieval fails from both the OS keyring and the fallback keyring.
//
// Example:
//
//	password, err := keyring.GetPassword("my_service", "user1")
//	if err != nil {
//	    // handle error
//	}
func (b *IdsecOSProvidedKeyring) GetPassword(serviceName string, username string) (string, error) {
	keyringStore, err := b.keyringForService(serviceName)
	if err != nil {
		b.logger.Warning("Failed to open OS keyring: %v. Falling back to basic keyring.", err)
		return b.fallbackKeyring.GetPassword(serviceName, username)
	}
	item, err := keyringStore.Get(fmt.Sprintf("%s_%s", keyringPrefix, username))
	if err != nil {
		// If the key is not found, return empty without error on non-Windows systems
		// This is because windows permissions might block us from even setting the key
		// Or the cred themselves are too long for windows cred manager
		if errors.Is(err, keyring.ErrKeyNotFound) && runtime.GOOS != "windows" {
			return "", nil
		}
		b.logger.Warning("Failed to get password from OS keyring: %v. Falling back to basic keyring.", err)
		return b.fallbackKeyring.GetPassword(serviceName, username)
	}
	return string(item.Data), nil
}

// DeletePassword removes a password from the OS keyring for the specified service and username.
//
// DeletePassword attempts to delete the password using the OS keyring. If the OS keyring
// operation fails, it logs a warning and falls back to the provided basic keyring implementation.
//
// Parameters:
//   - serviceName: string. The name of the service for which the password is deleted.
//   - username: string. The username associated with the password.
//
// Returns an error if the password could not be deleted from either the OS keyring or the fallback keyring.
//
// Example:
//
//	err := keyring.DeletePassword("my_service", "user1")
//	if err != nil {
//	    // handle error
//	}
func (b *IdsecOSProvidedKeyring) DeletePassword(serviceName string, username string) error {
	keyringStore, err := b.keyringForService(serviceName)
	if err != nil {
		b.logger.Warning("Failed to open OS keyring: %v. Falling back to basic keyring.", err)
		return b.fallbackKeyring.DeletePassword(serviceName, username)
	}
	err = keyringStore.Remove(fmt.Sprintf("%s_%s", keyringPrefix, username))
	if err != nil {
		b.logger.Warning("Failed to delete password from OS keyring: %v. Falling back to basic keyring.", err)
		return b.fallbackKeyring.DeletePassword(serviceName, username)
	}
	return nil
}

// isIdsecWinCredTarget reports whether a Credential Manager target name was written
// by SetPassword through the 99designs/keyring WinCred backend.
// Targets have the form "keyring:<service>:idsec_sdk_golang_<username>".
//
// The leading ":" anchors the match to the item-key segment, so a service whose
// name contains the prefix (e.g. "keyring:idsec_sdk_golang_tools:foreign") does
// not match. The trailing "_" rejects non-idsec keys that share only a prefix
// (e.g. "keyring:svc:idsec_sdk_golangci").
func isIdsecWinCredTarget(target string) bool {
	rest, ok := strings.CutPrefix(target, "keyring:")
	if !ok {
		return false
	}
	return strings.Contains(rest, ":"+keyringItemPrefix)
}

// clearWindowsCredentials deletes every idsec entry from Windows Credential Manager,
// across all keyring services, without needing to know the service names in advance.
// An entry that disappears between listing and deletion (concurrent clear, logout)
// is treated as already cleared.
func clearWindowsCredentials() error {
	creds, err := winCredList("keyring:*")
	if err != nil {
		return fmt.Errorf("list credential manager: %w", err)
	}
	var errs []error
	for _, c := range creds {
		if c == nil || !isIdsecWinCredTarget(c.TargetName) {
			continue
		}
		if err := winCredDelete(c.TargetName); err != nil && !errors.Is(err, wincred.ErrElementNotFound) {
			errs = append(errs, fmt.Errorf("delete %q: %w", c.TargetName, err))
		}
	}
	return errors.Join(errs...)
}

// ClearAllPasswords removes every idsec credential from the OS keyring and from the
// file-backed fallback keyring.
//
// On Windows, it enumerates Credential Manager and deletes every entry written by
// this SDK, across every service, so callers do not need to know which services
// were used and orphan entries from deleted profiles are also cleared.
//
// On macOS and Linux the idsec entries are already reachable from a single
// service query: macOS Keychain returns all services when the service filter is
// absent, and Linux stores all idsec tokens in the "default" Secret Service
// collection regardless of service name. clearService("") therefore covers all
// entries on those platforms with no additional work.
//
// The fallback (file) keyring is always cleared, even if the OS keyring fails,
// because tokens too large for the OS store are written to it instead.
// All errors are joined and returned together. Clearing an already-empty keyring
// returns nil.
func (b *IdsecOSProvidedKeyring) ClearAllPasswords() error {
	var osErr error
	if winCredDiscoveryEnabled {
		osErr = clearWindowsCredentials()
	} else {
		osErr = b.clearService("")
	}
	if osErr != nil {
		b.logger.Warning("Failed to clear OS keyring: %v. Clearing file keyring anyway.", osErr)
		osErr = fmt.Errorf("os keyring: %w", osErr)
	}
	var fileErr error
	if err := b.fallbackKeyring.ClearAllPasswords(); err != nil {
		fileErr = fmt.Errorf("file keyring: %w", err)
	}
	return errors.Join(osErr, fileErr)
}

func (b *IdsecOSProvidedKeyring) clearService(svc string) error {
	store, err := b.keyringForService(svc)
	if err != nil {
		return err
	}
	keys, err := store.Keys()
	if err != nil {
		return err
	}
	var errs []error
	for _, k := range keys {
		if !strings.HasPrefix(k, keyringItemPrefix) {
			continue
		}
		if err := store.Remove(k); err != nil && !errors.Is(err, keyring.ErrKeyNotFound) {
			errs = append(errs, fmt.Errorf("remove %q: %w", k, err))
		}
	}
	return errors.Join(errs...)
}

// ListKeys returns the usernames stored under the given serviceName in the
// OS keyring. On OS keyring open/list failure, falls back to the basic keyring.
// Secret values are not returned.
func (b *IdsecOSProvidedKeyring) ListKeys(serviceName string) ([]string, error) {
	keyringStore, err := b.keyringForService(serviceName)
	if err != nil {
		b.logger.Warning("Failed to open OS keyring: %v. Falling back to basic keyring.", err)
		return b.fallbackKeyring.ListKeys(serviceName)
	}
	rawKeys, err := keyringStore.Keys()
	if err != nil {
		b.logger.Warning("Failed to list keys from OS keyring: %v. Falling back to basic keyring.", err)
		return b.fallbackKeyring.ListKeys(serviceName)
	}
	keys := make([]string, 0, len(rawKeys))
	for _, k := range rawKeys {
		if trimmed, ok := strings.CutPrefix(k, keyringItemPrefix); ok {
			keys = append(keys, trimmed)
		}
	}
	return keys, nil
}
