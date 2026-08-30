package keyring

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

// isolateKeyringEnvironment points both the keyring folder and the master secret
// file at paths private to the test.
//
// Both locations have to be redirected. The master secret deliberately lives outside
// the keyring folder, so a test that only redirects the folder writes key material
// into the home directory of whoever is running the suite.
func isolateKeyringEnvironment(t *testing.T) (folder string, keyFile string) {
	t.Helper()

	folder = t.TempDir()
	keyFile = filepath.Join(t.TempDir(), "keyring.key")
	t.Setenv(IdsecBasicKeyringFolderEnvVar, folder)
	t.Setenv(IdsecBasicKeyringKeyFileEnvVar, keyFile)
	return folder, keyFile
}

// newIsolatedKeyring returns a keyring whose folder and master secret are private
// to the test.
func newIsolatedKeyring(t *testing.T) *IdsecBasicKeyring {
	t.Helper()

	isolateKeyringEnvironment(t)
	keyring := NewIdsecBasicKeyring()
	if keyring == nil {
		t.Fatal("Failed to create keyring for test")
	}
	return keyring
}

// seedUnreadableKeyring replaces the stored state with content the keyring cannot
// interpret, alongside a leftover sidecar that does not describe it.
func seedUnreadableKeyring(t *testing.T, keyring *IdsecBasicKeyring) {
	t.Helper()

	if err := os.WriteFile(keyring.keyringFilePath, []byte("this is not keyring content"), 0600); err != nil {
		t.Fatalf("Failed to seed keyring file: %v", err)
	}
	if err := os.WriteFile(keyring.macFilePath, []byte(strings.Repeat("a", 64)), 0600); err != nil {
		t.Fatalf("Failed to seed sidecar file: %v", err)
	}
}

// seedKeyringWithoutItsKeyFile stores a readable entry and then removes the master
// secret, which leaves every stored record unopenable.
func seedKeyringWithoutItsKeyFile(t *testing.T, keyring *IdsecBasicKeyring) {
	t.Helper()

	if err := keyring.SetPassword("github", "testuser", "testpassword"); err != nil {
		t.Fatalf("Failed to seed keyring entry: %v", err)
	}
	if err := os.Remove(keyring.keyFilePath); err != nil {
		t.Fatalf("Failed to remove the master secret: %v", err)
	}
	// The keyring caches what it derived while writing, so a fresh instance is needed
	// for the read to actually consult the removed key file.
	keyring.masterSecret = nil
	keyring.keys = nil
}

// assertKeyringStateRemoved verifies that no keyring state is left behind.
func assertKeyringStateRemoved(t *testing.T, keyring *IdsecBasicKeyring) {
	t.Helper()

	for _, path := range []string{keyring.keyringFilePath, keyring.macFilePath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("Expected '%s' to be removed, stat returned %v", filepath.Base(path), err)
		}
	}
}

// assertMasterSecretPresent verifies that the master secret survived an operation
// that discarded the cache it protects.
func assertMasterSecretPresent(t *testing.T, keyring *IdsecBasicKeyring) {
	t.Helper()

	secret, err := os.ReadFile(keyring.keyFilePath)
	if err != nil {
		t.Fatalf("Expected the master secret to be left in place, read returned %v", err)
	}
	if len(secret) != masterSecretSize {
		t.Errorf("Expected a %d byte master secret, got %d bytes", masterSecretSize, len(secret))
	}
}

// readStoredEnvelope returns the envelope as it is stored on disk.
func readStoredEnvelope(t *testing.T, keyring *IdsecBasicKeyring) keyringEnvelope {
	t.Helper()

	data, err := os.ReadFile(keyring.keyringFilePath)
	if err != nil {
		t.Fatalf("Failed to read the stored keyring: %v", err)
	}
	var envelope keyringEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatalf("Failed to parse the stored keyring: %v", err)
	}
	return envelope
}

// assertStoredEnvelopeIsCurrentFormat verifies that a write produced a single
// owner-only envelope file in the current format, and no sidecar beside it.
func assertStoredEnvelopeIsCurrentFormat(t *testing.T, keyring *IdsecBasicKeyring) {
	t.Helper()

	info, err := os.Stat(keyring.keyringFilePath)
	if err != nil {
		t.Fatalf("Expected the keyring envelope to be created, stat returned %v", err)
	}
	// Mode bits do not express owner-only access on Windows.
	if runtime.GOOS != "windows" {
		if mode := info.Mode().Perm(); mode != 0600 {
			t.Errorf("Expected the keyring envelope to be readable by its owner only, got mode %#o", mode)
		}
	}
	envelope := readStoredEnvelope(t, keyring)
	if envelope.Version != keyringFormatVersion {
		t.Errorf("Expected envelope version %d, got %d", keyringFormatVersion, envelope.Version)
	}
	if envelope.KDF.Algorithm != kdfAlgorithmHKDFSHA256 {
		t.Errorf("Expected key derivation algorithm %q, got %q", kdfAlgorithmHKDFSHA256, envelope.KDF.Algorithm)
	}
	salt, err := base64.StdEncoding.DecodeString(envelope.KDF.Salt)
	if err != nil {
		t.Fatalf("Failed to decode the stored salt: %v", err)
	}
	if len(salt) != saltSize {
		t.Errorf("Expected a %d byte salt, got %d bytes", saltSize, len(salt))
	}
	if envelope.MAC == "" {
		t.Error("Expected the envelope to carry a mac over its contents")
	}
	if _, err := os.Stat(keyring.macFilePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Expected no separate mac file to be written, stat returned %v", err)
	}
}

// skipIfFolderPermissionsAreNotEnforced skips tests that rely on a folder being
// unwritable, which mode bits cannot express on Windows or enforce against root.
func skipIfFolderPermissionsAreNotEnforced(t *testing.T) {
	t.Helper()

	if runtime.GOOS == "windows" {
		t.Skip("Folder mode bits do not restrict writes on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("Running as root bypasses folder permissions")
	}
}

// makeFolderReadOnly removes write access from a folder for the duration of a test.
func makeFolderReadOnly(t *testing.T, folder string) {
	t.Helper()

	if err := os.Chmod(folder, 0500); err != nil {
		t.Fatalf("Failed to restrict keyring folder: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(folder, 0700)
	})
}

// keyringPaths describes where a keyring is expected to keep its files.
type keyringPaths struct {
	folder  string
	keyFile string
}

func TestNewIdsecBasicKeyring(t *testing.T) {
	tests := []struct {
		name                      string
		setupFunc                 func(t *testing.T) keyringPaths
		requiresFolderPermissions bool
		expectedNil               bool
	}{
		{
			name: "success_derives_both_locations_from_the_home_directory",
			setupFunc: func(t *testing.T) keyringPaths {
				t.Helper()
				home := t.TempDir()
				t.Setenv("HOME", home)
				t.Setenv("USERPROFILE", home)
				t.Setenv(IdsecBasicKeyringFolderEnvVar, "")
				t.Setenv(IdsecBasicKeyringKeyFileEnvVar, "")
				return keyringPaths{
					folder:  filepath.Join(home, DefaultBasicKeyringFolder),
					keyFile: filepath.Join(home, DefaultBasicKeyringKeyFile),
				}
			},
		},
		{
			name: "success_creates_the_folder_named_by_the_environment",
			setupFunc: func(t *testing.T) keyringPaths {
				t.Helper()
				folder := filepath.Join(t.TempDir(), "custom_keyring")
				keyFile := filepath.Join(t.TempDir(), "keyring.key")
				t.Setenv(IdsecBasicKeyringFolderEnvVar, folder)
				t.Setenv(IdsecBasicKeyringKeyFileEnvVar, keyFile)
				return keyringPaths{folder: folder, keyFile: keyFile}
			},
		},
		{
			name: "success_keeps_the_master_secret_outside_a_relocated_folder",
			setupFunc: func(t *testing.T) keyringPaths {
				t.Helper()
				home := t.TempDir()
				folder := t.TempDir()
				t.Setenv("HOME", home)
				t.Setenv("USERPROFILE", home)
				t.Setenv(IdsecBasicKeyringFolderEnvVar, folder)
				t.Setenv(IdsecBasicKeyringKeyFileEnvVar, "")
				return keyringPaths{
					folder:  folder,
					keyFile: filepath.Join(home, DefaultBasicKeyringKeyFile),
				}
			},
		},
		{
			name: "success_handles_an_existing_folder",
			setupFunc: func(t *testing.T) keyringPaths {
				t.Helper()
				folder := filepath.Join(t.TempDir(), "existing_keyring")
				if err := os.MkdirAll(folder, 0700); err != nil {
					t.Fatalf("Failed to create the existing folder: %v", err)
				}
				keyFile := filepath.Join(t.TempDir(), "keyring.key")
				t.Setenv(IdsecBasicKeyringFolderEnvVar, folder)
				t.Setenv(IdsecBasicKeyringKeyFileEnvVar, keyFile)
				return keyringPaths{folder: folder, keyFile: keyFile}
			},
		},
		{
			name: "error_returns_nil_when_the_folder_cannot_be_created",
			setupFunc: func(t *testing.T) keyringPaths {
				t.Helper()
				parent := t.TempDir()
				makeFolderReadOnly(t, parent)
				t.Setenv(IdsecBasicKeyringFolderEnvVar, filepath.Join(parent, "keyring"))
				t.Setenv(IdsecBasicKeyringKeyFileEnvVar, filepath.Join(t.TempDir(), "keyring.key"))
				return keyringPaths{}
			},
			requiresFolderPermissions: true,
			expectedNil:               true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.requiresFolderPermissions {
				skipIfFolderPermissionsAreNotEnforced(t)
			}
			want := tt.setupFunc(t)

			keyring := NewIdsecBasicKeyring()

			if tt.expectedNil {
				if keyring != nil {
					t.Errorf("Expected nil keyring, got %+v", keyring)
				}
				return
			}
			if keyring == nil {
				t.Fatal("Expected non-nil keyring")
			}
			if keyring.basicFolderPath != want.folder {
				t.Errorf("Expected basicFolderPath '%s', got '%s'", want.folder, keyring.basicFolderPath)
			}
			if expected := filepath.Join(want.folder, keyringFileName); keyring.keyringFilePath != expected {
				t.Errorf("Expected keyringFilePath '%s', got '%s'", expected, keyring.keyringFilePath)
			}
			if expected := filepath.Join(want.folder, legacyMacFileName); keyring.macFilePath != expected {
				t.Errorf("Expected macFilePath '%s', got '%s'", expected, keyring.macFilePath)
			}
			if keyring.keyFilePath != want.keyFile {
				t.Errorf("Expected keyFilePath '%s', got '%s'", want.keyFile, keyring.keyFilePath)
			}
			if _, err := os.Stat(want.folder); err != nil {
				t.Errorf("Expected the keyring folder to be created, stat returned %v", err)
			}
			// Constructing a keyring must not create key material; only a write does.
			if _, err := os.Stat(want.keyFile); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("Expected no master secret to be created, stat returned %v", err)
			}
		})
	}
}

func TestIdsecBasicKeyring_SetPassword(t *testing.T) {
	tests := []struct {
		name          string
		setupFunc     func(t *testing.T) *IdsecBasicKeyring
		serviceName   string
		username      string
		password      string
		expectedError bool
		validateFunc  func(t *testing.T, keyring *IdsecBasicKeyring)
	}{
		{
			name:          "success_sets_password_new_keyring",
			setupFunc:     newIsolatedKeyring,
			serviceName:   "github",
			username:      "testuser",
			password:      "testpassword",
			expectedError: false,
			validateFunc: func(t *testing.T, keyring *IdsecBasicKeyring) {
				t.Helper()
				assertStoredEnvelopeIsCurrentFormat(t, keyring)
				assertMasterSecretPresent(t, keyring)
			},
		},
		{
			name: "success_sets_password_existing_keyring",
			setupFunc: func(t *testing.T) *IdsecBasicKeyring {
				t.Helper()
				keyring := newIsolatedKeyring(t)
				if err := keyring.SetPassword("service1", "user1", "pass1"); err != nil {
					t.Fatalf("SetPassword: %v", err)
				}
				return keyring
			},
			serviceName:   "service2",
			username:      "user2",
			password:      "pass2",
			expectedError: false,
			validateFunc: func(t *testing.T, keyring *IdsecBasicKeyring) {
				t.Helper()
				assertStoredPassword(t, keyring, "service1", "user1", "pass1")
				assertStoredPassword(t, keyring, "service2", "user2", "pass2")
			},
		},
		{
			name: "success_overwrites_existing_password",
			setupFunc: func(t *testing.T) *IdsecBasicKeyring {
				t.Helper()
				keyring := newIsolatedKeyring(t)
				if err := keyring.SetPassword("github", "testuser", "oldpassword"); err != nil {
					t.Fatalf("SetPassword: %v", err)
				}
				return keyring
			},
			serviceName:   "github",
			username:      "testuser",
			password:      "newpassword",
			expectedError: false,
			validateFunc: func(t *testing.T, keyring *IdsecBasicKeyring) {
				t.Helper()
				assertStoredPassword(t, keyring, "github", "testuser", "newpassword")
			},
		},
		{
			name:          "edge_case_empty_service_name",
			setupFunc:     newIsolatedKeyring,
			serviceName:   "",
			username:      "testuser",
			password:      "testpassword",
			expectedError: false,
			validateFunc: func(t *testing.T, keyring *IdsecBasicKeyring) {
				t.Helper()
				assertStoredPassword(t, keyring, "", "testuser", "testpassword")
			},
		},
		{
			name:          "edge_case_empty_username",
			setupFunc:     newIsolatedKeyring,
			serviceName:   "github",
			username:      "",
			password:      "testpassword",
			expectedError: false,
			validateFunc: func(t *testing.T, keyring *IdsecBasicKeyring) {
				t.Helper()
				assertStoredPassword(t, keyring, "github", "", "testpassword")
			},
		},
		{
			name:          "edge_case_empty_password",
			setupFunc:     newIsolatedKeyring,
			serviceName:   "github",
			username:      "testuser",
			password:      "",
			expectedError: false,
			validateFunc: func(t *testing.T, keyring *IdsecBasicKeyring) {
				t.Helper()
				assertStoredPassword(t, keyring, "github", "testuser", "")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyring := tt.setupFunc(t)

			err := keyring.SetPassword(tt.serviceName, tt.username, tt.password)

			if tt.expectedError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}
			if tt.validateFunc != nil {
				tt.validateFunc(t, keyring)
			}
		})
	}
}

// assertStoredPassword verifies that a stored credential reads back unchanged.
func assertStoredPassword(t *testing.T, keyring *IdsecBasicKeyring, serviceName string, username string, expected string) {
	t.Helper()

	password, err := keyring.GetPassword(serviceName, username)
	if err != nil {
		t.Fatalf("GetPassword %s/%s: %v", serviceName, username, err)
	}
	if password != expected {
		t.Errorf("Expected password '%s' for %s/%s, got '%s'", expected, serviceName, username, password)
	}
}

func TestIdsecBasicKeyring_GetPassword(t *testing.T) {
	tests := []struct {
		name             string
		setupFunc        func(t *testing.T) *IdsecBasicKeyring
		serviceName      string
		username         string
		expectedPassword string
	}{
		{
			name: "success_gets_existing_password",
			setupFunc: func(t *testing.T) *IdsecBasicKeyring {
				t.Helper()
				keyring := newIsolatedKeyring(t)
				if err := keyring.SetPassword("github", "testuser", "testpassword"); err != nil {
					t.Fatalf("SetPassword: %v", err)
				}
				return keyring
			},
			serviceName:      "github",
			username:         "testuser",
			expectedPassword: "testpassword",
		},
		{
			name:             "success_returns_empty_for_nonexistent_keyring",
			setupFunc:        newIsolatedKeyring,
			serviceName:      "github",
			username:         "testuser",
			expectedPassword: "",
		},
		{
			name: "success_returns_empty_for_nonexistent_service",
			setupFunc: func(t *testing.T) *IdsecBasicKeyring {
				t.Helper()
				keyring := newIsolatedKeyring(t)
				if err := keyring.SetPassword("github", "testuser", "testpassword"); err != nil {
					t.Fatalf("SetPassword: %v", err)
				}
				return keyring
			},
			serviceName:      "gitlab",
			username:         "testuser",
			expectedPassword: "",
		},
		{
			name: "success_returns_empty_for_nonexistent_username",
			setupFunc: func(t *testing.T) *IdsecBasicKeyring {
				t.Helper()
				keyring := newIsolatedKeyring(t)
				if err := keyring.SetPassword("github", "testuser", "testpassword"); err != nil {
					t.Fatalf("SetPassword: %v", err)
				}
				return keyring
			},
			serviceName:      "github",
			username:         "otheruser",
			expectedPassword: "",
		},
		{
			name: "success_gets_multiple_passwords",
			setupFunc: func(t *testing.T) *IdsecBasicKeyring {
				t.Helper()
				keyring := newIsolatedKeyring(t)
				for _, entry := range []struct{ service, user, password string }{
					{"github", "user1", "pass1"},
					{"github", "user2", "pass2"},
					{"gitlab", "user1", "pass3"},
				} {
					if err := keyring.SetPassword(entry.service, entry.user, entry.password); err != nil {
						t.Fatalf("SetPassword %s/%s: %v", entry.service, entry.user, err)
					}
				}
				return keyring
			},
			serviceName:      "gitlab",
			username:         "user1",
			expectedPassword: "pass3",
		},
		{
			name: "edge_case_empty_service_name",
			setupFunc: func(t *testing.T) *IdsecBasicKeyring {
				t.Helper()
				keyring := newIsolatedKeyring(t)
				if err := keyring.SetPassword("", "testuser", "testpassword"); err != nil {
					t.Fatalf("SetPassword: %v", err)
				}
				return keyring
			},
			serviceName:      "",
			username:         "testuser",
			expectedPassword: "testpassword",
		},
		{
			name: "edge_case_empty_username",
			setupFunc: func(t *testing.T) *IdsecBasicKeyring {
				t.Helper()
				keyring := newIsolatedKeyring(t)
				if err := keyring.SetPassword("github", "", "testpassword"); err != nil {
					t.Fatalf("SetPassword: %v", err)
				}
				return keyring
			},
			serviceName:      "github",
			username:         "",
			expectedPassword: "testpassword",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyring := tt.setupFunc(t)

			password, err := keyring.GetPassword(tt.serviceName, tt.username)

			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}
			if password != tt.expectedPassword {
				t.Errorf("Expected password '%s', got '%s'", tt.expectedPassword, password)
			}
		})
	}
}

func TestIdsecBasicKeyring_DeletePassword(t *testing.T) {
	tests := []struct {
		name         string
		setupFunc    func(t *testing.T) *IdsecBasicKeyring
		serviceName  string
		username     string
		validateFunc func(t *testing.T, keyring *IdsecBasicKeyring)
	}{
		{
			name: "success_deletes_existing_password",
			setupFunc: func(t *testing.T) *IdsecBasicKeyring {
				t.Helper()
				keyring := newIsolatedKeyring(t)
				if err := keyring.SetPassword("github", "testuser", "testpassword"); err != nil {
					t.Fatalf("SetPassword: %v", err)
				}
				return keyring
			},
			serviceName: "github",
			username:    "testuser",
			validateFunc: func(t *testing.T, keyring *IdsecBasicKeyring) {
				t.Helper()
				assertStoredPassword(t, keyring, "github", "testuser", "")
			},
		},
		{
			name:        "success_idempotent_nonexistent_keyring",
			setupFunc:   newIsolatedKeyring,
			serviceName: "github",
			username:    "testuser",
		},
		{
			name: "success_idempotent_nonexistent_service",
			setupFunc: func(t *testing.T) *IdsecBasicKeyring {
				t.Helper()
				keyring := newIsolatedKeyring(t)
				if err := keyring.SetPassword("github", "testuser", "testpassword"); err != nil {
					t.Fatalf("SetPassword: %v", err)
				}
				return keyring
			},
			serviceName: "gitlab",
			username:    "testuser",
			validateFunc: func(t *testing.T, keyring *IdsecBasicKeyring) {
				t.Helper()
				assertStoredPassword(t, keyring, "github", "testuser", "testpassword")
			},
		},
		{
			name: "success_idempotent_nonexistent_username",
			setupFunc: func(t *testing.T) *IdsecBasicKeyring {
				t.Helper()
				keyring := newIsolatedKeyring(t)
				if err := keyring.SetPassword("github", "testuser", "testpassword"); err != nil {
					t.Fatalf("SetPassword: %v", err)
				}
				return keyring
			},
			serviceName: "github",
			username:    "otheruser",
			validateFunc: func(t *testing.T, keyring *IdsecBasicKeyring) {
				t.Helper()
				assertStoredPassword(t, keyring, "github", "testuser", "testpassword")
			},
		},
		{
			name: "success_deletes_one_of_multiple_passwords",
			setupFunc: func(t *testing.T) *IdsecBasicKeyring {
				t.Helper()
				keyring := newIsolatedKeyring(t)
				for _, entry := range []struct{ service, user, password string }{
					{"github", "user1", "pass1"},
					{"github", "user2", "pass2"},
					{"gitlab", "user1", "pass3"},
				} {
					if err := keyring.SetPassword(entry.service, entry.user, entry.password); err != nil {
						t.Fatalf("SetPassword %s/%s: %v", entry.service, entry.user, err)
					}
				}
				return keyring
			},
			serviceName: "github",
			username:    "user1",
			validateFunc: func(t *testing.T, keyring *IdsecBasicKeyring) {
				t.Helper()
				assertStoredPassword(t, keyring, "github", "user1", "")
				assertStoredPassword(t, keyring, "github", "user2", "pass2")
				assertStoredPassword(t, keyring, "gitlab", "user1", "pass3")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyring := tt.setupFunc(t)

			err := keyring.DeletePassword(tt.serviceName, tt.username)

			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}
			if tt.validateFunc != nil {
				tt.validateFunc(t, keyring)
			}
		})
	}
}

func TestIdsecBasicKeyring_Integration(t *testing.T) {
	tests := []struct {
		name         string
		actions      []func(*IdsecBasicKeyring) error
		validateFunc func(t *testing.T, keyring *IdsecBasicKeyring)
	}{
		{
			name: "integration_complete_lifecycle",
			actions: []func(*IdsecBasicKeyring) error{
				func(k *IdsecBasicKeyring) error { return k.SetPassword("service1", "user1", "pass1") },
				func(k *IdsecBasicKeyring) error { return k.SetPassword("service1", "user2", "pass2") },
				func(k *IdsecBasicKeyring) error { return k.SetPassword("service2", "user1", "pass3") },
				func(k *IdsecBasicKeyring) error { return k.DeletePassword("service1", "user1") },
			},
			validateFunc: func(t *testing.T, keyring *IdsecBasicKeyring) {
				t.Helper()
				assertStoredPassword(t, keyring, "service1", "user1", "")
				assertStoredPassword(t, keyring, "service1", "user2", "pass2")
				assertStoredPassword(t, keyring, "service2", "user1", "pass3")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyring := newIsolatedKeyring(t)

			for i, action := range tt.actions {
				if err := action(keyring); err != nil {
					t.Errorf("Action %d failed: %v", i, err)
				}
			}

			if tt.validateFunc != nil {
				tt.validateFunc(t, keyring)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant interface{}
		expected interface{}
	}{
		{
			name:     "nonce_size_correct_value",
			constant: nonceSize,
			expected: 12,
		},
		{
			name:     "tag_size_correct_value",
			constant: tagSize,
			expected: 16,
		},
		{
			name:     "salt_size_correct_value",
			constant: saltSize,
			expected: 16,
		},
		{
			name:     "master_secret_size_correct_value",
			constant: masterSecretSize,
			expected: 32,
		},
		{
			name:     "derived_key_size_correct_value",
			constant: derivedKeySize,
			expected: 32,
		},
		{
			name:     "format_version_correct_value",
			constant: keyringFormatVersion,
			expected: 2,
		},
		{
			name:     "kdf_algorithm_correct_value",
			constant: kdfAlgorithmHKDFSHA256,
			expected: "hkdf-sha256",
		},
		{
			name:     "default_folder_correct_value",
			constant: DefaultBasicKeyringFolder,
			expected: ".idsec/cache/keyring",
		},
		{
			name:     "default_key_file_correct_value",
			constant: DefaultBasicKeyringKeyFile,
			expected: ".idsec/keys/keyring.key",
		},
		{
			name:     "folder_env_var_correct_value",
			constant: IdsecBasicKeyringFolderEnvVar,
			expected: "IDSEC_KEYRING_FOLDER",
		},
		{
			name:     "key_file_env_var_correct_value",
			constant: IdsecBasicKeyringKeyFileEnvVar,
			expected: "IDSEC_KEYRING_KEY_FILE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if !reflect.DeepEqual(tt.constant, tt.expected) {
				t.Errorf("Expected %v, got %v", tt.expected, tt.constant)
			}
		})
	}
}

// TestIdsecBasicKeyring_ClearAllPasswords verifies that clearing the cache removes
// the stored credentials and any file left behind by an earlier on-disk format,
// while keeping the master secret that other keyrings may still depend on.
func TestIdsecBasicKeyring_ClearAllPasswords(t *testing.T) {
	tests := []struct {
		name             string
		setupFunc        func(t *testing.T, keyring *IdsecBasicKeyring)
		restrictedFolder bool
		expectedError    bool
		expectKeyFile    bool
	}{
		{
			name: "success_case_envelope_exists",
			setupFunc: func(t *testing.T, keyring *IdsecBasicKeyring) {
				t.Helper()
				if err := keyring.SetPassword("github", "testuser", "testpassword"); err != nil {
					t.Fatalf("SetPassword: %v", err)
				}
			},
			expectKeyFile: true,
		},
		{
			name: "success_case_envelope_and_leftover_sidecar_exist",
			setupFunc: func(t *testing.T, keyring *IdsecBasicKeyring) {
				t.Helper()
				if err := keyring.SetPassword("github", "testuser", "testpassword"); err != nil {
					t.Fatalf("SetPassword: %v", err)
				}
				if err := os.WriteFile(keyring.macFilePath, []byte(strings.Repeat("a", 64)), 0600); err != nil {
					t.Fatalf("Failed to write the leftover sidecar: %v", err)
				}
			},
			expectKeyFile: true,
		},
		{
			name: "edge_case_only_a_leftover_sidecar_exists",
			setupFunc: func(t *testing.T, keyring *IdsecBasicKeyring) {
				t.Helper()
				if err := os.WriteFile(keyring.macFilePath, []byte(strings.Repeat("a", 64)), 0600); err != nil {
					t.Fatalf("Failed to write the leftover sidecar: %v", err)
				}
			},
		},
		{
			name:      "edge_case_files_do_not_exist",
			setupFunc: func(t *testing.T, keyring *IdsecBasicKeyring) {},
		},
		{
			name: "error_case_files_cannot_be_removed",
			setupFunc: func(t *testing.T, keyring *IdsecBasicKeyring) {
				t.Helper()
				if err := keyring.SetPassword("github", "testuser", "testpassword"); err != nil {
					t.Fatalf("SetPassword: %v", err)
				}
			},
			restrictedFolder: true,
			expectedError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.restrictedFolder {
				skipIfFolderPermissionsAreNotEnforced(t)
			}

			folder, _ := isolateKeyringEnvironment(t)
			keyring := NewIdsecBasicKeyring()
			if keyring == nil {
				t.Fatal("Failed to create keyring for test")
			}
			tt.setupFunc(t, keyring)
			if tt.restrictedFolder {
				makeFolderReadOnly(t, folder)
			}

			err := keyring.ClearAllPasswords()

			if tt.expectedError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}
			assertKeyringStateRemoved(t, keyring)
			if tt.expectKeyFile {
				assertMasterSecretPresent(t, keyring)
			}
		})
	}
}

// TestIdsecBasicKeyring_SetPasswordRecoversUnreadableStore verifies that a keyring
// whose stored state can no longer be interpreted does not block new credentials
// from being written and read back.
func TestIdsecBasicKeyring_SetPasswordRecoversUnreadableStore(t *testing.T) {
	keyring := newIsolatedKeyring(t)
	seedUnreadableKeyring(t, keyring)

	if err := keyring.SetPassword("github", "testuser", "newpassword"); err != nil {
		t.Fatalf("SetPassword on an unreadable keyring: %v", err)
	}

	assertStoredPassword(t, keyring, "github", "testuser", "newpassword")
}

// TestIdsecBasicKeyring_RecoversFromUnreadableState verifies that every read and
// delete path treats stored state it cannot interpret as a cache miss and clears it,
// instead of reporting an error the caller cannot act on. The cases cover the shapes
// such state actually takes: content that is not a keyring at all, a keyring left
// behind by an earlier on-disk format, and a keyring whose master secret is gone.
//
// Each seed also pins the reason its state is rejected for, which keeps the fixtures
// honest: without it a seed that stopped exercising the path it was written for, such
// as an earlier format that merely failed to parse, would still pass.
func TestIdsecBasicKeyring_RecoversFromUnreadableState(t *testing.T) {
	seeds := []struct {
		name     string
		seedFunc func(t *testing.T, keyring *IdsecBasicKeyring)
		reason   error
	}{
		{name: "uninterpretable_contents", seedFunc: seedUnreadableKeyring, reason: errContentsMalformed},
		{name: "earlier_on_disk_format", seedFunc: seedEarlierFormatKeyring, reason: errVersionUnsupported},
		{name: "missing_master_secret", seedFunc: seedKeyringWithoutItsKeyFile, reason: errKeyFileMissing},
	}
	operations := []struct {
		name          string
		operationFunc func(t *testing.T, keyring *IdsecBasicKeyring)
	}{
		{
			name: "get_password_reports_a_cache_miss",
			operationFunc: func(t *testing.T, keyring *IdsecBasicKeyring) {
				t.Helper()
				password, err := keyring.GetPassword("github", "testuser")
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}
				if password != "" {
					t.Errorf("Expected empty password, got '%s'", password)
				}
			},
		},
		{
			name: "delete_password_is_idempotent",
			operationFunc: func(t *testing.T, keyring *IdsecBasicKeyring) {
				t.Helper()
				if err := keyring.DeletePassword("github", "testuser"); err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}
			},
		},
		{
			name: "list_keys_returns_no_entries",
			operationFunc: func(t *testing.T, keyring *IdsecBasicKeyring) {
				t.Helper()
				keys, err := keyring.ListKeys("github")
				if err != nil {
					t.Fatalf("Expected no error, got %v", err)
				}
				if len(keys) != 0 {
					t.Errorf("Expected no keys, got %v", keys)
				}
			},
		},
	}

	for _, seed := range seeds {
		for _, operation := range operations {
			t.Run("success_"+operation.name+"_with_"+seed.name, func(t *testing.T) {
				keyring := newIsolatedKeyring(t)
				seed.seedFunc(t, keyring)
				if _, err := keyring.readStore(); !errors.Is(err, seed.reason) {
					t.Fatalf("Expected the seeded state to be rejected as %v, got %v", seed.reason, err)
				}

				operation.operationFunc(t, keyring)

				assertKeyringStateRemoved(t, keyring)
			})
		}
	}
}

// TestIdsecBasicKeyring_DropsOnlyUnreadableRecords verifies that a single entry that
// cannot be read is reported as a cache miss on its own, while the entries stored
// next to it still decrypt correctly. Reading never rewrites the stored state, so the
// unreadable entry is skipped rather than removed.
func TestIdsecBasicKeyring_DropsOnlyUnreadableRecords(t *testing.T) {
	keyring := newIsolatedKeyring(t)
	for _, entry := range []struct{ service, user, password string }{
		{"github", "alice", "secret-a"},
		{"github", "bob", "secret-b"},
		{"gitlab", "carol", "secret-c"},
	} {
		if err := keyring.SetPassword(entry.service, entry.user, entry.password); err != nil {
			t.Fatalf("SetPassword %s/%s: %v", entry.service, entry.user, err)
		}
	}

	state, err := keyring.readStore()
	if err != nil {
		t.Fatalf("Failed to read seeded keyring: %v", err)
	}
	alice := state.entries["github"]["alice"]
	alice.Ciphertext = base64.StdEncoding.EncodeToString([]byte("unrelated bytes"))
	state.entries["github"]["alice"] = alice
	if err := keyring.writeStore(state); err != nil {
		t.Fatalf("Failed to store the modified keyring: %v", err)
	}

	assertStoredPassword(t, keyring, "github", "alice", "")
	// Reading must leave the stored state alone so that it cannot discard an entry
	// another process wrote in the meantime.
	if _, err := os.Stat(keyring.keyringFilePath); err != nil {
		t.Errorf("Expected the stored keyring to be left in place, stat returned %v", err)
	}

	assertStoredPassword(t, keyring, "github", "bob", "secret-b")
	assertStoredPassword(t, keyring, "gitlab", "carol", "secret-c")

	// ListKeys does not decrypt, so the unreadable entry is still listed.
	keys, err := keyring.ListKeys("github")
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	listed := map[string]bool{}
	for _, key := range keys {
		listed[key] = true
	}
	if len(keys) != 2 || !listed["alice"] || !listed["bob"] {
		t.Errorf("Expected 'alice' and 'bob' to be listed, got %v", keys)
	}
}

// TestIdsecBasicKeyring_RecoversWithNonDefaultLoggerStyle verifies that recovery from
// unreadable state does not depend on how logging is configured.
func TestIdsecBasicKeyring_RecoversWithNonDefaultLoggerStyle(t *testing.T) {
	t.Setenv(config.IdsecLoggerStyleEnvVar, "json")

	keyring := newIsolatedKeyring(t)
	seedUnreadableKeyring(t, keyring)

	assertStoredPassword(t, keyring, "github", "testuser", "")
	if err := keyring.SetPassword("github", "testuser", "newpassword"); err != nil {
		t.Fatalf("SetPassword on an unreadable keyring: %v", err)
	}
	assertStoredPassword(t, keyring, "github", "testuser", "newpassword")
}

// TestIdsecBasicKeyring_TreatsALeftoverSidecarAsAnEmptyKeyring verifies that a file
// left behind by an earlier on-disk format, with no keyring beside it, reads as an
// empty keyring rather than as unusable state, and that clearing the cache removes it.
func TestIdsecBasicKeyring_TreatsALeftoverSidecarAsAnEmptyKeyring(t *testing.T) {
	keyring := newIsolatedKeyring(t)
	if err := os.WriteFile(keyring.macFilePath, []byte(strings.Repeat("a", 64)), 0600); err != nil {
		t.Fatalf("Failed to write the leftover sidecar: %v", err)
	}

	assertStoredPassword(t, keyring, "github", "testuser", "")
	keys, err := keyring.ListKeys("github")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("Expected no keys, got %v", keys)
	}
	if err := keyring.DeletePassword("github", "testuser"); err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	// Reading an absent keyring creates nothing, so the leftover file is still there.
	if _, err := os.Stat(keyring.macFilePath); err != nil {
		t.Errorf("Expected the leftover sidecar to be left in place by a read, stat returned %v", err)
	}

	if err := keyring.ClearAllPasswords(); err != nil {
		t.Fatalf("ClearAllPasswords: %v", err)
	}
	assertKeyringStateRemoved(t, keyring)
}

// TestIdsecKeyring_DoesNotRetryBasicKeyringOnGenuineFailure verifies that a save which
// already used the file-backed keyring reports its failure immediately, instead of
// retrying the same files through a second file-backed keyring.
func TestIdsecKeyring_DoesNotRetryBasicKeyringOnGenuineFailure(t *testing.T) {
	skipIfFolderPermissionsAreNotEnforced(t)

	folder, _ := isolateKeyringEnvironment(t)
	t.Setenv(IdsecBasicKeyringOverrideEnvVar, "true")

	tokenKeyring := NewIdsecKeyring("idsec-test")
	var logs bytes.Buffer
	tokenKeyring.logger = common.NewIdsecLogger("IdsecKeyring", common.Debug, true, false)
	tokenKeyring.logger.SetOutput(&logs)
	makeFolderReadOnly(t, folder)

	err := tokenKeyring.SaveToken(
		&models.IdsecProfile{ProfileName: "test-profile"},
		&auth.IdsecToken{Token: "test-token"},
		"access",
		false,
	)

	if err == nil {
		t.Fatal("Expected SaveToken to report the write failure, got nil")
	}
	// Asserting on the captured failure first keeps the fallback count below
	// meaningful: an empty buffer would otherwise satisfy it for the wrong reason.
	if !strings.Contains(logs.String(), "Failed to save token") {
		t.Fatalf("Expected the write failure to be logged, got %q", logs.String())
	}
	if fallbacks := strings.Count(logs.String(), "Falling back to basic keyring"); fallbacks != 0 {
		t.Errorf("Expected no retry through a second basic keyring, got %d fallback attempts", fallbacks)
	}
}

// TestIdsecBasicKeyring_SetPasswordReportsGenuineFailures verifies that a keyring
// folder that cannot be written to produces an error rather than a silent success.
func TestIdsecBasicKeyring_SetPasswordReportsGenuineFailures(t *testing.T) {
	skipIfFolderPermissionsAreNotEnforced(t)

	folder, _ := isolateKeyringEnvironment(t)
	keyring := NewIdsecBasicKeyring()
	if keyring == nil {
		t.Fatal("Failed to create keyring for test")
	}
	makeFolderReadOnly(t, folder)

	if err := keyring.SetPassword("github", "testuser", "testpassword"); err == nil {
		t.Fatal("Expected SetPassword to report the write failure, got nil")
	}
	if _, err := os.Stat(keyring.keyringFilePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Expected no keyring file to be written, stat returned %v", err)
	}
}

func TestIdsecBasicKeyring_ListKeys(t *testing.T) {
	t.Run("populated_service", func(t *testing.T) {
		kr := newIsolatedKeyring(t)
		for _, entry := range []struct{ service, user, password string }{
			{"github", "alice", "secret-a"},
			{"github", "bob", "secret-b"},
			{"gitlab", "carol", "secret-c"},
		} {
			if err := kr.SetPassword(entry.service, entry.user, entry.password); err != nil {
				t.Fatalf("SetPassword %s/%s: %v", entry.service, entry.user, err)
			}
		}

		keys, err := kr.ListKeys("github")
		if err != nil {
			t.Fatalf("ListKeys: %v", err)
		}
		if len(keys) != 2 {
			t.Fatalf("got %d keys, want 2: %v", len(keys), keys)
		}
		seen := map[string]bool{}
		for _, k := range keys {
			seen[k] = true
		}
		if !seen["alice"] || !seen["bob"] {
			t.Errorf("got keys %v, want alice and bob", keys)
		}
	})

	t.Run("missing_file", func(t *testing.T) {
		kr := newIsolatedKeyring(t)

		keys, err := kr.ListKeys("github")
		if err != nil {
			t.Fatalf("ListKeys: %v", err)
		}
		if len(keys) != 0 {
			t.Errorf("got keys %v, want empty", keys)
		}
	})

	t.Run("missing_service", func(t *testing.T) {
		kr := newIsolatedKeyring(t)
		if err := kr.SetPassword("github", "alice", "secret"); err != nil {
			t.Fatalf("SetPassword: %v", err)
		}

		keys, err := kr.ListKeys("gitlab")
		if err != nil {
			t.Fatalf("ListKeys: %v", err)
		}
		if len(keys) != 0 {
			t.Errorf("got keys %v, want empty", keys)
		}
	})
}
