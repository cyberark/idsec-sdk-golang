package keyring

import (
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/99designs/keyring"
	"github.com/danieljoos/wincred"
)

// mockKeyringStore implements keyring.Keyring for testing.
type mockKeyringStore struct {
	setErr    error
	getErr    error
	removeErr error
	keysErr   error
	keys      []string
	item      keyring.Item
}

func (m *mockKeyringStore) Set(item keyring.Item) error {
	if m.setErr != nil {
		return m.setErr
	}
	m.item = item
	return nil
}

func (m *mockKeyringStore) Get(key string) (keyring.Item, error) {
	if m.getErr != nil {
		return keyring.Item{}, m.getErr
	}
	return m.item, nil
}

func (m *mockKeyringStore) Remove(key string) error {
	if m.removeErr != nil {
		return m.removeErr
	}
	m.item = keyring.Item{}
	return nil
}

// The following methods are required to satisfy keyring.Keyring but are unused in these tests.
func (m *mockKeyringStore) Keys() ([]string, error) {
	if m.keysErr != nil {
		return nil, m.keysErr
	}
	return m.keys, nil
}
func (m *mockKeyringStore) GetMetadata(key string) (keyring.Metadata, error) {
	return keyring.Metadata{}, nil
}
func (m *mockKeyringStore) Type() keyring.BackendType { return keyring.KeychainBackend }

func patchOSKeyringOpen(store keyring.Keyring, err error) func() {
	origOpen := OSKeyringOpen
	OSKeyringOpen = func(cfg keyring.Config) (keyring.Keyring, error) {
		return store, err
	}
	return func() {
		OSKeyringOpen = origOpen
	}
}

// fakeWinCred simulates the 99designs/keyring Windows WinCred backend:
//   - a shared backing map keyed "keyring:<service>:<key>"
//   - ServiceName=="" maps to "default"
//   - Keys() returns only keys under the opening service's prefix
//   - Set returns an error when len(item.Data) > 2560
//   - Remove returns keyring.ErrKeyNotFound for missing keys
type fakeWinCred struct {
	mu    sync.Mutex
	store map[string][]byte // key = "keyring:<svc>:<itemKey>"
}

func newFakeWinCred() *fakeWinCred {
	return &fakeWinCred{store: map[string][]byte{}}
}

// open returns a view scoped to serviceName.
func (f *fakeWinCred) open(serviceName string) keyring.Keyring {
	svc := serviceName
	if svc == "" {
		svc = "default"
	}
	return &fakeWinCredView{f: f, svc: svc}
}

// list mimics wincred.FilteredList. filter must end with "*" for prefix matching.
func (f *fakeWinCred) list(filter string) ([]*wincred.Credential, error) {
	prefix := strings.TrimSuffix(filter, "*")
	f.mu.Lock()
	defer f.mu.Unlock()
	var targets []string
	for k := range f.store {
		if strings.HasPrefix(k, prefix) {
			targets = append(targets, k)
		}
	}
	sort.Strings(targets) // deterministic order for error-propagation assertions
	creds := make([]*wincred.Credential, 0, len(targets))
	for _, t := range targets {
		creds = append(creds, &wincred.Credential{TargetName: t})
	}
	return creds, nil
}

// delete mimics (*wincred.GenericCredential).Delete.
func (f *fakeWinCred) delete(targetName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.store[targetName]; !ok {
		return wincred.ErrElementNotFound
	}
	delete(f.store, targetName)
	return nil
}

type fakeWinCredView struct {
	f   *fakeWinCred
	svc string
}

func (v *fakeWinCredView) globalKey(itemKey string) string {
	return "keyring:" + v.svc + ":" + itemKey
}

func (v *fakeWinCredView) Set(item keyring.Item) error {
	if len(item.Data) > 2560 {
		return errors.New("credential blob exceeds 2560-byte limit")
	}
	v.f.mu.Lock()
	defer v.f.mu.Unlock()
	v.f.store[v.globalKey(item.Key)] = item.Data
	return nil
}

func (v *fakeWinCredView) Get(key string) (keyring.Item, error) {
	v.f.mu.Lock()
	defer v.f.mu.Unlock()
	data, ok := v.f.store[v.globalKey(key)]
	if !ok {
		return keyring.Item{}, keyring.ErrKeyNotFound
	}
	return keyring.Item{Key: key, Data: data}, nil
}

func (v *fakeWinCredView) Remove(key string) error {
	v.f.mu.Lock()
	defer v.f.mu.Unlock()
	gk := v.globalKey(key)
	if _, ok := v.f.store[gk]; !ok {
		return keyring.ErrKeyNotFound
	}
	delete(v.f.store, gk)
	return nil
}

func (v *fakeWinCredView) Keys() ([]string, error) {
	v.f.mu.Lock()
	defer v.f.mu.Unlock()
	prefix := "keyring:" + v.svc + ":"
	var keys []string
	for k := range v.f.store {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, strings.TrimPrefix(k, prefix))
		}
	}
	return keys, nil
}

func (v *fakeWinCredView) GetMetadata(key string) (keyring.Metadata, error) {
	return keyring.Metadata{}, nil
}
func (v *fakeWinCredView) Type() keyring.BackendType { return keyring.WinCredBackend }

// withFakeWinCred patches OSKeyringOpen to use a shared fakeWinCred and
// isolates the file keyring to a temp directory.
func withFakeWinCred(t *testing.T) *fakeWinCred {
	t.Helper()
	f := newFakeWinCred()
	origOpen, origEnabled, origList, origDelete :=
		OSKeyringOpen, winCredDiscoveryEnabled, winCredList, winCredDelete
	t.Cleanup(func() {
		OSKeyringOpen, winCredDiscoveryEnabled, winCredList, winCredDelete =
			origOpen, origEnabled, origList, origDelete
	})
	OSKeyringOpen = func(cfg keyring.Config) (keyring.Keyring, error) {
		return f.open(cfg.ServiceName), nil
	}
	winCredDiscoveryEnabled = true
	winCredList = f.list
	winCredDelete = f.delete
	t.Setenv(IdsecBasicKeyringFolderEnvVar, t.TempDir())
	t.Setenv(IdsecBasicKeyringKeyFileEnvVar, filepath.Join(t.TempDir(), "keyring.key"))
	return f
}

// mockFallbackKeyring implements IdsecKeyringImpl for fallback logic.
type mockFallbackKeyring struct {
	setCalled      bool
	getCalled      bool
	deleteCalled   bool
	listKeysCalled bool
	password       string
	keys           []string
	shouldError    bool
}

func (m *mockFallbackKeyring) SetPassword(service, user, password string) error {
	m.setCalled = true
	m.password = password
	if m.shouldError {
		return errors.New("fallback error")
	}
	return nil
}
func (m *mockFallbackKeyring) GetPassword(service, user string) (string, error) {
	m.getCalled = true
	return m.password, nil
}
func (m *mockFallbackKeyring) DeletePassword(service, user string) error {
	m.deleteCalled = true
	m.password = ""
	return nil
}

func (m *mockFallbackKeyring) ClearAllPasswords() error {
	m.deleteCalled = true
	m.password = ""
	return nil
}

func (m *mockFallbackKeyring) ListKeys(service string) ([]string, error) {
	m.listKeysCalled = true
	if m.shouldError {
		return nil, errors.New("fallback error")
	}
	return m.keys, nil
}

func TestIdsecOSProvidedKeyring_SetPassword(t *testing.T) {
	tests := []struct {
		name             string
		openErr          error
		setErr           error
		fallbackCalled   bool
		fallbackError    error
		expectedError    bool
		expectedErrorMsg string
	}{
		{
			name:           "success_case_os_keyring",
			openErr:        nil,
			setErr:         nil,
			fallbackCalled: false,
			expectedError:  false,
		},
		{
			name:           "error_case_open_fallback",
			openErr:        errors.New("open error"),
			setErr:         nil,
			fallbackCalled: true,
			expectedError:  false,
		},
		{
			name:           "error_case_set_fallback",
			openErr:        nil,
			setErr:         errors.New("set error"),
			fallbackCalled: true,
			expectedError:  false,
		},
		{
			name:             "error_case_fallback_returns_error",
			openErr:          errors.New("open error"),
			setErr:           nil,
			fallbackCalled:   true,
			fallbackError:    errors.New("fallback error"),
			expectedError:    true,
			expectedErrorMsg: "fallback error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockKeyringStore{setErr: tt.setErr}
			restore := patchOSKeyringOpen(store, tt.openErr)
			defer restore()

			mockFallback := &mockFallbackKeyring{}
			if tt.fallbackError != nil {
				mockFallback.shouldError = true
			}
			keyring := NewIdsecOSProvidedKeyring(mockFallback)

			err := keyring.SetPassword("svc", "user", "pwd")
			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
				if tt.expectedErrorMsg != "" && err.Error() != tt.expectedErrorMsg {
					t.Errorf("Expected error message '%s', got '%s'", tt.expectedErrorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}
			if tt.fallbackCalled && !mockFallback.setCalled {
				t.Errorf("Expected fallback SetPassword to be called")
			}
			if !tt.fallbackCalled && mockFallback.setCalled {
				t.Errorf("Fallback should not be called on OS keyring success")
			}
		})
	}
}

func TestIdsecOSProvidedKeyring_GetPassword(t *testing.T) {
	tests := []struct {
		name           string
		openErr        error
		getErr         error
		itemData       string
		fallbackCalled bool
		fallbackPwd    string
		expectedPwd    string
	}{
		{
			name:           "success_case_os_keyring",
			openErr:        nil,
			getErr:         nil,
			itemData:       "os_pwd",
			fallbackCalled: false,
			expectedPwd:    "os_pwd",
		},
		{
			name:           "error_case_open_fallback",
			openErr:        errors.New("open error"),
			getErr:         nil,
			itemData:       "",
			fallbackCalled: true,
			fallbackPwd:    "fallback_pwd",
			expectedPwd:    "fallback_pwd",
		},
		{
			name:           "error_case_get_fallback",
			openErr:        nil,
			getErr:         errors.New("get error"),
			itemData:       "",
			fallbackCalled: true,
			fallbackPwd:    "fallback_pwd",
			expectedPwd:    "fallback_pwd",
		},
		{
			name:           "edge_case_key_not_found",
			openErr:        nil,
			getErr:         keyring.ErrKeyNotFound,
			itemData:       "",
			fallbackCalled: false,
			expectedPwd:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockKeyringStore{
				getErr: tt.getErr,
				item:   keyring.Item{Data: []byte(tt.itemData)},
			}
			restore := patchOSKeyringOpen(store, tt.openErr)
			defer restore()

			mockFallback := &mockFallbackKeyring{password: tt.fallbackPwd}
			keyring := NewIdsecOSProvidedKeyring(mockFallback)

			pwd, err := keyring.GetPassword("svc", "user")
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
			if pwd != tt.expectedPwd {
				t.Errorf("Expected password %q, got %q", tt.expectedPwd, pwd)
			}
			if tt.fallbackCalled && !mockFallback.getCalled {
				t.Errorf("Expected fallback GetPassword to be called")
			}
			if !tt.fallbackCalled && mockFallback.getCalled {
				t.Errorf("Fallback should not be called on OS keyring success")
			}
		})
	}
}

func TestIdsecOSProvidedKeyring_DeletePassword(t *testing.T) {
	tests := []struct {
		name           string
		openErr        error
		removeErr      error
		fallbackCalled bool
	}{
		{
			name:           "success_case_os_keyring",
			openErr:        nil,
			removeErr:      nil,
			fallbackCalled: false,
		},
		{
			name:           "error_case_open_fallback",
			openErr:        errors.New("open error"),
			removeErr:      nil,
			fallbackCalled: true,
		},
		{
			name:           "error_case_remove_fallback",
			openErr:        nil,
			removeErr:      errors.New("remove error"),
			fallbackCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockKeyringStore{removeErr: tt.removeErr}
			restore := patchOSKeyringOpen(store, tt.openErr)
			defer restore()

			mockFallback := &mockFallbackKeyring{}
			keyring := NewIdsecOSProvidedKeyring(mockFallback)

			err := keyring.DeletePassword("svc", "user")
			if (tt.openErr != nil || tt.removeErr != nil) && err != nil {
				if !mockFallback.deleteCalled {
					t.Errorf("Expected fallback DeletePassword to be called")
				}
			}
			if tt.openErr == nil && tt.removeErr == nil && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
			if tt.openErr == nil && tt.removeErr == nil && mockFallback.deleteCalled {
				t.Errorf("Fallback should not be called on OS keyring success")
			}
		})
	}
}

func TestIdsecOSProvidedKeyring_FallbackError(t *testing.T) {
	store := &mockKeyringStore{setErr: errors.New("set error")}
	restore := patchOSKeyringOpen(store, nil)
	defer restore()

	mockFallback := &mockFallbackKeyring{}
	mockFallback.shouldError = true
	keyring := NewIdsecOSProvidedKeyring(mockFallback)

	err := keyring.SetPassword("svc", "user", "pwd")
	if err == nil || err.Error() != "fallback error" {
		t.Errorf("Expected fallback error, got %v", err)
	}
}

func TestIdsecOSProvidedKeyring_ConcurrentUsage(t *testing.T) {
	store := &mockKeyringStore{}
	restore := patchOSKeyringOpen(store, nil)
	defer restore()

	mockFallback := &mockFallbackKeyring{}
	keyring := NewIdsecOSProvidedKeyring(mockFallback)

	const n = 10
	done := make(chan bool, n)
	for i := 0; i < n; i++ {
		go func(idx int) {
			_ = keyring.SetPassword("svc", "user", "pwd")
			_, _ = keyring.GetPassword("svc", "user")
			_ = keyring.DeletePassword("svc", "user")
			done <- true
		}(i)
	}
	for i := 0; i < n; i++ {
		<-done
	}
}

// TestClearAllPasswords_ClearsProfileScopedService verifies that entries under any
// service scope, including the legacy default scope, are removed without
// registration (Bug A).
func TestClearAllPasswords_ClearsProfileScopedService(t *testing.T) {
	f := withFakeWinCred(t)
	kr := NewIdsecOSProvidedKeyring(NewIdsecBasicKeyring())

	// write a small token — fits in CM
	_ = kr.SetPassword("azure-profile", "IdsecISPAuth-access", "token")
	// verify it landed in the fake CM
	if _, ok := f.store["keyring:azure-profile:idsec_sdk_golang_IdsecISPAuth-access"]; !ok {
		t.Fatal("expected entry in fake CM, got none")
	}
	_ = kr.SetPassword("", "legacy", "token")
	if _, ok := f.store["keyring:default:idsec_sdk_golang_legacy"]; !ok {
		t.Fatal("expected legacy default-scope entry in fake CM")
	}

	if err := kr.ClearAllPasswords(); err != nil {
		t.Fatalf("ClearAllPasswords: %v", err)
	}
	for k := range f.store {
		if strings.Contains(k, "idsec_sdk_golang_") {
			t.Errorf("unexpected idsec entry still in CM: %s", k)
		}
	}
}

// TestClearAllPasswords_ClearsK8sServices verifies that the three fixed
// K8s service scopes are also cleared without registration (Bug A).
func TestClearAllPasswords_ClearsK8sServices(t *testing.T) {
	f := withFakeWinCred(t)
	kr := NewIdsecOSProvidedKeyring(NewIdsecBasicKeyring())
	k8sSvcs := []string{
		"idsec-sca-k8s-elevate",
		"idsec-sca-k8s-execcred",
		"idsec-sca-k8s-aws-idc-oidc",
	}
	for _, svc := range k8sSvcs {
		_ = kr.SetPassword(svc, "some-key", "value")
	}

	if err := kr.ClearAllPasswords(); err != nil {
		t.Fatalf("ClearAllPasswords: %v", err)
	}
	for k := range f.store {
		if strings.Contains(k, "idsec_sdk_golang_") {
			t.Errorf("unexpected idsec entry still in CM: %s", k)
		}
	}
}

// TestClearAllPasswords_ClearsOverflowedFileKeyring verifies that a token too
// large for CM (> 2560 bytes) that went to the file keyring is also removed
// when ClearAllPasswords is called (Bug A2).
// The assertion reads the file keyring directly — not through IdsecOSProvidedKeyring —
// because GetPassword on non-Windows returns "" on ErrKeyNotFound without consulting
// the fallback, so a read through the OS keyring would pass even if the bug is present.
func TestClearAllPasswords_ClearsOverflowedFileKeyring(t *testing.T) {
	_ = withFakeWinCred(t) // also sets IDSEC_KEYRING_FOLDER to a temp dir
	kr := NewIdsecOSProvidedKeyring(NewIdsecBasicKeyring())

	// 3000 bytes exceeds the 2560-byte CM limit; SetPassword falls back to file keyring.
	bigToken := strings.Repeat("x", 3000)
	if err := kr.SetPassword("azure-profile", "IdsecISPAuth-access", bigToken); err != nil {
		t.Fatalf("SetPassword (overflow): %v", err)
	}

	if err := kr.ClearAllPasswords(); err != nil {
		t.Fatalf("ClearAllPasswords: %v", err)
	}

	// Assert directly against the basic keyring, not through IdsecOSProvidedKeyring.
	basic := NewIdsecBasicKeyring()
	got, err := basic.GetPassword("azure-profile", "IdsecISPAuth-access")
	if err != nil {
		t.Fatalf("basic GetPassword: %v", err)
	}
	if got != "" {
		t.Errorf("expected file keyring to be empty after clear, got %q", got)
	}
}

// TestClearAllPasswords_LeavesForeignEntries verifies that non-idsec entries
// anywhere in Credential Manager are not removed.
func TestClearAllPasswords_LeavesForeignEntries(t *testing.T) {
	f := withFakeWinCred(t)

	// Put foreign (non-idsec) entries directly into the fake store.
	foreign := []string{
		"keyring:my-profile:foreign_key",
		"keyring:idsec_sdk_golang_tools:foreign",
		"keyring:svc:idsec_sdk_golangci",
		"git:https://example.com",
	}
	for _, k := range foreign {
		f.store[k] = []byte("keep me")
	}

	kr := NewIdsecOSProvidedKeyring(NewIdsecBasicKeyring())
	if err := kr.ClearAllPasswords(); err != nil {
		t.Fatalf("ClearAllPasswords: %v", err)
	}
	for _, k := range foreign {
		if _, ok := f.store[k]; !ok {
			t.Errorf("expected %q to survive ClearAllPasswords", k)
		}
	}
}

// TestClearAllPasswords_PropagatesDeleteErrors verifies that a Credential Manager
// delete failure is returned (not silently dropped) and does not stop other
// entries from being deleted.
func TestClearAllPasswords_PropagatesDeleteErrors(t *testing.T) {
	f := withFakeWinCred(t)
	kr := NewIdsecOSProvidedKeyring(NewIdsecBasicKeyring())
	_ = kr.SetPassword("bad-profile", "IdsecISPAuth-access", "token")
	_ = kr.SetPassword("good-profile", "IdsecISPAuth-access", "token")

	bad := "keyring:bad-profile:idsec_sdk_golang_IdsecISPAuth-access"
	good := "keyring:good-profile:idsec_sdk_golang_IdsecISPAuth-access"
	real := winCredDelete
	winCredDelete = func(target string) error {
		if target == bad {
			return errors.New("injected delete error")
		}
		return real(target)
	}

	err := kr.ClearAllPasswords()

	if err == nil {
		t.Fatal("expected error from failed delete, got nil")
	}
	if !strings.Contains(err.Error(), bad) {
		t.Errorf("error should name the target, got: %v", err)
	}
	if _, ok := f.store[good]; ok {
		t.Error("good entry should have been deleted")
	}
	if _, ok := f.store[bad]; !ok {
		t.Error("bad entry should still exist (delete failed)")
	}
}

// TestClearAllPasswords_IdempotentOnEmpty verifies that clearing an already-empty
// keyring returns nil.
func TestClearAllPasswords_IdempotentOnEmpty(t *testing.T) {
	withFakeWinCred(t)
	kr := NewIdsecOSProvidedKeyring(NewIdsecBasicKeyring())
	if err := kr.ClearAllPasswords(); err != nil {
		t.Fatalf("ClearAllPasswords on empty: %v", err)
	}
}

func TestIdsecOSProvidedKeyring_ListKeys(t *testing.T) {
	tests := []struct {
		name           string
		openErr        error
		keysErr        error
		keys           []string
		fallbackKeys   []string
		expectFallback bool
		expectedKeys   []string
	}{
		{
			name: "success_strips_prefix",
			keys: []string{
				"idsec_sdk_golang_alice",
				"idsec_sdk_golang_bob",
				"other_key",
			},
			expectedKeys: []string{"alice", "bob"},
		},
		{
			name:           "open_error_falls_back",
			openErr:        errors.New("open error"),
			fallbackKeys:   []string{"alice"},
			expectFallback: true,
			expectedKeys:   []string{"alice"},
		},
		{
			name:           "keys_error_falls_back",
			keysErr:        errors.New("keys error"),
			fallbackKeys:   []string{"bob"},
			expectFallback: true,
			expectedKeys:   []string{"bob"},
		},
		{
			name:         "no_matching_prefix",
			keys:         []string{"other_key"},
			expectedKeys: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockKeyringStore{
				keys:    tt.keys,
				keysErr: tt.keysErr,
			}
			restore := patchOSKeyringOpen(store, tt.openErr)
			defer restore()

			mockFallback := &mockFallbackKeyring{keys: tt.fallbackKeys}
			kr := NewIdsecOSProvidedKeyring(mockFallback)

			got, err := kr.ListKeys("github")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.expectFallback && !mockFallback.listKeysCalled {
				t.Error("expected fallback ListKeys to be called")
			}
			if !tt.expectFallback && mockFallback.listKeysCalled {
				t.Error("fallback ListKeys should not be called on OS success")
			}
			if len(got) != len(tt.expectedKeys) {
				t.Fatalf("got keys %v, want %v", got, tt.expectedKeys)
			}
			for i, want := range tt.expectedKeys {
				if got[i] != want {
					t.Errorf("key[%d]=%q, want %q", i, got[i], want)
				}
			}
		})
	}
}

func TestClearAllPasswords_DiscoverySkippedOnNonWindows(t *testing.T) {
	f := withFakeWinCred(t)
	winCredDiscoveryEnabled = false
	winCredList = func(filter string) ([]*wincred.Credential, error) {
		t.Fatal("winCredList must not be called when discovery is disabled")
		return nil, nil
	}
	kr := NewIdsecOSProvidedKeyring(NewIdsecBasicKeyring())
	_ = kr.SetPassword("", "default-key", "token")
	_ = kr.SetPassword("azure-profile", "IdsecISPAuth-access", "token")

	err := kr.ClearAllPasswords()

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if _, ok := f.store["keyring:default:idsec_sdk_golang_default-key"]; ok {
		t.Error("default-scope entry should have been cleared")
	}
	// azure-profile entry survives because discovery was skipped and clearService("") on
	// Windows only sees keyring:default:* — this is expected non-Windows behaviour.
	if _, ok := f.store["keyring:azure-profile:idsec_sdk_golang_IdsecISPAuth-access"]; !ok {
		t.Error("azure-profile entry should survive when discovery is disabled")
	}
}

// TestClearAllPasswords_ListErrorStillClearsFileKeyring asserts against the basic
// keyring directly for the same reason as TestClearAllPasswords_ClearsOverflowedFileKeyring:
// GetPassword on non-Windows does not consult the fallback on ErrKeyNotFound.
func TestClearAllPasswords_ListErrorStillClearsFileKeyring(t *testing.T) {
	withFakeWinCred(t)
	kr := NewIdsecOSProvidedKeyring(NewIdsecBasicKeyring())
	// 3000 bytes exceeds the 2560-byte CM limit; SetPassword falls back to file keyring.
	bigToken := strings.Repeat("x", 3000)
	if err := kr.SetPassword("azure-profile", "IdsecISPAuth-access", bigToken); err != nil {
		t.Fatalf("SetPassword (overflow): %v", err)
	}
	basic := NewIdsecBasicKeyring()
	if got, _ := basic.GetPassword("azure-profile", "IdsecISPAuth-access"); got != bigToken {
		t.Fatal("expected overflowed token in file keyring before clear")
	}

	winCredList = func(filter string) ([]*wincred.Credential, error) {
		return nil, errors.New("injected list error")
	}

	err := kr.ClearAllPasswords()

	if err == nil {
		t.Fatal("expected an error from list failure, got nil")
	}
	if !strings.Contains(err.Error(), "injected list error") {
		t.Errorf("error should mention list failure, got: %v", err)
	}
	got, err := basic.GetPassword("azure-profile", "IdsecISPAuth-access")
	if err != nil {
		t.Fatalf("basic GetPassword: %v", err)
	}
	if got != "" {
		t.Errorf("expected file keyring to be cleared, still contains token")
	}
}

func TestClearAllPasswords_IgnoresVanishedEntry(t *testing.T) {
	f := withFakeWinCred(t)
	kr := NewIdsecOSProvidedKeyring(NewIdsecBasicKeyring())
	_ = kr.SetPassword("my-profile", "IdsecISPAuth-access", "token")
	realList := winCredList
	winCredList = func(filter string) ([]*wincred.Credential, error) {
		creds, err := realList(filter)
		creds = append(creds, &wincred.Credential{TargetName: "keyring:gone:idsec_sdk_golang_x"})
		return creds, err
	}

	err := kr.ClearAllPasswords()

	if err != nil {
		t.Fatalf("ErrElementNotFound on delete should be ignored, got: %v", err)
	}
	if _, ok := f.store["keyring:my-profile:idsec_sdk_golang_IdsecISPAuth-access"]; ok {
		t.Error("real entry should have been deleted")
	}
}
