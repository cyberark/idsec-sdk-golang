package keyring

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

// Parameters of an earlier on-disk format, reproduced here so that the tests below
// can seed a keyring exactly as an earlier build left one behind. This build discards
// such a keyring instead of reading it.
const (
	earlierFormatNonceSize = 16
	earlierFormatKeySize   = 32
)

// earlierFormatRecord is the stored form of a single credential in the earlier format.
type earlierFormatRecord struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	Tag        string `json:"tag"`
}

// earlierFormatKey returns the key the earlier format's records were stored under.
func earlierFormatKey() []byte {
	key := make([]byte, earlierFormatKeySize)
	source, _ := os.Hostname()
	filler := earlierFormatKeySize - len(source)%earlierFormatKeySize
	copy(key, append([]byte(source), bytes.Repeat([]byte{byte(filler)}, filler)...))
	return key
}

// earlierFormatEncrypt returns the stored form a secret took in the earlier format.
func earlierFormatEncrypt(t *testing.T, key []byte, data string) earlierFormatRecord {
	t.Helper()

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create the cipher of the earlier format: %v", err)
	}
	aesGCM, err := cipher.NewGCMWithNonceSize(block, earlierFormatNonceSize)
	if err != nil {
		t.Fatalf("Failed to create the cipher mode of the earlier format: %v", err)
	}
	nonce := make([]byte, earlierFormatNonceSize)
	ciphertextWithTag := aesGCM.Seal(nil, nonce, []byte(data), nil)
	return earlierFormatRecord{
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertextWithTag[:len(ciphertextWithTag)-tagSize]),
		Tag:        base64.StdEncoding.EncodeToString(ciphertextWithTag[len(ciphertextWithTag)-tagSize:]),
	}
}

// writeEarlierFormatKeyring stores the given credentials in the earlier format,
// together with the second file that format kept beside the keyring.
func writeEarlierFormatKeyring(t *testing.T, keyring *IdsecBasicKeyring, entries map[string]map[string]string) {
	t.Helper()

	key := earlierFormatKey()
	stored := make(map[string]map[string]earlierFormatRecord, len(entries))
	for service, users := range entries {
		stored[service] = make(map[string]earlierFormatRecord, len(users))
		for username, password := range users {
			stored[service][username] = earlierFormatEncrypt(t, key, password)
		}
	}
	data, err := json.Marshal(stored)
	if err != nil {
		t.Fatalf("Failed to encode the keyring in the earlier format: %v", err)
	}
	if err := os.WriteFile(keyring.keyringFilePath, data, 0600); err != nil {
		t.Fatalf("Failed to write the keyring in the earlier format: %v", err)
	}
	companion := sha256.Sum256(data)
	if err := os.WriteFile(keyring.macFilePath, []byte(hex.EncodeToString(companion[:])), 0600); err != nil {
		t.Fatalf("Failed to write the second file of the earlier format: %v", err)
	}
}

// seedEarlierFormatKeyring stores a single credential in the earlier format.
func seedEarlierFormatKeyring(t *testing.T, keyring *IdsecBasicKeyring) {
	t.Helper()

	writeEarlierFormatKeyring(t, keyring, map[string]map[string]string{
		"github": {"testuser": "testpassword"},
	})
}

// macKeyForStoredEnvelope re-derives the file mac key from the stored master secret
// and the salt the envelope carries.
//
// A test that edits an envelope has to authenticate it again with this key, otherwise
// it only proves that the file-level mac notices the edit and never reaches the
// property it set out to check.
func macKeyForStoredEnvelope(t *testing.T, keyring *IdsecBasicKeyring, envelope *keyringEnvelope) []byte {
	t.Helper()

	secret, err := os.ReadFile(keyring.keyFilePath)
	if err != nil {
		t.Fatalf("Failed to read the master secret: %v", err)
	}
	salt, err := base64.StdEncoding.DecodeString(envelope.KDF.Salt)
	if err != nil {
		t.Fatalf("Failed to decode the stored salt: %v", err)
	}
	macKey, err := hkdf.Key(sha256.New, secret, salt, macKeyInfo, derivedKeySize)
	if err != nil {
		t.Fatalf("Failed to derive the file mac key: %v", err)
	}
	return macKey
}

// storeEnvelopeAuthenticatedWith writes an envelope back to disk, authenticated with
// the given key.
func storeEnvelopeAuthenticatedWith(t *testing.T, keyring *IdsecBasicKeyring, envelope *keyringEnvelope, macKey []byte) {
	t.Helper()

	canonical, err := canonicalMACInput(envelope)
	if err != nil {
		t.Fatalf("Failed to encode the envelope for authentication: %v", err)
	}
	envelope.MAC = hex.EncodeToString(envelopeMAC(macKey, canonical))
	storeEnvelopeVerbatim(t, keyring, envelope)
}

// storeEnvelopeVerbatim writes an envelope back to disk exactly as given.
func storeEnvelopeVerbatim(t *testing.T, keyring *IdsecBasicKeyring, envelope *keyringEnvelope) {
	t.Helper()

	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("Failed to encode the envelope: %v", err)
	}
	if err := os.WriteFile(keyring.keyringFilePath, data, 0600); err != nil {
		t.Fatalf("Failed to write the envelope: %v", err)
	}
}

// flipBase64Byte flips one bit of a base64 encoded field, leaving it the same length
// and still decodable so that the record itself is what rejects the change.
func flipBase64Byte(t *testing.T, encoded string) string {
	t.Helper()

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("Failed to decode the stored field: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("Expected a non-empty stored field")
	}
	raw[0] ^= 0x01
	return base64.StdEncoding.EncodeToString(raw)
}

// seedTwoRecords stores two credentials under one service so that a test can change
// one of them and show that the other is unaffected.
func seedTwoRecords(t *testing.T, keyring *IdsecBasicKeyring) {
	t.Helper()

	if err := keyring.SetPassword("github", "alice", "secret-a"); err != nil {
		t.Fatalf("SetPassword alice: %v", err)
	}
	if err := keyring.SetPassword("github", "bob", "secret-b"); err != nil {
		t.Fatalf("SetPassword bob: %v", err)
	}
}

// TestIdsecBasicKeyring_UsesAFreshNonceForEveryStoredRecord verifies that storing the
// same secret many times gives every stored record its own nonce, and never produces
// the same stored ciphertext twice.
func TestIdsecBasicKeyring_UsesAFreshNonceForEveryStoredRecord(t *testing.T) {
	const storedRecords = 128
	const sameSecret = "the very same secret every time"

	keyring := newIsolatedKeyring(t)
	for i := 0; i < storedRecords; i++ {
		if err := keyring.SetPassword("github", fmt.Sprintf("user-%03d", i), sameSecret); err != nil {
			t.Fatalf("SetPassword user-%03d: %v", i, err)
		}
	}

	entries := readStoredEnvelope(t, keyring).Entries["github"]
	if len(entries) != storedRecords {
		t.Fatalf("Expected %d stored records, got %d", storedRecords, len(entries))
	}
	noncesSeen := make(map[string]string, storedRecords)
	ciphertextsSeen := make(map[string]string, storedRecords)
	for username, entry := range entries {
		nonce, err := base64.StdEncoding.DecodeString(entry.Nonce)
		if err != nil {
			t.Fatalf("Failed to decode the nonce of %q: %v", username, err)
		}
		if len(nonce) != nonceSize {
			t.Errorf("Expected a %d byte nonce for %q, got %d bytes", nonceSize, username, len(nonce))
		}
		if previous, seen := noncesSeen[entry.Nonce]; seen {
			t.Errorf("Records for %q and %q were stored under the same nonce", previous, username)
		}
		noncesSeen[entry.Nonce] = username
		if previous, seen := ciphertextsSeen[entry.Ciphertext]; seen {
			t.Errorf("Records for %q and %q were stored as the same ciphertext", previous, username)
		}
		ciphertextsSeen[entry.Ciphertext] = username
	}
}

// TestIdsecBasicKeyring_ReadsBackRecordsThroughASecondInstance verifies that a
// credential written by one keyring is readable by another one built against the same
// folder and master secret, which is what a second process does.
func TestIdsecBasicKeyring_ReadsBackRecordsThroughASecondInstance(t *testing.T) {
	writer := newIsolatedKeyring(t)
	if err := writer.SetPassword("github", "testuser", "testpassword"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	reader := NewIdsecBasicKeyring()
	if reader == nil {
		t.Fatal("Failed to create the second keyring")
	}

	assertStoredPassword(t, reader, "github", "testuser", "testpassword")
	keys, err := reader.ListKeys("github")
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 || keys[0] != "testuser" {
		t.Errorf("Expected the stored username to be listed, got %v", keys)
	}
}

// TestIdsecBasicKeyring_DerivesDistinctEncryptionAndMacKeys verifies that the record
// encryption key and the file mac key differ even though they come from the same
// master secret and salt, and that both are re-derived identically from those inputs.
func TestIdsecBasicKeyring_DerivesDistinctEncryptionAndMacKeys(t *testing.T) {
	keyring := newIsolatedKeyring(t)
	if err := keyring.SetPassword("github", "testuser", "testpassword"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	secret, err := os.ReadFile(keyring.keyFilePath)
	if err != nil {
		t.Fatalf("Failed to read the master secret: %v", err)
	}
	salt, err := base64.StdEncoding.DecodeString(readStoredEnvelope(t, keyring).KDF.Salt)
	if err != nil {
		t.Fatalf("Failed to decode the stored salt: %v", err)
	}

	keys, err := keyring.deriveKeys(secret, salt)
	if err != nil {
		t.Fatalf("deriveKeys: %v", err)
	}

	if len(keys.encKey) != derivedKeySize {
		t.Errorf("Expected a %d byte record encryption key, got %d bytes", derivedKeySize, len(keys.encKey))
	}
	if len(keys.macKey) != derivedKeySize {
		t.Errorf("Expected a %d byte file mac key, got %d bytes", derivedKeySize, len(keys.macKey))
	}
	if bytes.Equal(keys.encKey, keys.macKey) {
		t.Error("Expected the record encryption key and the file mac key to differ")
	}
	again, err := keyring.deriveKeys(secret, salt)
	if err != nil {
		t.Fatalf("deriveKeys a second time: %v", err)
	}
	if !bytes.Equal(keys.encKey, again.encKey) || !bytes.Equal(keys.macKey, again.macKey) {
		t.Error("Expected the same master secret and salt to yield the same keys")
	}
}

// TestIdsecBasicKeyring_ReplacesAKeyringInAnEarlierFormatOnWrite verifies that a
// keyring left behind by an earlier build does not block a write: the new credential
// is stored in the current format and reads back.
func TestIdsecBasicKeyring_ReplacesAKeyringInAnEarlierFormatOnWrite(t *testing.T) {
	keyring := newIsolatedKeyring(t)
	seedEarlierFormatKeyring(t, keyring)

	if err := keyring.SetPassword("github", "testuser", "newpassword"); err != nil {
		t.Fatalf("SetPassword over an earlier format: %v", err)
	}

	assertStoredPassword(t, keyring, "github", "testuser", "newpassword")
	assertStoredEnvelopeIsCurrentFormat(t, keyring)
}

// TestIdsecBasicKeyring_RecoversWhenTheMasterSecretIsMissing verifies that a keyring
// whose master secret has been removed reads as a cache miss, and that normal
// operation resumes against a fresh keyring afterwards.
func TestIdsecBasicKeyring_RecoversWhenTheMasterSecretIsMissing(t *testing.T) {
	keyring := newIsolatedKeyring(t)
	seedKeyringWithoutItsKeyFile(t, keyring)

	assertStoredPassword(t, keyring, "github", "testuser", "")
	assertKeyringStateRemoved(t, keyring)

	if err := keyring.SetPassword("github", "testuser", "newpassword"); err != nil {
		t.Fatalf("SetPassword after the master secret was removed: %v", err)
	}
	assertStoredPassword(t, keyring, "github", "testuser", "newpassword")
	assertStoredEnvelopeIsCurrentFormat(t, keyring)
	assertMasterSecretPresent(t, keyring)
}

// TestIdsecBasicKeyring_DiscardsAnEnvelopeWithAnUnsupportedVersion verifies that a
// keyring written by a future build is discarded rather than misread.
func TestIdsecBasicKeyring_DiscardsAnEnvelopeWithAnUnsupportedVersion(t *testing.T) {
	keyring := newIsolatedKeyring(t)
	if err := keyring.SetPassword("github", "testuser", "testpassword"); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	envelope := readStoredEnvelope(t, keyring)
	envelope.Version = 99
	storeEnvelopeVerbatim(t, keyring, &envelope)

	assertStoredPassword(t, keyring, "github", "testuser", "")

	assertKeyringStateRemoved(t, keyring)
}

// TestIdsecBasicKeyring_RejectsAnAlteredRecord verifies that a record whose stored
// bytes no longer match what was sealed is reported as absent, while the records
// stored next to it still read back.
func TestIdsecBasicKeyring_RejectsAnAlteredRecord(t *testing.T) {
	tests := []struct {
		name       string
		alterFunc  func(t *testing.T, entry record) record
		alteredKey string
	}{
		{
			name: "altered_ciphertext",
			alterFunc: func(t *testing.T, entry record) record {
				t.Helper()
				entry.Ciphertext = flipBase64Byte(t, entry.Ciphertext)
				return entry
			},
			alteredKey: "alice",
		},
		{
			name: "altered_tag",
			alterFunc: func(t *testing.T, entry record) record {
				t.Helper()
				entry.Tag = flipBase64Byte(t, entry.Tag)
				return entry
			},
			alteredKey: "alice",
		},
	}

	for _, tt := range tests {
		t.Run("success_reports_a_cache_miss_for_an_"+tt.name, func(t *testing.T) {
			keyring := newIsolatedKeyring(t)
			seedTwoRecords(t, keyring)

			envelope := readStoredEnvelope(t, keyring)
			envelope.Entries["github"][tt.alteredKey] = tt.alterFunc(t, envelope.Entries["github"][tt.alteredKey])
			storeEnvelopeAuthenticatedWith(t, keyring, &envelope, macKeyForStoredEnvelope(t, keyring, &envelope))

			assertStoredPassword(t, keyring, "github", tt.alteredKey, "")
			assertStoredPassword(t, keyring, "github", "bob", "secret-b")
		})
	}
}

// TestIdsecBasicKeyring_RejectsARecordStoredUnderAnotherUsername verifies that a
// record is bound to the service name and username it was stored under: the same
// record read for a different username is reported as absent even though the record
// itself is untouched and the file is authenticated correctly.
func TestIdsecBasicKeyring_RejectsARecordStoredUnderAnotherUsername(t *testing.T) {
	keyring := newIsolatedKeyring(t)
	seedTwoRecords(t, keyring)

	envelope := readStoredEnvelope(t, keyring)
	envelope.Entries["github"]["carol"] = envelope.Entries["github"]["alice"]
	delete(envelope.Entries["github"], "alice")
	storeEnvelopeAuthenticatedWith(t, keyring, &envelope, macKeyForStoredEnvelope(t, keyring, &envelope))

	assertStoredPassword(t, keyring, "github", "carol", "")
	assertStoredPassword(t, keyring, "github", "bob", "secret-b")
}

// TestIdsecBasicKeyring_RejectsAnEnvelopeAuthenticatedWithAnotherKey verifies that
// removing a record and authenticating the result with a key the keyring did not
// derive discards the whole stored keyring rather than accepting the removal.
//
// This covers a mismatched file mac generally, so there is no separate case for one
// whose bytes were altered directly: both are rejected by the same comparison, and an
// envelope re-authenticated with the wrong key is the stronger of the two because it
// also proves the mac is computed over the entries rather than over the file alone.
func TestIdsecBasicKeyring_RejectsAnEnvelopeAuthenticatedWithAnotherKey(t *testing.T) {
	keyring := newIsolatedKeyring(t)
	seedTwoRecords(t, keyring)

	envelope := readStoredEnvelope(t, keyring)
	delete(envelope.Entries["github"], "bob")
	unrelatedKey := make([]byte, derivedKeySize)
	if _, err := rand.Read(unrelatedKey); err != nil {
		t.Fatalf("Failed to generate an unrelated key: %v", err)
	}
	storeEnvelopeAuthenticatedWith(t, keyring, &envelope, unrelatedKey)

	assertStoredPassword(t, keyring, "github", "alice", "")

	assertKeyringStateRemoved(t, keyring)
}

// TestNewIdsecBasicKeyring_ReportsAnUnresolvableHomeDirectory verifies that a keyring
// which needs a home directory it cannot resolve yields nothing, rather than falling
// back to a path relative to the working directory.
func TestNewIdsecBasicKeyring_ReportsAnUnresolvableHomeDirectory(t *testing.T) {
	workingDirectory := t.TempDir()
	t.Chdir(workingDirectory)
	// The production code treats an empty value as unset, so clearing the variables
	// forces both locations to be derived from the home directory.
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv(IdsecBasicKeyringFolderEnvVar, "")
	t.Setenv(IdsecBasicKeyringKeyFileEnvVar, "")

	keyring := NewIdsecBasicKeyring()

	if keyring != nil {
		t.Fatalf("Expected no keyring, got one rooted at '%s'", keyring.basicFolderPath)
	}
	entries, err := os.ReadDir(workingDirectory)
	if err != nil {
		t.Fatalf("Failed to inspect the working directory: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Errorf("Expected nothing to be created in the working directory, got %v", names)
	}
}
