// Package keyring provides keyring utilities for the IDSEC SDK.
//
// This package contains internal implementations including a basic keyring system for
// secure password storage using AES-GCM encryption.
//
// The basic keyring is a credential cache rather than a system of record. On-disk state
// that cannot be interpreted is therefore treated as a cache miss: the stored files are
// reset and the caller receives an empty result so that it can re-authenticate. Genuine
// I/O failures such as permission errors or a full disk are still reported to the caller.
package keyring

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
)

const (
	// nonceSize defines the size in bytes for AES-GCM nonce generation.
	nonceSize = 12
	// tagSize defines the size in bytes for AES-GCM authentication tag.
	tagSize = 16
	// saltSize defines the size in bytes of the per-store key derivation salt.
	saltSize = 16
	// masterSecretSize defines the size in bytes of the persisted master secret.
	masterSecretSize = 32
	// derivedKeySize defines the size in bytes of each key derived from the master secret.
	derivedKeySize = 32
)

const (
	// keyringFormatVersion is the on-disk envelope version this build reads and writes.
	// Any other version, including the absent version field of a version 1 file, is
	// discarded rather than migrated.
	keyringFormatVersion = 2

	// kdfAlgorithmHKDFSHA256 is the only key derivation algorithm this build recognises.
	kdfAlgorithmHKDFSHA256 = "hkdf-sha256"

	// encKeyInfo and macKeyInfo are the HKDF info strings that give the two derived keys
	// domain separation, so neither can stand in for the other.
	encKeyInfo = "idsec-keyring-v2-enc"
	macKeyInfo = "idsec-keyring-v2-mac"

	// aadSeparator joins a service name and a username into the additional authenticated
	// data of a record; see recordAAD for why an input containing one is rejected.
	aadSeparator = "\x00"
)

const (
	// keyringFileName is the name of the envelope file inside the keyring folder.
	keyringFileName = "keyring"

	// legacyMacFileName is the version 1 MAC sidecar. Version 2 never writes it; the name
	// is retained so that a reset removes a leftover copy.
	legacyMacFileName = "mac"

	// redactedMarker stands in for key material in the keyring's own formatted output.
	redactedMarker = "[redacted]"
)

// Keyring configuration constants
const (
	// DefaultBasicKeyringFolder is the default folder path relative to the home directory
	// where the basic keyring files are stored.
	DefaultBasicKeyringFolder = ".idsec/cache/keyring"

	// DefaultBasicKeyringKeyFile is the default path relative to the home directory of the
	// file holding the keyring master secret. It deliberately lives outside
	// DefaultBasicKeyringFolder, because cache folders are routinely mounted into
	// containers, archived as CI artifacts and swept up by backup agents, and key material
	// stored beside the ciphertext travels with it.
	DefaultBasicKeyringKeyFile = ".idsec/keys/keyring.key"

	// IdsecBasicKeyringFolderEnvVar is the environment variable name that can be used
	// to override the default keyring folder location. It does not relocate the master
	// secret; use IdsecBasicKeyringKeyFileEnvVar for that.
	IdsecBasicKeyringFolderEnvVar = "IDSEC_KEYRING_FOLDER"

	// IdsecBasicKeyringKeyFileEnvVar is the environment variable name that can be used
	// to override the default location of the file holding the keyring master secret.
	IdsecBasicKeyringKeyFileEnvVar = "IDSEC_KEYRING_KEY_FILE"
)

// ErrKeyringUnusable indicates that the stored keyring state cannot be interpreted, for
// any reason: an unsupported format version, an unrecognised key derivation algorithm, an
// absent or unusable master secret, a missing or mismatched MAC, malformed JSON,
// undecodable base64 or a failed AES-GCM open.
//
// It deliberately does not cover genuine I/O failures such as a permission error or a full
// disk, which are reported as the underlying *os.PathError so that callers can tell an
// unusable cache apart from a broken environment.
//
// The keyring methods never surface this sentinel. They treat it as a cache miss, reset
// the stored files and continue against an empty store, which is what allows a caller to
// recover by re-authenticating.
var ErrKeyringUnusable = errors.New("keyring state is unusable")

// ErrKeyringInvalidName indicates that a service name or username cannot be stored,
// because it contains the NUL byte that recordAAD relies on to bind a record
// unambiguously.
//
// Unlike ErrKeyringUnusable this describes the caller's arguments rather than on-disk
// state, so it is not treated as a cache miss and is returned to the caller.
var ErrKeyringInvalidName = errors.New("keyring service name or username is not valid")

// Reasons for which stored keyring state cannot be interpreted. Each wraps
// ErrKeyringUnusable, and they exist so that the severity of a reset is chosen by a typed
// check rather than by matching on message text.
var (
	errMacMissing         = fmt.Errorf("%w: mac is missing", ErrKeyringUnusable)
	errMacMismatch        = fmt.Errorf("%w: mac does not match the keyring contents", ErrKeyringUnusable)
	errContentsMalformed  = fmt.Errorf("%w: keyring contents are malformed", ErrKeyringUnusable)
	errRecordUndecodable  = fmt.Errorf("%w: keyring record cannot be decoded", ErrKeyringUnusable)
	errRecordUndecrypted  = fmt.Errorf("%w: keyring record failed to decrypt", ErrKeyringUnusable)
	errVersionUnsupported = fmt.Errorf("%w: keyring format version is not supported", ErrKeyringUnusable)
	errKDFUnsupported     = fmt.Errorf("%w: keyring key derivation algorithm is not supported", ErrKeyringUnusable)
	errKeyFileMissing     = fmt.Errorf("%w: keyring key file is missing", ErrKeyringUnusable)
	errKeyFileMalformed   = fmt.Errorf("%w: keyring key file does not hold a usable master secret", ErrKeyringUnusable)
)

// unusableWarningReasons lists the reasons that a warning is worth emitting for. Every
// other reason is a routine consequence of an interrupted write, an upgrade that leaves an
// older format behind, or the master secret being removed to invalidate the cache on
// purpose, so it is reported at info level.
var unusableWarningReasons = []error{errMacMismatch, errRecordUndecrypted}

// record is the stored form of a single encrypted credential. The ciphertext and the
// authentication tag are kept in separate fields, which is the layout earlier versions of
// the keyring used.
type record struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	Tag        string `json:"tag"`
}

// kdfParams describes how the keys protecting an envelope were derived. Algorithm is
// recorded so that a future change of algorithm is detected rather than silently
// misinterpreted. Salt is generated fresh whenever a store is created, so resetting a
// store changes every key derived from it.
type kdfParams struct {
	Algorithm string `json:"algorithm"`
	Salt      string `json:"salt"`
}

// keyringEnvelope is the on-disk representation of the whole keyring: format version, key
// derivation parameters, every encrypted record, and a MAC over all of the above.
// Authenticating the structure and not just the individual records is what detects a
// record being removed or moved between users.
type keyringEnvelope struct {
	Version int                          `json:"version"`
	KDF     kdfParams                    `json:"kdf"`
	Entries map[string]map[string]record `json:"entries"`
	MAC     string                       `json:"mac"`
}

// keyringEnvelopeMACInput is the canonical subset of a keyringEnvelope that its MAC
// authenticates, which is every field except the MAC itself. Encoding it through a typed
// struct keeps the encoding deterministic and pins exactly which fields are authenticated;
// see canonicalMACInput for what that means for a format that adds fields later.
type keyringEnvelopeMACInput struct {
	Version int                          `json:"version"`
	KDF     kdfParams                    `json:"kdf"`
	Entries map[string]map[string]record `json:"entries"`
}

// derivedKeys holds the two keys derived from the master secret and one salt.
type derivedKeys struct {
	// salt is the salt these keys were derived from, used to detect a stale cache
	salt []byte
	// encKey seals and opens individual records
	encKey []byte
	// macKey authenticates the envelope as a whole
	macKey []byte
}

// keyringState is the decoded, in-memory view of a keyring envelope.
//
// entries is always non-nil. salt is empty for a state that has never been persisted, in
// which case a write fills it in. keys is nil until a read has authenticated an envelope
// or a write has derived them, so any state that exposes an entry also carries the keys
// needed to open it.
type keyringState struct {
	salt    []byte
	keys    *derivedKeys
	entries map[string]map[string]record
}

// newKeyringState returns an empty state that no envelope has been read into.
func newKeyringState() *keyringState {
	return &keyringState{entries: make(map[string]map[string]record)}
}

// randomBytes returns n cryptographically random bytes.
//
// Every piece of key material and every nonce this package generates comes from here, so
// that the one call to crypto/rand is in a single place rather than repeated at each site
// that needs randomness. Keeping it in its own function is also what lets a static analyser
// tie a generated nonce to crypto/rand: an analyser that cannot see through a slice filled
// in place reports a nonce built that way as hardcoded.
func randomBytes(n int) ([]byte, error) {
	buffer := make([]byte, n)
	if _, err := rand.Read(buffer); err != nil {
		return nil, err
	}
	return buffer, nil
}

// ensureSalt fills in a fresh random salt when the state does not carry a usable one.
func (s *keyringState) ensureSalt() error {
	if len(s.salt) == saltSize {
		return nil
	}
	salt, err := randomBytes(saltSize)
	if err != nil {
		return err
	}
	s.salt = salt
	return nil
}

// IdsecBasicKeyring is a file-backed keyring implementation that stores passwords
// encrypted with AES-GCM.
//
// Entries live in a single versioned envelope file. The record encryption key and the file
// MAC key are derived with HKDF-SHA256 from a master secret generated once and stored
// outside the keyring folder, and from a per-store salt held in the envelope. Each record
// is sealed under its own random nonce and bound to the service name and username it is
// stored under through the GCM additional authenticated data, so a record copied from one
// user to another no longer opens. The file-level HMAC-SHA256 covers the version, the key
// derivation parameters and every record, which is what detects a record being deleted
// rather than altered.
//
// The keyring is a credential cache, so integrity failures are not fatal. State that
// cannot be interpreted is discarded and reported to the caller as an absent value; a
// single undecryptable entry is reported as absent on its own, leaving the rest readable.
// Genuine I/O failures are returned unchanged. Version 1 keyrings, which derived their key
// from the system hostname and kept their MAC in a sidecar file, are not migrated but
// discarded and replaced on the next write.
//
// Writes are atomic, so an interrupted write cannot leave a truncated file behind.
//
// The type is not safe for concurrent use: its read-modify-write file operations were never
// serialised, and the derived key cache is guarded no more carefully than they are.
//
// Every exported method tolerates a nil receiver and reports ErrKeyringUnavailable rather
// than panicking, because NewIdsecBasicKeyring signals failure by returning nil and a nil
// *IdsecBasicKeyring assigned to an IdsecKeyringImpl compares unequal to nil, which makes
// the omission of a nil check invisible at the call site.
//
// Formatting a keyring never discloses key material, whatever verb is used; see String.
//
// File Structure:
//   - keyring: JSON envelope holding the format version, the key derivation
//     parameters, the encrypted records and the file-level MAC
//   - keyring.key: the master secret, stored outside the keyring folder
//   - mac: version 1 sidecar, never written and removed on reset
type IdsecBasicKeyring struct {
	IdsecKeyringImpl
	// basicFolderPath is the absolute path to the keyring folder
	basicFolderPath string
	// keyringFilePath is the absolute path to the keyring envelope file
	keyringFilePath string
	// macFilePath is the absolute path to the version 1 MAC sidecar file, retained
	// only so that a reset removes a leftover copy
	macFilePath string
	// keyFilePath is the absolute path to the file holding the master secret, which
	// lives outside basicFolderPath
	keyFilePath string
	// masterSecret caches the master secret read from or written to keyFilePath
	masterSecret []byte
	// keys caches the keys derived from masterSecret and one salt
	keys *derivedKeys
	// logger reports cache misses caused by unusable keyring state
	logger *common.IdsecLogger
}

// NewIdsecBasicKeyring creates a new IdsecBasicKeyring instance with initialized folder and file paths.
//
// NewIdsecBasicKeyring initializes the keyring folder structure and returns a new IdsecBasicKeyring
// instance. The folder location is determined by the IdsecBasicKeyringFolderEnvVar environment
// variable, or defaults to DefaultBasicKeyringFolder within the user's home directory. The master
// secret location is determined independently by IdsecBasicKeyringKeyFileEnvVar, or defaults to
// DefaultBasicKeyringKeyFile within the user's home directory; relocating the keyring folder
// deliberately does not relocate the master secret.
//
// The home directory is resolved with os.UserHomeDir and only when a default is actually needed,
// so setting both environment variables works where no home directory can be resolved. An
// unresolvable home directory that is needed yields nil rather than a path relative to the
// working directory.
//
// The keyring folder is created if it doesn't exist, restricted to the current user. The folder
// holding the master secret is created on first use instead, so that merely constructing a
// keyring never creates key material.
//
// Returns a new IdsecBasicKeyring instance or nil if the home directory cannot be resolved or
// folder creation fails.
//
// Environment Variables:
//   - IDSEC_KEYRING_FOLDER: Override default keyring folder location
//   - IDSEC_KEYRING_KEY_FILE: Override default master secret file location
//
// Example:
//
//	keyring := NewIdsecBasicKeyring()
//	if keyring == nil {
//	    // Handle keyring initialization failure
//	}
func NewIdsecBasicKeyring() *IdsecBasicKeyring {
	// GetLogger yields nil for every logger style other than the default one, and the
	// recovery paths below log unconditionally, so fall back to a plain logger
	// configured the same way the default style configures one.
	logger := common.GetLogger("IdsecBasicKeyring", common.Unknown)
	if logger == nil {
		logger = common.NewIdsecLogger("IdsecBasicKeyring", common.LogLevelFromEnv(), true, true)
	}
	var basicFolderPath, keyFilePath string
	if folder := os.Getenv(IdsecBasicKeyringFolderEnvVar); folder != "" {
		basicFolderPath = filepath.Clean(folder)
	}
	if keyFile := os.Getenv(IdsecBasicKeyringKeyFileEnvVar); keyFile != "" {
		keyFilePath = filepath.Clean(keyFile)
	}
	if basicFolderPath == "" || keyFilePath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			logger.Warning("Failed to resolve the home directory for the keyring [%v]", err)
			return nil
		}
		if basicFolderPath == "" {
			basicFolderPath = filepath.Join(homeDir, DefaultBasicKeyringFolder)
		}
		if keyFilePath == "" {
			keyFilePath = filepath.Join(homeDir, DefaultBasicKeyringKeyFile)
		}
	}
	if _, err := os.Stat(basicFolderPath); os.IsNotExist(err) {
		if err := os.MkdirAll(basicFolderPath, 0700); err != nil {
			logger.Warning("Failed to create the keyring folder [%v]", err)
			return nil
		}
	}
	return &IdsecBasicKeyring{
		basicFolderPath: basicFolderPath,
		keyringFilePath: filepath.Join(basicFolderPath, keyringFileName),
		macFilePath:     filepath.Join(basicFolderPath, legacyMacFileName),
		keyFilePath:     keyFilePath,
		logger:          logger,
	}
}

// String returns a description of the keyring that carries no key material.
//
// The struct holds the master secret and the keys derived from it in ordinary fields, so a
// verb that walks those fields would otherwise write raw key bytes into whatever collects
// the log, and those logs travel in CI artifacts and support bundles. Implementing Stringer
// makes redaction a property of the type rather than something every caller must remember.
// Paths are safe to report and are the part worth having in a log, so they are included.
//
// Returns a description naming the file paths in use, with all key material replaced by a
// redaction marker.
//
// Example:
//
//	log.Printf("keyring in use: %v", keyring)
func (b *IdsecBasicKeyring) String() string {
	if b == nil {
		return "IdsecBasicKeyring(nil)"
	}
	return fmt.Sprintf(
		"IdsecBasicKeyring{keyringFile: %q, keyFile: %q, masterSecret: %s, keys: %s}",
		b.keyringFilePath, b.keyFilePath, redactedMarker, redactedMarker,
	)
}

// GoString returns the same redacted description that String returns.
//
// GoString covers the one family of verbs that Stringer does not: %#v is satisfied from
// GoStringer if the value implements it, and otherwise by walking the struct fields and
// printing the master secret as a byte slice literal.
//
// Returns the redacted description produced by String.
//
// Example:
//
//	log.Printf("keyring in use: %#v", keyring)
func (b *IdsecBasicKeyring) GoString() string {
	return b.String()
}

// loadMasterSecret returns the persisted master secret without creating one.
//
// An absent or wrongly sized key file cannot have produced the stored records, so it is
// reported as ErrKeyringUnusable, which is also what makes removing the key file a
// deliberate way to invalidate the cache. Any other read failure is returned unchanged.
//
// A cached secret is only trusted while the key file it came from still exists, so that
// removing that file invalidates a live instance and not merely the next one constructed.
// Both cached secret and cached keys are dropped in that case, so a subsequent write
// derives afresh rather than sealing a record under a secret that is gone from disk.
func (b *IdsecBasicKeyring) loadMasterSecret() ([]byte, error) {
	if len(b.masterSecret) == masterSecretSize {
		if _, err := os.Stat(b.keyFilePath); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			b.masterSecret = nil
			b.keys = nil
			return nil, errKeyFileMissing
		}
		return b.masterSecret, nil
	}
	secret, err := os.ReadFile(b.keyFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errKeyFileMissing
		}
		return nil, err
	}
	if len(secret) != masterSecretSize {
		return nil, fmt.Errorf("%w: holds %d bytes, expected %d", errKeyFileMalformed, len(secret), masterSecretSize)
	}
	b.masterSecret = secret
	return secret, nil
}

// ensureMasterSecret returns the persisted master secret, generating and storing a new one
// when the key file is absent or does not hold usable key material.
//
// The containing folder is created here rather than in the constructor so that reading an
// absent keyring never leaves key material behind. Genuine I/O failures are returned
// unchanged instead of being replaced by a fresh secret.
func (b *IdsecBasicKeyring) ensureMasterSecret() ([]byte, error) {
	secret, err := b.loadMasterSecret()
	if err == nil {
		return secret, nil
	}
	if !errors.Is(err, ErrKeyringUnusable) {
		return nil, err
	}
	secret, err = randomBytes(masterSecretSize)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(b.keyFilePath), 0700); err != nil {
		return nil, err
	}
	if err := b.writeFileAtomically(b.keyFilePath, secret); err != nil {
		return nil, err
	}
	b.masterSecret = secret
	return secret, nil
}

// deriveKeys derives the record encryption key and the file MAC key from a salt.
//
// The result is cached against the salt it came from, so HKDF runs once per salt per
// instance. Whether the master secret behind it is still valid is decided by
// loadMasterSecret, which clears this cache when the key file disappears so that a matching
// salt can never resurrect keys derived from a secret that is gone.
func (b *IdsecBasicKeyring) deriveKeys(secret []byte, salt []byte) (*derivedKeys, error) {
	if b.keys != nil && bytes.Equal(b.keys.salt, salt) {
		return b.keys, nil
	}
	encKey, err := hkdf.Key(sha256.New, secret, salt, encKeyInfo, derivedKeySize)
	if err != nil {
		return nil, err
	}
	macKey, err := hkdf.Key(sha256.New, secret, salt, macKeyInfo, derivedKeySize)
	if err != nil {
		return nil, err
	}
	b.keys = &derivedKeys{salt: bytes.Clone(salt), encKey: encKey, macKey: macKey}
	return b.keys, nil
}

// keysForRead returns the keys for an existing salt without creating key material. The
// master secret is consulted on every call so that a key file removed since the last call
// is noticed.
func (b *IdsecBasicKeyring) keysForRead(salt []byte) (*derivedKeys, error) {
	secret, err := b.loadMasterSecret()
	if err != nil {
		return nil, err
	}
	return b.deriveKeys(secret, salt)
}

// keysForWrite returns the keys for a salt, generating master key material if needed.
//
// Only this path creates a key file, which keeps a read of an absent keyring free of side
// effects. A key file removed since the last call is regenerated here rather than reported,
// so a write always seals its record under a secret that exists on disk.
func (b *IdsecBasicKeyring) keysForWrite(salt []byte) (*derivedKeys, error) {
	secret, err := b.ensureMasterSecret()
	if err != nil {
		return nil, err
	}
	return b.deriveKeys(secret, salt)
}

// recordAAD binds a record to the service name and username it is stored under, so that a
// record moved to another service or username fails to open even though its own tag is
// still intact.
//
// The encoding is only injective while neither input contains the separator, so an input
// that does is rejected rather than encoded ambiguously: otherwise the pairs ("a\x00b",
// "c") and ("a", "b\x00c") would share one additional authenticated data and their records
// would open interchangeably. Rejecting rather than switching to a length-prefixed encoding
// keeps every record already written by this build readable.
func recordAAD(serviceName string, username string) ([]byte, error) {
	if strings.Contains(serviceName, aadSeparator) || strings.Contains(username, aadSeparator) {
		return nil, fmt.Errorf("%w: service name and username must not contain a NUL byte", ErrKeyringInvalidName)
	}
	return []byte(serviceName + aadSeparator + username), nil
}

// canonicalMACInput encodes the part of an envelope that its MAC authenticates.
//
// The encoding is byte-for-byte reproducible because struct fields marshal in declaration
// order and encoding/json sorts map keys, so a read and a write of the same values yield
// identical bytes.
//
// Only the fields named by keyringEnvelopeMACInput are covered. A field a future envelope
// adds is dropped on unmarshal and never reaches the MAC, so it is not authenticated here
// and can be added or removed without invalidating the MAC. A later format that actually
// reads such a field must cover it, and doing so makes existing files fail validation, so
// that change belongs with a keyringFormatVersion bump.
func canonicalMACInput(envelope *keyringEnvelope) ([]byte, error) {
	return json.Marshal(keyringEnvelopeMACInput{
		Version: envelope.Version,
		KDF:     envelope.KDF,
		Entries: envelope.Entries,
	})
}

// envelopeMAC computes the file-level HMAC-SHA256 over a canonical envelope encoding.
func envelopeMAC(macKey []byte, canonical []byte) []byte {
	mac := hmac.New(sha256.New, macKey)
	// hash.Hash never reports a write failure.
	_, _ = mac.Write(canonical)
	return mac.Sum(nil)
}

// encrypt seals a secret into a record bound to a service name and username. The nonce is
// drawn fresh from crypto/rand for every write, so two writes of the same secret under the
// same key never produce the same ciphertext.
func (b *IdsecBasicKeyring) encrypt(encKey []byte, serviceName string, username string, data string) (record, error) {
	aad, err := recordAAD(serviceName, username)
	if err != nil {
		return record{}, err
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return record{}, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return record{}, err
	}
	nonce, err := randomBytes(nonceSize)
	if err != nil {
		return record{}, err
	}
	ciphertextWithTag := aesGCM.Seal(nil, nonce, []byte(data), aad)
	ciphertext := ciphertextWithTag[:len(ciphertextWithTag)-tagSize]
	tag := ciphertextWithTag[len(ciphertextWithTag)-tagSize:]
	return record{
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Tag:        base64.StdEncoding.EncodeToString(tag),
	}, nil
}

// decrypt opens a record that was sealed under the given service name and username.
//
// A record whose fields cannot be decoded and a record that fails to authenticate are both
// reported as ErrKeyringUnusable. The nonce length is checked before the open, because
// AES-GCM panics rather than erring on a nonce of the wrong size.
func (b *IdsecBasicKeyring) decrypt(encKey []byte, serviceName string, username string, entry record) (string, error) {
	aad, err := recordAAD(serviceName, username)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce, err := base64.StdEncoding.DecodeString(entry.Nonce)
	if err != nil {
		return "", fmt.Errorf("%w: nonce: %w", errRecordUndecodable, err)
	}
	if len(nonce) != aesGCM.NonceSize() {
		return "", fmt.Errorf("%w: nonce is %d bytes, expected %d", errRecordUndecodable, len(nonce), aesGCM.NonceSize())
	}
	ciphertext, err := base64.StdEncoding.DecodeString(entry.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("%w: ciphertext: %w", errRecordUndecodable, err)
	}
	tag, err := base64.StdEncoding.DecodeString(entry.Tag)
	if err != nil {
		return "", fmt.Errorf("%w: tag: %w", errRecordUndecodable, err)
	}
	fullCiphertext := make([]byte, 0, len(ciphertext)+len(tag))
	fullCiphertext = append(fullCiphertext, ciphertext...)
	fullCiphertext = append(fullCiphertext, tag...)
	plaintext, err := aesGCM.Open(nil, nonce, fullCiphertext, aad)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errRecordUndecrypted, err)
	}
	return string(plaintext), nil
}

// readStore loads and validates the stored keyring envelope.
//
// An absent keyring file yields an empty state and a nil error without touching the key
// file, so a read of a keyring that was never written creates nothing. A present keyring
// file is checked in the order that keeps recovery cheap: version, key derivation
// parameters, then the file MAC. State that cannot be interpreted yields
// ErrKeyringUnusable, while genuine I/O failures are returned unchanged.
//
// Together with reset this is the chokepoint every exported method passes through, so the
// nil receiver check here is what turns a keyring whose construction failed into
// ErrKeyringUnavailable rather than a panic.
func (b *IdsecBasicKeyring) readStore() (*keyringState, error) {
	if b == nil {
		return nil, ErrKeyringUnavailable
	}
	data, err := os.ReadFile(b.keyringFilePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return newKeyringState(), nil
		}
		return nil, err
	}
	var envelope keyringEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("%w: %w", errContentsMalformed, err)
	}
	// A version 1 file carries no version field and so unmarshals to version 0. Such a
	// file is discarded rather than migrated, which is why no version but the current
	// one is accepted here.
	if envelope.Version != keyringFormatVersion {
		return nil, fmt.Errorf("%w: found version %d, expected %d", errVersionUnsupported, envelope.Version, keyringFormatVersion)
	}
	if envelope.KDF.Algorithm != kdfAlgorithmHKDFSHA256 {
		return nil, fmt.Errorf("%w: found %q, expected %q", errKDFUnsupported, envelope.KDF.Algorithm, kdfAlgorithmHKDFSHA256)
	}
	salt, err := base64.StdEncoding.DecodeString(envelope.KDF.Salt)
	if err != nil {
		return nil, fmt.Errorf("%w: salt: %w", errContentsMalformed, err)
	}
	if len(salt) != saltSize {
		return nil, fmt.Errorf("%w: salt is %d bytes, expected %d", errContentsMalformed, len(salt), saltSize)
	}
	if envelope.MAC == "" {
		return nil, errMacMissing
	}
	storedMac, err := hex.DecodeString(envelope.MAC)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errMacMismatch, err)
	}
	keys, err := b.keysForRead(salt)
	if err != nil {
		return nil, err
	}
	// The canonical encoding is taken before the entries map is normalised below, so
	// that an envelope written with a null entries map validates against the same bytes
	// it was signed over.
	canonical, err := canonicalMACInput(&envelope)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errContentsMalformed, err)
	}
	if !hmac.Equal(storedMac, envelopeMAC(keys.macKey, canonical)) {
		return nil, errMacMismatch
	}
	entries := envelope.Entries
	if entries == nil {
		entries = make(map[string]map[string]record)
	}
	return &keyringState{salt: salt, keys: keys, entries: entries}, nil
}

// writeStore persists the keyring entries as a version 2 envelope.
//
// The whole keyring is one file, so a single atomic rename replaces both the records and the
// MAC that authenticates them and there is no window in which the two disagree. A state
// carrying no salt yet is given one here, which makes the keys of a freshly reset keyring
// unrelated to those of the keyring it replaced.
func (b *IdsecBasicKeyring) writeStore(state *keyringState) error {
	if err := state.ensureSalt(); err != nil {
		return err
	}
	keys, err := b.keysForWrite(state.salt)
	if err != nil {
		return err
	}
	state.keys = keys
	if state.entries == nil {
		state.entries = make(map[string]map[string]record)
	}
	envelope := keyringEnvelope{
		Version: keyringFormatVersion,
		KDF: kdfParams{
			Algorithm: kdfAlgorithmHKDFSHA256,
			Salt:      base64.StdEncoding.EncodeToString(state.salt),
		},
		Entries: state.entries,
	}
	canonical, err := canonicalMACInput(&envelope)
	if err != nil {
		return err
	}
	envelope.MAC = hex.EncodeToString(envelopeMAC(keys.macKey, canonical))
	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	return b.writeFileAtomically(b.keyringFilePath, data)
}

// writeFileAtomically writes data to a path through a temporary file in the same folder.
//
// The temporary file is created in the target path's own folder so that the rename stays on
// a single filesystem, which matters because the master secret lives outside the keyring
// folder and may be on a different mount. It carries owner-only permissions and is removed
// again on every failure path.
func (b *IdsecBasicKeyring) writeFileAtomically(path string, data []byte) error {
	tempFile, err := os.CreateTemp(filepath.Dir(path), ".idsec-keyring-*")
	if err != nil {
		return err
	}
	tempPath := tempFile.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tempPath)
		}
	}()
	if err := tempFile.Chmod(0600); err != nil {
		_ = tempFile.Close()
		return err
	}
	if _, err := tempFile.Write(data); err != nil {
		_ = tempFile.Close()
		return err
	}
	if err := tempFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

// reset removes the keyring envelope and any leftover version 1 mac sidecar.
//
// The master secret is left in place; discarding it is a heavier action than discarding the
// cache it protects. A file that is already absent counts as success, which keeps the reset
// safe when another process resets concurrently. ClearAllPasswords reaches the receiver only
// through here, so it repeats the nil check readStore performs for the other methods.
func (b *IdsecBasicKeyring) reset() error {
	if b == nil {
		return ErrKeyringUnavailable
	}
	var removeErrors []error
	for _, path := range []string{b.keyringFilePath, b.macFilePath} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			removeErrors = append(removeErrors, err)
		}
	}
	return errors.Join(removeErrors...)
}

// logUnusable reports unusable keyring state at a severity chosen by its reason. The
// reasons in unusableWarningReasons cannot be explained by an interrupted write, an upgrade
// or a deliberate invalidation, so they are worth surfacing even though the cache recovers.
func (b *IdsecBasicKeyring) logUnusable(message string, reason error) {
	for _, warningReason := range unusableWarningReasons {
		if errors.Is(reason, warningReason) {
			b.logger.Warning("%s [%v]", message, reason)
			return
		}
	}
	b.logger.Info("%s [%v]", message, reason)
}

// resetUnusableStore discards keyring state that cannot be interpreted. A failed reset does
// not change the outcome of the operation that triggered it, since the cached credentials
// are unreadable either way, so the failure is logged rather than returned.
func (b *IdsecBasicKeyring) resetUnusableStore(reason error) {
	b.logUnusable("Resetting the keyring cache as it cannot be read", reason)
	if err := b.reset(); err != nil {
		b.logger.Warning("Failed to reset the keyring cache [%v]", err)
	}
}

// resetUnusableStoreForDelete discards unusable keyring state on behalf of an explicit
// delete. DeletePassword asks for a credential to be forgotten, so a removal failure means
// the caller's request was not carried out on disk and is logged differently from the read
// paths, even though the call still reports success.
func (b *IdsecBasicKeyring) resetUnusableStoreForDelete(reason error) {
	b.logUnusable("Resetting the keyring cache as it cannot be read", reason)
	if err := b.reset(); err != nil {
		b.logger.Warning("Failed to remove the keyring cache holding a deleted credential [%v]", err)
	}
}

// SetPassword sets a password for a given service and username in the keyring.
//
// SetPassword encrypts and stores a password for the specified service and username
// combination. The password is sealed with AES-GCM under a key derived with HKDF-SHA256 from
// the stored master secret and the keyring's salt, using a nonce drawn fresh for this write
// and binding the record to the service name and username. The envelope is written
// atomically, so an interrupted write cannot leave a truncated keyring behind.
//
// Stored state that cannot be interpreted never blocks a write: it is reset and the new entry
// is stored in a fresh keyring with a fresh salt. This is also the path that replaces a
// version 1 keyring and regenerates a master secret that has been removed. Genuine I/O
// failures are returned to the caller.
//
// Parameters:
//   - serviceName: The name of the service (e.g., "github", "aws")
//   - username: The username for the service
//   - password: The password to encrypt and store
//
// Returns an error if key derivation, encryption or file operations fail.
//
// Example:
//
//	err := keyring.SetPassword("github", "myuser", "mypassword")
//	if err != nil {
//	    // Handle password storage error
//	}
func (b *IdsecBasicKeyring) SetPassword(serviceName string, username string, password string) error {
	state, err := b.readStore()
	if err != nil {
		if !errors.Is(err, ErrKeyringUnusable) {
			return err
		}
		b.resetUnusableStore(err)
		state = newKeyringState()
	}
	if err := state.ensureSalt(); err != nil {
		return err
	}
	keys, err := b.keysForWrite(state.salt)
	if err != nil {
		return err
	}
	state.keys = keys
	encryptedPassword, err := b.encrypt(keys.encKey, serviceName, username, password)
	if err != nil {
		return err
	}
	// Testing for a nil map rather than for a missing key also covers an envelope that
	// maps a service to JSON null, which unmarshals to a present key holding a nil map
	// that cannot be assigned into.
	if state.entries[serviceName] == nil {
		state.entries[serviceName] = make(map[string]record)
	}
	state.entries[serviceName][username] = encryptedPassword
	return b.writeStore(state)
}

// GetPassword retrieves a password for a given service and username from the keyring.
//
// GetPassword opens and returns the stored password for the specified service and
// username combination. The envelope's format version, key derivation parameters and
// file-level MAC are validated before any record is opened, and the record itself is
// opened against the service name and username it is being read for, so a record moved
// between users does not open. If the keyring file doesn't exist, the service doesn't
// exist, or the username doesn't exist, an empty string is returned without error.
//
// Stored state that cannot be interpreted is treated as a cache miss rather than an error:
// the keyring is reset and an empty string is returned with a nil error. A single entry that
// does not decrypt is reported as absent on its own, leaving the remaining entries readable.
// Genuine I/O failures are returned to the caller.
//
// GetPassword never writes. An unreadable entry is skipped rather than deleted, so a read
// cannot discard an entry another process stored concurrently, and a read against an absent
// keyring file does not create a master secret.
//
// Parameters:
//   - serviceName: The name of the service to retrieve password for
//   - username: The username to retrieve password for
//
// Returns the decrypted password string and any error encountered during retrieval.
// Returns empty string with nil error if the entry doesn't exist or cannot be read.
//
// Example:
//
//	password, err := keyring.GetPassword("github", "myuser")
//	if err != nil {
//	    // Handle retrieval error
//	}
//	if password == "" {
//	    // Password not found
//	}
func (b *IdsecBasicKeyring) GetPassword(serviceName string, username string) (string, error) {
	state, err := b.readStore()
	if err != nil {
		if !errors.Is(err, ErrKeyringUnusable) {
			return "", err
		}
		b.resetUnusableStore(err)
		return "", nil
	}
	entry, ok := state.entries[serviceName][username]
	if !ok {
		return "", nil
	}
	password, err := b.decrypt(state.keys.encKey, serviceName, username, entry)
	if err != nil {
		if !errors.Is(err, ErrKeyringUnusable) {
			return "", err
		}
		b.logUnusable("Ignoring a keyring record that cannot be read", err)
		return "", nil
	}
	return password, nil
}

// DeletePassword deletes a password for a given service and username from the keyring.
//
// DeletePassword removes the specified password entry and rewrites the envelope, whose
// file-level MAC is recomputed over the remaining entries so that the removal is itself
// authenticated. If the keyring file doesn't exist, the service doesn't exist, or the
// username doesn't exist, the function returns nil without error (idempotent behavior).
//
// Stored state that cannot be interpreted is reset and reported as success, since the
// requested entry is gone either way. Genuine I/O failures are returned to the caller.
//
// Parameters:
//   - serviceName: The name of the service to delete password from
//   - username: The username to delete password for
//
// Returns an error if key derivation, file operations or JSON marshaling fails.
//
// Example:
//
//	err := keyring.DeletePassword("github", "myuser")
//	if err != nil {
//	    // Handle deletion error
//	}
func (b *IdsecBasicKeyring) DeletePassword(serviceName string, username string) error {
	state, err := b.readStore()
	if err != nil {
		if !errors.Is(err, ErrKeyringUnusable) {
			return err
		}
		b.resetUnusableStoreForDelete(err)
		return nil
	}
	if _, ok := state.entries[serviceName][username]; !ok {
		return nil
	}
	delete(state.entries[serviceName], username)
	return b.writeStore(state)
}

// ClearAllPasswords removes all stored passwords from the keyring.
//
// ClearAllPasswords deletes the keyring envelope and any leftover version 1 mac sidecar,
// effectively clearing all stored passwords for all services and users. A file that is
// already absent counts as success (idempotent behavior), which also keeps the call safe
// when another process clears the keyring concurrently.
//
// The master secret file is deliberately left in place: once the envelope is removed the
// stored credentials are gone, and the secret on its own decrypts nothing. Removing it is the
// broader action of invalidating every keyring that secret ever protected, including backed up
// or mounted copies. The next write generates a new salt regardless, so the keys protecting
// the new keyring do not match the old one's.
//
// Returns an error if file removal fails for either the keyring envelope or the sidecar.
//
// Example:
//
//	err := keyring.ClearAllPasswords()
//	if err != nil {
//	    // Handle error
//	}
func (b *IdsecBasicKeyring) ClearAllPasswords() error {
	return b.reset()
}

// ListKeys returns the usernames stored under the given serviceName in the
// basic (file-backed) keyring. Secret values are not returned, so no record is opened
// and no master secret is created.
//
// If the keyring file does not exist or the service has no entries, an empty
// slice is returned with a nil error. Stored state that cannot be interpreted is
// treated as a cache miss: the keyring is reset and an empty slice is returned with a
// nil error. Genuine I/O failures are returned to the caller.
func (b *IdsecBasicKeyring) ListKeys(serviceName string) ([]string, error) {
	state, err := b.readStore()
	if err != nil {
		if !errors.Is(err, ErrKeyringUnusable) {
			return nil, err
		}
		b.resetUnusableStore(err)
		return []string{}, nil
	}
	entries, ok := state.entries[serviceName]
	if !ok {
		return nil, nil
	}
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	return keys, nil
}
