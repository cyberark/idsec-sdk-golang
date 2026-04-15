package common

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/keyring"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

// TokenLoader defines the interface for loading tokens from cache.
type TokenLoader interface {
	// LoadToken loads a token from cache and returns whether it was successfully loaded.
	// The implementation should handle setting session token, expiration, and updating the session.
	LoadToken(profile interface{}, cacheKey string) (bool, error)
}

// TokenSaver defines the interface for saving tokens to cache.
type TokenSaver interface {
	// SaveToken saves a token to cache.
	SaveToken(profile interface{}, cacheKey string) error
}

// SessionState represents common session state fields.
type SessionState struct {
	SessionExp      commonmodels.IdsecRFC3339Time
	LoadedFromCache bool
}

// CacheConfig represents cache configuration.
type CacheConfig struct {
	Keyring             keyring.IdsecKeyringInterface
	CacheAuthentication bool
	Logger              *common.IdsecLogger
}
