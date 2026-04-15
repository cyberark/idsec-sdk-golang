package common

import (
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

// SessionBase provides common session management functionality.
type SessionBase struct {
	SessionState
	CacheManager *CacheManager
	Logger       *common.IdsecLogger
}

// NewSessionBase creates a new SessionBase instance.
func NewSessionBase(logger *common.IdsecLogger, cacheConfig *CacheConfig) *SessionBase {
	return &SessionBase{
		SessionState: SessionState{
			LoadedFromCache: false,
		},
		CacheManager: NewCacheManager(cacheConfig),
		Logger:       logger,
	}
}

// IsTokenValid checks if the current session token is valid (not expired).
func (sb *SessionBase) IsTokenValid() bool {
	return sb.CacheManager.ValidateCachedToken(sb.SessionExp)
}

// SetSessionExpiration sets the session expiration time.
func (sb *SessionBase) SetSessionExpiration(exp commonmodels.IdsecRFC3339Time) {
	sb.SessionExp = exp
}

// SetLoadedFromCache marks the session as loaded from cache.
func (sb *SessionBase) SetLoadedFromCache(loaded bool) {
	sb.LoadedFromCache = loaded
}

// CalculateExpirationTime calculates expiration time from a lifetime in seconds.
func CalculateExpirationTime(lifetimeSeconds int) commonmodels.IdsecRFC3339Time {
	if lifetimeSeconds == 0 {
		lifetimeSeconds = DefaultTokenLifetimeSeconds
	}
	return commonmodels.IdsecRFC3339Time(time.Now().Add(time.Duration(lifetimeSeconds) * time.Second))
}
