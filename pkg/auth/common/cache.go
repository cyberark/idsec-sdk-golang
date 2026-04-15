package common

import (
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

// CacheManager provides common cache management utilities.
type CacheManager struct {
	config *CacheConfig
}

// NewCacheManager creates a new CacheManager instance.
func NewCacheManager(config *CacheConfig) *CacheManager {
	return &CacheManager{
		config: config,
	}
}

// IsTokenExpired checks if a token expiration time has passed.
func (cm *CacheManager) IsTokenExpired(exp commonmodels.IdsecRFC3339Time) bool {
	return !time.Time(exp).After(time.Now())
}

// ShouldUseCache determines if cache should be used based on configuration and force flag.
func (cm *CacheManager) ShouldUseCache(force bool) bool {
	return cm.config.CacheAuthentication && !force
}

// ShouldLoadFromCache determines if cache should be loaded based on configuration, force flag, and current state.
func (cm *CacheManager) ShouldLoadFromCache(force bool, loadedFromCache bool) bool {
	if !cm.ShouldUseCache(force) {
		return false
	}
	// If already loaded from cache, we should check expiration
	// If not loaded, we should try loading
	return true
}

// ValidateCachedToken checks if a cached token is valid (not expired).
func (cm *CacheManager) ValidateCachedToken(exp commonmodels.IdsecRFC3339Time) bool {
	return !cm.IsTokenExpired(exp)
}

// LoadTokenFromCache is a generic helper that loads a token using the provided loader.
func (cm *CacheManager) LoadTokenFromCache(loader TokenLoader, profile *models.IdsecProfile, cacheKey string) (bool, error) {
	if cm.config.Keyring == nil || profile == nil {
		return false, nil
	}
	return loader.LoadToken(profile, cacheKey)
}

// SaveTokenToCache is a generic helper that saves a token using the provided saver.
func (cm *CacheManager) SaveTokenToCache(saver TokenSaver, profile *models.IdsecProfile, cacheKey string) error {
	if cm.config.Keyring == nil || profile == nil {
		return nil
	}
	return saver.SaveToken(profile, cacheKey)
}
