//go:build e2e

// This file is test support for E2E-tagged builds. The e2e build constraint
// excludes it from normal production builds and released SDK binaries.

package auth

import (
	"errors"
	"time"

	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

// SetTokenExpirationForE2E replaces the published token with an immutable copy
// whose expiration can exercise proactive refresh without waiting for a live
// token to expire. This helper is available only in E2E-tagged builds.
func (a *IdsecAuthBase) SetTokenExpirationForE2E(expiration time.Time) error {
	token, profile, authProfile := a.snapshotState()
	if token == nil {
		return errors.New("cannot set expiration without a published token")
	}

	nearExpiry := *token
	nearExpiry.ExpiresIn = commonmodels.IdsecRFC3339Time(expiration)
	a.setState(&nearExpiry, profile, authProfile)
	return nil
}
