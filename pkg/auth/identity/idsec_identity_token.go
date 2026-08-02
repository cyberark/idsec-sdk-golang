package identity

import (
	"errors"
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

func parseUnverifiedTokenClaims(rawToken string) (jwt.MapClaims, error) {
	parsedToken, _, err := new(jwt.Parser).ParseUnverified(rawToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse identity token: %w", err)
	}
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("identity token contains unsupported claims")
	}
	return claims, nil
}

func requiredStringClaim(claims jwt.MapClaims, name string) (string, error) {
	value, ok := claims[name].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("identity token is missing required string claim %q", name)
	}
	return value, nil
}

func tokenExpiration(rawToken string) (commonmodels.IdsecRFC3339Time, error) {
	claims, err := parseUnverifiedTokenClaims(rawToken)
	if err != nil {
		return commonmodels.IdsecRFC3339Time{}, err
	}
	expiration, err := claims.GetExpirationTime()
	if err != nil {
		return commonmodels.IdsecRFC3339Time{}, fmt.Errorf("identity token has invalid exp claim: %w", err)
	}
	if expiration == nil {
		return commonmodels.IdsecRFC3339Time{}, errors.New("identity token is missing required exp claim")
	}
	return commonmodels.IdsecRFC3339Time(expiration.Time), nil
}

func tokenLifetime(rawToken string, expiration commonmodels.IdsecRFC3339Time) int {
	claims, err := parseUnverifiedTokenClaims(rawToken)
	if err == nil {
		issuedAt, issuedAtErr := claims.GetIssuedAt()
		if issuedAtErr == nil && issuedAt != nil {
			lifetime := time.Time(expiration).Sub(issuedAt.Time)
			if lifetime > 0 {
				return int(lifetime.Seconds())
			}
		}
	}
	remaining := time.Until(time.Time(expiration))
	if remaining <= 0 {
		return 0
	}
	return int(remaining.Seconds())
}
