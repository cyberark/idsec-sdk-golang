package identity

import (
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

func signedTestToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte("test-key"))
	if err != nil {
		t.Fatalf("failed to sign test token: %v", err)
	}
	return signed
}

func TestTokenExpirationUsesAbsoluteExp(t *testing.T) {
	expectedExpiration := time.Now().Add(5 * time.Minute).Truncate(time.Second)
	rawToken := signedTestToken(t, jwt.MapClaims{
		"iat": time.Now().Add(-time.Hour).Unix(),
		"exp": expectedExpiration.Unix(),
	})

	expiration, err := tokenExpiration(rawToken)
	if err != nil {
		t.Fatalf("tokenExpiration returned an error: %v", err)
	}
	if !time.Time(expiration).Equal(expectedExpiration) {
		t.Fatalf("expected absolute expiration %v, got %v", expectedExpiration, expiration)
	}
}

func TestTokenExpirationRejectsInvalidClaims(t *testing.T) {
	tests := []struct {
		name       string
		rawToken   func(*testing.T) string
		errorMatch string
	}{
		{
			name:       "malformed token",
			rawToken:   func(*testing.T) string { return "not-a-jwt" },
			errorMatch: "failed to parse identity token",
		},
		{
			name: "missing exp",
			rawToken: func(t *testing.T) string {
				return signedTestToken(t, jwt.MapClaims{"sub": "test-user"})
			},
			errorMatch: "missing required exp claim",
		},
		{
			name: "invalid exp type",
			rawToken: func(t *testing.T) string {
				return signedTestToken(t, jwt.MapClaims{"exp": "tomorrow"})
			},
			errorMatch: "invalid exp claim",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tokenExpiration(tt.rawToken(t))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.errorMatch) {
				t.Fatalf("expected error containing %q, got %q", tt.errorMatch, err)
			}
		})
	}
}

func TestRequiredStringClaimRejectsMissingOrWrongType(t *testing.T) {
	for _, claims := range []jwt.MapClaims{
		{},
		{"tenant_id": 123},
		{"tenant_id": ""},
	} {
		if _, err := requiredStringClaim(claims, "tenant_id"); err == nil {
			t.Fatalf("expected invalid tenant_id claim %#v to return an error", claims["tenant_id"])
		}
	}
}
