package models

import (
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/validation"
)

// TestIdsecPolicyInfraTimeCondition_HoursFormat pins the infrastructure (VM/DB)
// contract: the access window accepts 4-digit "HH:MM" hours and rejects the
// 6-digit "HH:MM:SS" format that the backend explicitly rejects with "You must
// supply the hours timeframe in a 4 digits format".
func TestIdsecPolicyInfraTimeCondition_HoursFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		fromHour  string
		toHour    string
		expectErr bool
	}{
		{"4_digit_accepted", "09:00", "17:00", false},
		{"6_digit_rejected", "09:00:00", "17:00:00", true},
		{"empty_accepted", "", "", false},
		{"mixed_one_6_digit_rejected", "09:00", "17:00:00", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			conditions := IdsecPolicyInfraCommonConditions{
				AccessWindow: IdsecPolicyInfraTimeCondition{
					DaysOfTheWeek: []int{1, 2, 3, 4, 5},
					FromHour:      tt.fromHour,
					ToHour:        tt.toHour,
				},
				MaxSessionDuration: 4,
			}

			err := validation.ValidateStruct(&conditions)
			if tt.expectErr && err == nil {
				t.Fatalf("expected validation error for from_hour=%q to_hour=%q, got nil", tt.fromHour, tt.toHour)
			}
			if !tt.expectErr && err != nil {
				t.Fatalf("expected no validation error for from_hour=%q to_hour=%q, got: %v", tt.fromHour, tt.toHour, err)
			}
		})
	}
}
