package actions

import (
	"reflect"
	"testing"
)

type fieldSecretSample struct {
	Plain       string `flag:"plain"`
	SecretTrue  string `flag:"secret" secret:"true"`
	SecretFalse string `flag:"not-secret" secret:"false"`
	SecretEmpty string `flag:"empty" secret:""`
	SecretJunk  string `flag:"junk" secret:"yesplease"`
	SecretOne   string `flag:"one" secret:"1"`
	UnrelatedTg string `flag:"unrelated" validate:"required"`
}

func TestFieldIsSecret(t *testing.T) {
	tests := []struct {
		field string
		want  bool
	}{
		{"Plain", false},
		{"SecretTrue", true},
		{"SecretFalse", false},
		{"SecretEmpty", false},
		{"SecretJunk", false},
		{"SecretOne", true},
		{"UnrelatedTg", false},
	}

	rt := reflect.TypeOf(fieldSecretSample{})
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			f, ok := rt.FieldByName(tt.field)
			if !ok {
				t.Fatalf("field %s not found", tt.field)
			}
			if got := FieldIsSecret(f); got != tt.want {
				t.Errorf("FieldIsSecret(%s) = %v, want %v", tt.field, got, tt.want)
			}
		})
	}
}
