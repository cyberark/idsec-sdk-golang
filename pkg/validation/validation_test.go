package validation

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
)

// TestValidateStruct_acceptsAndRejects walks one fixture per rule shape the
// SDK relies on, in both their valid and invalid forms.
func TestValidateStruct_acceptsAndRejects(t *testing.T) {
	type withRequired struct {
		Name string `validate:"required"`
	}
	type withLen struct {
		ID string `validate:"len=12"`
	}
	type withRegexp struct {
		Code string `validate:"regexp=^[A-Z]{3}$"`
	}
	type withRegexpRequired struct {
		Code string `validate:"required,regexp=^[A-Z]{3}$"`
	}
	type child struct {
		Value string `validate:"required"`
	}
	type withNested struct {
		Child child `validate:"required"`
	}

	cases := []struct {
		name    string
		input   any
		wantErr bool
	}{
		{"nil input", nil, false},
		{"required: set", &withRequired{Name: "ok"}, false},
		{"required: empty", &withRequired{}, true},
		{"len: matches", &withLen{ID: "123456789012"}, false},
		{"len: mismatches", &withLen{ID: "123"}, true},
		{"regexp: matches", &withRegexp{Code: "ABC"}, false},
		{"regexp: mismatches", &withRegexp{Code: "abc"}, true},
		{"regexp: empty passes (compose with required to fail)", &withRegexp{}, false},
		{"regexp+required: empty fails", &withRegexpRequired{}, true},
		{"nested: inner missing", &withNested{}, true},
		{"nested: inner set", &withNested{Child: child{Value: "x"}}, false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			err := ValidateStruct(c.input)
			if (err != nil) != c.wantErr {
				t.Fatalf("wantErr=%v, got err=%v", c.wantErr, err)
			}
		})
	}
}

// TestValidateStruct_messageShape pins the default Error() text contract:
// snake_case field name from the mapstructure tag, rule + parameter,
// quoted offending value, no Go struct prefix.
func TestValidateStruct_messageShape(t *testing.T) {
	type withMin struct {
		SafeName string `mapstructure:"safe_name" validate:"min=5"`
	}
	msg := mustErrorMsg(t, ValidateStruct(&withMin{SafeName: "ad"}))
	for _, want := range []string{"safe_name: min=5", `got "ad"`} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in %q", want, msg)
		}
	}
	if strings.Contains(msg, "withMin") {
		t.Errorf("Go struct name leaked into message: %q", msg)
	}
}

// TestValidateStruct_nestedFieldPath asserts nested violations render with
// the tag-resolved dotted path and no Go struct names.
func TestValidateStruct_nestedFieldPath(t *testing.T) {
	type child struct {
		Account string `mapstructure:"account_id" validate:"required"`
	}
	type parent struct {
		Spec child `mapstructure:"spec"`
	}
	msg := mustErrorMsg(t, ValidateStruct(&parent{}))
	if !strings.Contains(msg, "spec.account_id:") {
		t.Errorf("expected dotted snake_case path, got %q", msg)
	}
	if strings.Contains(msg, "parent") || strings.Contains(msg, "child") {
		t.Errorf("Go struct names leaked: %q", msg)
	}
}

// TestValidateStruct_flatVsMultilineRendering asserts a single failure
// renders flat (one line, no preamble) while multiple failures use the
// "validation failed:" preamble with each field on its own line.
func TestValidateStruct_flatVsMultilineRendering(t *testing.T) {
	type one struct {
		Name string `mapstructure:"name" validate:"required"`
	}
	type two struct {
		Name  string `mapstructure:"name" validate:"required"`
		Email string `mapstructure:"email" validate:"required"`
	}
	if msg := mustErrorMsg(t, ValidateStruct(&one{})); strings.HasPrefix(msg, "validation failed:") {
		t.Errorf("single failure should be flat, got %q", msg)
	}
	if msg := mustErrorMsg(t, ValidateStruct(&two{})); !strings.HasPrefix(msg, "validation failed:") {
		t.Errorf("multiple failures should use the preamble, got %q", msg)
	}
}

// TestValidateStruct_panicSafetyOnMalformedTag asserts a typo'd rule name
// returns an error instead of crashing — the runtime counterpart to the
// CI sweep test in tests/schemas_validation_tags_test.go.
func TestValidateStruct_panicSafetyOnMalformedTag(t *testing.T) {
	type broken struct {
		Field string `validate:"not-a-real-rule"`
	}
	err := ValidateStruct(&broken{Field: "x"})
	if err == nil {
		t.Fatal("expected error from malformed tag")
	}
	if !strings.Contains(err.Error(), "malformed validate tag") {
		t.Errorf("expected 'malformed validate tag' in error, got %q", err.Error())
	}
}

// TestValidateStruct_unwrapsToValidationErrors asserts callers can branch
// programmatically by unwrapping to validator.ValidationErrors via errors.As.
func TestValidateStruct_unwrapsToValidationErrors(t *testing.T) {
	type req struct {
		Name string `validate:"required"`
	}
	err := ValidateStruct(&req{})
	var verrs validator.ValidationErrors
	if !errors.As(err, &verrs) {
		t.Fatalf("error did not unwrap to validator.ValidationErrors: %v", err)
	}
	if len(verrs) == 0 {
		t.Fatal("unwrapped ValidationErrors should not be empty")
	}
}

// TestValidateStruct_squashedEmbedPath asserts a rule on a field inside a
// `mapstructure:",squash"` embed reports the promoted path, not the Go type
// name of the embedded struct — the path consumers resolve against a schema.
func TestValidateStruct_squashedEmbedPath(t *testing.T) {
	type create struct {
		Name string `mapstructure:"name" validate:"required"`
	}
	type update struct {
		create `mapstructure:",squash"`
		ID     string `mapstructure:"id"`
	}
	err := ValidateStruct(&update{})
	msg := mustErrorMsg(t, err)
	if !strings.Contains(msg, "name: required") {
		t.Errorf("expected the promoted field path, got %q", msg)
	}
	if strings.Contains(msg, "create") {
		t.Errorf("squashed embed leaked into message: %q", msg)
	}
	var verr *Error
	if !errors.As(err, &verr) {
		t.Fatalf("error did not unwrap to *Error: %v", err)
	}
	if got := FieldPath(verr.Fields()[0]); got != "name" {
		t.Errorf("FieldPath() = %q, want %q", got, "name")
	}
}

// TestValidateStruct_nonStringValueRendering asserts non-string offending
// values render in their default form; %q would print a rune for an integer
// and a verb error for a pointer.
func TestValidateStruct_nonStringValueRendering(t *testing.T) {
	type req struct {
		Minutes  int     `mapstructure:"minutes" validate:"max=240"`
		Optional *string `mapstructure:"optional" validate:"required_if=Minutes 999"`
	}
	msg := mustErrorMsg(t, ValidateStruct(&req{Minutes: 999}))
	for _, want := range []string{"minutes: max=240 (got 999)", "optional: required_if=Minutes 999 (got <nil>)"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in %q", want, msg)
		}
	}
	if strings.Contains(msg, "%!q") {
		t.Errorf("verb error leaked into message: %q", msg)
	}
}

func mustErrorMsg(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	return err.Error()
}
