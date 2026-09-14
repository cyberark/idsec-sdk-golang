package actions

import (
	"reflect"
	"strconv"
)

// FieldSecretTag is the struct-tag name used on SDK request struct fields to
// mark a field as carrying a secret value (a password, private key, token,
// client secret, etc.). Surfaces that render request arguments (such as the
// CLI dry-run preview) use it to redact the value instead of printing it.
//
// The tag value is a boolean: only `secret:"true"` marks the field as secret.
// An absent tag, `secret:"false"`, an empty value, or any non-boolean value
// leave the field unmarked.
const FieldSecretTag = "secret"

// FieldIsSecret reports whether a reflect.StructField is marked secret via
// `secret:"true"`. It returns false when the tag is absent or its value does
// not parse to boolean true, so callers can use a simple
// `if actions.FieldIsSecret(f) { ... }` check.
func FieldIsSecret(field reflect.StructField) bool {
	raw, ok := field.Tag.Lookup(FieldSecretTag)
	if !ok {
		return false
	}
	b, err := strconv.ParseBool(raw)
	return err == nil && b
}
