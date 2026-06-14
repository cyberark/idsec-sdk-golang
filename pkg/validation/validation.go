// Package validation provides struct validation using go-playground/validator.
package validation

import (
	"fmt"
	"github.com/go-playground/validator/v10"
	"reflect"
	"regexp"
	"strings"
	"sync"
	_ "time/tzdata"
)

var defaultValidator *validator.Validate

func init() {
	defaultValidator = validator.New()
	defaultValidator.RegisterTagNameFunc(externalFieldName)
	for _, tag := range []string{"regexp", "pattern"} {
		if err := defaultValidator.RegisterValidation(tag, validateRegexp); err != nil {
			panic(fmt.Errorf("validation: failed to register %q rule: %w", tag, err))
		}
	}
}

// DefaultValidator returns the package-wide *validator.Validate instance.
func DefaultValidator() *validator.Validate { return defaultValidator }

// ValidateStruct validates s (and any nested structs) against its
// `validate` struct tags. Zero-value fields that declare a `default:"..."`
// tag are filled on an internal copy so validators see declared defaults
// rather than empty values; the original struct is never mutated.
// It returns nil if s is nil or valid, otherwise a *Error.
func ValidateStruct(s interface{}) (err error) {
	if s == nil {
		return nil
	}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("validation: malformed validate tag in %T — %v", s, r)
		}
	}()
	target := shallowCopyPtr(s)
	ApplyDefaults(target)
	raw := defaultValidator.Struct(target)
	if raw == nil {
		return nil
	}
	if fields, ok := raw.(validator.ValidationErrors); ok {
		return &Error{fields: fields}
	}
	return raw
}

// Error is returned by ValidateStruct when one or more validation rules fail.
type Error struct {
	fields validator.ValidationErrors
}

// Error returns a multi-field, snake-case-friendly summary.
func (e *Error) Error() string {
	switch len(e.fields) {
	case 0:
		return ""
	case 1:
		return formatField(e.fields[0])
	}
	lines := make([]string, 0, len(e.fields))
	for _, f := range e.fields {
		lines = append(lines, formatField(f))
	}
	return "validation failed:\n  " + strings.Join(lines, "\n  ")
}

// Unwrap exposes the underlying validator.ValidationErrors so callers can
// use errors.As to inspect individual failures.
func (e *Error) Unwrap() error { return e.fields }

// Fields returns the underlying validator.ValidationErrors slice.
func (e *Error) Fields() validator.ValidationErrors { return e.fields }

// FieldPath returns the dotted, tag-resolved path of the offending field
// with the Go struct type prefix that go-playground prepends in
// Namespace() stripped.
func FieldPath(e validator.FieldError) string {
	ns := e.Namespace()
	if i := strings.IndexByte(ns, '.'); i >= 0 {
		return ns[i+1:]
	}
	return ns
}

// externalFieldName resolves the user-facing name of a struct field for
// validation messages.
func externalFieldName(fld reflect.StructField) string {
	for _, tag := range []string{"mapstructure", "json"} {
		raw := fld.Tag.Get(tag)
		if raw == "" {
			continue
		}
		if name := strings.SplitN(raw, ",", 2)[0]; name != "" && name != "-" {
			return name
		}
	}
	return fld.Name
}

// formatField renders one validation failure as a single line in the
// default, factual style. UI-facing surfaces should build their own
// renderer on top of FieldPath / validator.FieldError instead.
func formatField(e validator.FieldError) string {
	rule := e.Tag()
	if p := e.Param(); p != "" {
		rule += "=" + p
	}
	if v := e.Value(); v != nil && v != "" {
		rule += fmt.Sprintf(" (got %q)", v)
	}
	return FieldPath(e) + ": " + rule
}

// --- regexp / pattern custom rule -------------------------------------

// shallowCopyPtr returns a pointer to a shallow copy of the struct behind s.
// If s is not a pointer to a struct, it is returned as-is.
func shallowCopyPtr(s interface{}) interface{} {
	v := reflect.ValueOf(s)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return s
	}
	elem := v.Elem()
	if elem.Kind() != reflect.Struct {
		return s
	}
	cp := reflect.New(elem.Type())
	cp.Elem().Set(elem)
	return cp.Interface()
}

// regexpCache memoises compiled regexes by pattern so each validation
// call after the first hits a precompiled *regexp.Regexp. Patterns come
// from struct tags resolved at build time, so the cache is bounded by
// the number of distinct regexp= patterns in the SDK.
var regexpCache sync.Map

// validateRegexp implements `validate:"regexp=<pattern>"`.
// Empty values are accepted by design — compose with
// `required` to fail emptiness.
func validateRegexp(fl validator.FieldLevel) bool {
	pattern := fl.Param()
	if pattern == "" {
		return true
	}
	value := fl.Field().String()
	if value == "" {
		return true
	}
	if cached, ok := regexpCache.Load(pattern); ok {
		return cached.(*regexp.Regexp).MatchString(value)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	regexpCache.Store(pattern, re)
	return re.MatchString(value)
}
