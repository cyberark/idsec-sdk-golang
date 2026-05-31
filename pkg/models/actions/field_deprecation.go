package actions

import (
	"reflect"
	"strings"
)

// FieldDeprecatedTag is the single struct-tag name used on SDK request struct
// fields to declare flag/attribute deprecation. The tag value carries both
// the replacement and the custom message, separated by the first comma in the
// value: "<replacement>,<message>". Replacement always comes first.
//
// Value formats:
//
//	deprecated:""                          // marker only, no replacement, no message
//	deprecated:"secret_id"                 // replacement only
//	deprecated:",plain-text is going away" // message only (note leading comma)
//	deprecated:"secret_id,plain-text is going away" // replacement + message
//
// Only the FIRST comma is treated as the separator, so messages may contain
// additional commas freely.
const FieldDeprecatedTag = "deprecated"

// FieldDeprecation reads the deprecation tag from a reflect.StructField and
// returns a non-nil *Deprecation when the field carries the `deprecated` tag.
// Returns nil when the tag is absent so callers can use a simple
// `if dep := actions.FieldDeprecation(f); dep != nil { ... }` check.
//
// The tag value is split at the first comma: the prefix becomes Replacement
// and the suffix becomes Message. A tag with no comma is interpreted as
// "replacement only"; an empty tag value is a bare deprecation marker.
func FieldDeprecation(field reflect.StructField) *Deprecation {
	raw, hasTag := field.Tag.Lookup(FieldDeprecatedTag)
	if !hasTag {
		return nil
	}
	var replacement, message string
	if idx := strings.Index(raw, ","); idx >= 0 {
		replacement = raw[:idx]
		message = raw[idx+1:]
	} else {
		replacement = raw
	}
	return &Deprecation{Message: message, Replacement: replacement}
}
