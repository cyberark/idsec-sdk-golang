package common

import (
	"regexp"
	"strings"
)

const redactedPlaceholder = "[REDACTED]"

// sensitiveFieldNames lists JSON/struct field names whose values must be
// redacted before writing to file logs. Matching is case-insensitive.
var sensitiveFieldNames = []string{
	"password",
	"secret",
	"token",
	"refreshtoken",
	"refresh_token",
	"accesstoken",
	"access_token",
	"privatekeycontents",
	"private_key_contents",
	"privatekey",
	"private_key",
	"awssecretaccesskey",
	"aws_secret_access_key",
	"awssessiontoken",
	"aws_session_token",
	"iamaccesskeyid",
	"iam_access_key_id",
	"iamsecretaccesskey",
	"iam_secret_access_key",
	"atlasprivatekey",
	"atlas_private_key",
	"credentials",
	"accesscredentials",
	"access_credentials",
	"provisionerpassword",
	"provisioner_password",
	"authorization",
	"cookie",
	"session_token",
	"client_secret",
	"clientsecret",
}

type fieldSanitizer struct {
	jsonPattern   *regexp.Regexp
	structPattern *regexp.Regexp
	fieldName     string
}

// sensitiveValuePatterns matches secrets by their content shape, regardless of
// field name. Patterns are inspired by gitleaks / trufflehog rules.
var sensitiveValuePatterns = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{"aws_access_key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"pem_private_key", regexp.MustCompile(`-----BEGIN\s[\w\s]*PRIVATE KEY-----[\s\S]*?-----END\s[\w\s]*PRIVATE KEY-----`)},
	{"bearer_token", regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9_\-.~+/]{20,}=*`)},
	{"basic_auth", regexp.MustCompile(`(?i)\bBasic\s+[A-Za-z0-9+/]{20,}={0,2}`)},
	{"generic_hex_secret", regexp.MustCompile(`(?i)(?:secret|token|key|password|passwd|pwd)[:= ]+[0-9a-f]{32,}`)},
}

var fieldSanitizers []fieldSanitizer

// init compiles sanitizer patterns once at startup.
func init() {
	fieldSanitizers = buildFieldSanitizers(sensitiveFieldNames)
}

// buildFieldSanitizers builds regex-based sanitizers for all sensitive fields.
func buildFieldSanitizers(fields []string) []fieldSanitizer {
	sanitizers := make([]fieldSanitizer, 0, len(fields))
	for _, name := range fields {
		sanitizers = append(sanitizers, fieldSanitizer{
			fieldName:     name,
			jsonPattern:   buildJSONPattern(name),
			structPattern: buildStructPattern(name),
		})
	}
	return sanitizers
}

// buildJSONPattern matches `"fieldName" : "anyValue"` with case-insensitive
// field name and tolerant whitespace around the colon.
func buildJSONPattern(fieldName string) *regexp.Regexp {
	return regexp.MustCompile(
		`(?i)"` + regexp.QuoteMeta(fieldName) + `"\s*:\s*"[^"]*"`,
	)
}

// buildStructPattern matches Go struct dump fields like `FieldName:value`
// where value runs until the next whitespace, closing brace, or bracket.
func buildStructPattern(fieldName string) *regexp.Regexp {
	return regexp.MustCompile(
		`(?i)` + regexp.QuoteMeta(fieldName) + `:[^\s\}\]]+`,
	)
}

// sanitizeMessage redacts sensitive data from a log message. It handles
// field-name-based redaction (JSON and struct dumps) and value-based
// pattern matching (JWTs, AWS keys, PEM blocks, Bearer/Basic tokens).
func sanitizeMessage(message string) string {
	for _, s := range fieldSanitizers {
		message = s.jsonPattern.ReplaceAllStringFunc(message, func(match string) string {
			return replaceJSONValue(match, s.fieldName)
		})
		message = s.structPattern.ReplaceAllStringFunc(message, func(match string) string {
			return replaceStructValue(match, s.fieldName)
		})
	}
	for _, vp := range sensitiveValuePatterns {
		message = vp.pattern.ReplaceAllString(message, redactedPlaceholder)
	}
	return message
}

// replaceJSONValue rebuilds a JSON key-value pair with the value redacted.
// Input example: `"password" : "s3cret"` -> `"password":"[REDACTED]"`
func replaceJSONValue(match, fieldName string) string {
	idx := strings.Index(strings.ToLower(match), strings.ToLower(fieldName))
	if idx == -1 {
		return match
	}
	originalKey := match[idx : idx+len(fieldName)]
	return `"` + originalKey + `":"` + redactedPlaceholder + `"`
}

// replaceStructValue rebuilds a struct field with the value redacted.
// Input example: `Password:s3cret` -> `Password:[REDACTED]`
func replaceStructValue(match, _ string) string {
	colonIdx := strings.Index(match, ":")
	if colonIdx == -1 {
		return match
	}
	originalKey := match[:colonIdx]
	return originalKey + ":" + redactedPlaceholder
}
