package models

import (
	"errors"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/validation"
)

// failedRules validates the create and the update model with the given suffix and returns, per model,
// the rule that rejected it ("" when the suffix is accepted).
func failedRules(t *testing.T, suffix string) map[string]string {
	t.Helper()
	got := map[string]string{}
	for name, input := range map[string]interface{}{
		"create": &IdsecIdentityCreateTenantSuffix{ReplaceDomain: suffix},
		"update": &IdsecIdentityUpdateTenantSuffix{ID: "old.example.com", ReplaceDomain: suffix},
	} {
		err := validation.ValidateStruct(input)
		if err == nil {
			got[name] = ""
			continue
		}
		var verr *validation.Error
		if !errors.As(err, &verr) || len(verr.Fields()) != 1 || validation.FieldPath(verr.Fields()[0]) != "suffix" {
			t.Fatalf("%s %q: want exactly one failure on suffix, got %v", name, suffix, err)
		}
		got[name] = verr.Fields()[0].Tag()
	}
	return got
}

func TestTenantSuffixAcceptsWhatTheServerAccepts(t *testing.T) {
	// .NET's \w is Unicode-aware, so the server accepts non-ASCII letters and combining marks.
	for _, suffix := range []string{
		"example.com",
		"a_b.example.com",
		"o'neil+x.example.com",
		"Mixed-Case.Example.com",
		"m\u00fcller.example.com",  // precomposed u-umlaut, category L
		"cafe\u0301.example.com",   // e plus a combining acute accent, category Mn
		"\u4f8b\u3048.example.com", // CJK and kana letters, category L
		"123.example.com",
	} {
		for model, rule := range failedRules(t, suffix) {
			if rule != "" {
				t.Errorf("%s %q: rejected by %q, want accepted", model, suffix, rule)
			}
		}
	}
}

func TestTenantSuffixRejectsWhatTheServerRejects(t *testing.T) {
	for suffix, want := range map[string]string{
		"/x.example.com":      "regexp",
		"tfacc x.example.com": "regexp",
		"x@example.com":       "regexp",
		"a,b.example.com":     "regexp",
		" pad.example.com":    "regexp", // the server trims, so a padded suffix would read back as a diff
		"pad.example.com\t":   "regexp",
		"   ":                 "regexp",
		"":                    "required",
	} {
		for model, rule := range failedRules(t, suffix) {
			if rule != want {
				t.Errorf("%s %q: rejected by %q, want %q", model, suffix, rule, want)
			}
		}
	}
}
