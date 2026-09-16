// Copyright CyberArk 2026
// SPDX-License-Identifier: Apache-2.0

package actions

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// credentialNameSuffixes lists the normalized field-name suffixes that identify a field as
// carrying a credential value, and therefore as requiring the `secret:"true"` tag.
//
// Matching is on a suffix of the normalized name rather than a substring because the suffix
// carries the meaning. "provisioner_password" and "k8s_password" end in the secret itself, while
// "password_never_expires", "extra_password_index" and "require_password_every_x_days" merely
// mention it — a substring match would flag all five and force an allowlist large enough that
// nobody would read it. The same distinction keeps "private_key_path" (a filesystem path) out
// while keeping "private_key_contents" (the key material) in.
var credentialNameSuffixes = []string{
	"password",
	"passphrase",
	"secret",
	"secretdata",
	"secretaccesskey",
	"privatekey",
	"privatekeycontents",
	"clientsecret",
	"userpassscript",
	"token",
	"credentials",
	"apikey",
}

// allowedUntaggedNames lists normalized field names that match credentialNameSuffixes but do not
// carry a secret value, so they are exempt from requiring the tag.
//
// Each entry is a deliberate assertion that the field holds a reference, an identifier or a
// pagination cursor rather than credential material. Keep this list short: a growing allowlist is
// a signal that credentialNameSuffixes has become too broad.
var allowedUntaggedNames = map[string]string{
	"continuationtoken":  "pagination cursor, not a credential",
	"nexttoken":          "pagination cursor, not a credential",
	"k8simagepullsecret": "name of an existing Kubernetes pull-secret, not the secret value",
}

// isBoolFieldType reports whether a field's declared type is bool or *bool.
//
// Boolean fields are exempt from the gate because a bool cannot carry credential material: names
// like "allow_specify_secret", "allow_view_fixed_credentials" and "trusted_token" describe a
// permission or an outcome rather than a value to redact. Deriving this from the type keeps them
// out of allowedUntaggedNames, where they would otherwise need an entry each.
//
// Parameters:
// - expr: the field's type expression from the AST
//
// Returns true when the type is bool or a pointer to bool.
func isBoolFieldType(expr ast.Expr) bool {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	ident, ok := expr.(*ast.Ident)
	return ok && ident.Name == "bool"
}

// normalizeFieldName reduces a serialized field name to a comparison form by lowercasing it and
// dropping separators, so that "k8s_password", "K8SPassword" and "k8s-password" all normalize to
// "k8spassword". This lets one suffix list cover the json, mapstructure and flag naming styles
// used across the SDK models.
//
// Parameters:
// - name: the serialized or Go field name
//
// Returns the lowercased, separator-free form of name.
func normalizeFieldName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// isCredentialFieldName reports whether a serialized field name identifies credential material
// according to credentialNameSuffixes.
//
// Parameters:
// - name: the serialized or Go field name
//
// Returns true when the normalized name ends with one of credentialNameSuffixes.
func isCredentialFieldName(name string) bool {
	n := normalizeFieldName(name)
	if n == "" {
		return false
	}
	for _, suffix := range credentialNameSuffixes {
		if strings.HasSuffix(n, suffix) {
			return true
		}
	}
	return false
}

// serializedFieldName resolves the name a struct field is exposed under, mirroring the precedence
// the SDK's consumers use: mapstructure, then flag, then json, then the Go field name.
//
// Parameters:
// - tag: the field's struct tag
// - goName: the Go field name, used when no naming tag is present
//
// Returns the resolved serialized name.
func serializedFieldName(tag reflect.StructTag, goName string) string {
	for _, key := range []string{"mapstructure", "flag", "json"} {
		if v, ok := tag.Lookup(key); ok {
			if name := strings.Split(v, ",")[0]; name != "" && name != "-" {
				return name
			}
		}
	}
	return goName
}

// tagMarksSecret reports whether a struct tag carries `secret:"true"`. It mirrors FieldIsSecret,
// which takes a reflect.StructField and so cannot be used against tags recovered from the AST.
//
// Parameters:
// - tag: the field's struct tag
//
// Returns true when the secret tag is present and parses to boolean true.
func tagMarksSecret(tag reflect.StructTag) bool {
	raw, ok := tag.Lookup(FieldSecretTag)
	if !ok {
		return false
	}
	b, err := strconv.ParseBool(raw)
	return err == nil && b
}

// repoRoot walks up from the working directory to the directory holding go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate go.mod above %s", dir)
		}
		dir = parent
	}
}

// gateScopeDir is the directory the gate enforces the tag in, relative to the repo root.
//
// The tag is a service-model convention: pkg/services holds the request and response models that
// actions are generated from, and those are the structs whose fields reach the CLI and the
// Terraform provider. Types elsewhere under pkg/ (transport helpers, auth plumbing, shared
// identity schemas) are not action models, so requiring the tag there would assert a convention
// that does not apply to them.
const gateScopeDir = "pkg/services"

// TestCredentialFieldsAreTaggedSecret fails if a struct field in pkg/services whose name
// identifies credential material is missing the `secret:"true"` tag.
//
// The tag is what every downstream surface keys off to redact a value: the CLI dry-run preview
// suppresses tagged fields, and the Terraform provider marks the corresponding attribute
// Sensitive so it renders as "(sensitive value)" instead of appearing verbatim in plan output,
// CI logs and pull-request comments. An untagged credential silently opts out of all of that,
// and nothing else in the build notices.
//
// The check reads the source with go/ast rather than reflecting over a registry, so it covers
// every struct in scope including models not yet wired into an action. It needs no network and
// no tenant, so it runs in plain `go test`.
func TestCredentialFieldsAreTaggedSecret(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	pkgDir := filepath.Join(root, gateScopeDir)

	type finding struct {
		file  string
		line  int
		field string
		name  string
	}
	var findings []finding

	err := filepath.Walk(pkgDir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		fset := token.NewFileSet()
		parsed, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return fmt.Errorf("parse %s: %w", path, parseErr)
		}

		ast.Inspect(parsed, func(n ast.Node) bool {
			st, ok := n.(*ast.StructType)
			if !ok || st.Fields == nil {
				return true
			}
			for _, f := range st.Fields.List {
				if f.Tag == nil || len(f.Names) == 0 {
					continue
				}
				if isBoolFieldType(f.Type) {
					continue
				}
				tag := reflect.StructTag(strings.Trim(f.Tag.Value, "`"))

				for _, ident := range f.Names {
					if !ident.IsExported() {
						continue
					}
					name := serializedFieldName(tag, ident.Name)
					if !isCredentialFieldName(name) {
						continue
					}
					if _, allowed := allowedUntaggedNames[normalizeFieldName(name)]; allowed {
						continue
					}
					if tagMarksSecret(tag) {
						continue
					}
					rel, relErr := filepath.Rel(root, path)
					if relErr != nil {
						rel = path
					}
					findings = append(findings, finding{
						file:  rel,
						line:  fset.Position(ident.Pos()).Line,
						field: ident.Name,
						name:  name,
					})
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", pkgDir, err)
	}

	if len(findings) == 0 {
		return
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].file != findings[j].file {
			return findings[i].file < findings[j].file
		}
		return findings[i].line < findings[j].line
	})

	var b strings.Builder
	b.WriteString("credential-named fields in " + gateScopeDir + " are missing `secret:\"true\"`:\n")
	for _, f := range findings {
		b.WriteString(fmt.Sprintf("  %s:%d  %s (serialized as %q)\n", f.file, f.line, f.field, f.name))
	}
	b.WriteString("\nAdd `secret:\"true\"` to each field so downstream surfaces redact it.\n")
	b.WriteString("If a field is not credential material, add its normalized name to allowedUntaggedNames with a justification.")
	t.Error(b.String())
}

// TestIsCredentialFieldName covers the suffix matcher that decides which fields the gate
// requires a tag on, including the near-miss names that a substring match would wrongly flag.
func TestIsCredentialFieldName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		fieldName string
		want      bool
	}{
		{"credential_bare_password", "password", true},
		{"credential_prefixed_password", "provisioner_password", true},
		{"credential_camel_case_password", "K8SPassword", true},
		{"credential_kebab_case_password", "k8s-password", true},
		{"credential_bare_secret", "secret", true},
		{"credential_secret_data", "secret_data", true},
		{"credential_secret_access_key", "secret_access_key", true},
		{"credential_private_key_contents", "private_key_contents", true},
		{"credential_client_secret", "clientSecret", true},
		{"credential_user_pass_script", "user_pass_script", true},
		{"credential_refresh_token", "refresh_token", true},
		{"credential_access_credentials", "accessCredentials", true},
		{"non_credential_password_never_expires", "password_never_expires", false},
		{"non_credential_force_password_change_next", "force_password_change_next", false},
		{"non_credential_extra_password_index", "extra_password_index", false},
		{"non_credential_require_password_every_x_days", "require_password_every_x_days", false},
		{"non_credential_private_key_path", "private_key_path", false},
		{"non_credential_private_key_filepath", "private_key_filepath", false},
		{"non_credential_secret_id", "secret_id", false},
		{"non_credential_secret_name", "secret_name", false},
		{"non_credential_secret_type", "secret_type", false},
		{"non_credential_secret_management", "secret_management", false},
		{"non_credential_secrets_plural", "secrets", false},
		{"non_credential_token_type", "token_type", false},
		{"non_credential_token_lifetime", "token_lifetime", false},
		{"non_credential_access_key_id", "access_key_id", false},
		{"non_credential_unrelated", "display_name", false},
		{"edge_case_empty_string", "", false},
		{"edge_case_separators_only", "__--__", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isCredentialFieldName(tt.fieldName); got != tt.want {
				t.Errorf("isCredentialFieldName(%q) = %v, want %v", tt.fieldName, got, tt.want)
			}
		})
	}
}

// TestSerializedFieldName covers the naming-tag precedence the gate relies on to resolve the
// name a field is exposed under.
func TestSerializedFieldName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		tag    string
		goName string
		want   string
	}{
		{"success_mapstructure_wins", `mapstructure:"a" flag:"b" json:"c"`, "Go", "a"},
		{"success_flag_when_no_mapstructure", `flag:"b" json:"c"`, "Go", "b"},
		{"success_json_when_only_json", `json:"c"`, "Go", "c"},
		{"success_strips_options", `json:"c,omitempty"`, "Go", "c"},
		{"success_falls_back_to_go_name", `desc:"something"`, "Go", "Go"},
		{"success_skips_empty_tag_value", `mapstructure:"" json:"c"`, "Go", "c"},
		{"success_skips_dash_tag_value", `json:"-"`, "Go", "Go"},
		{"edge_case_no_tags", ``, "Go", "Go"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := serializedFieldName(reflect.StructTag(tt.tag), tt.goName)
			if got != tt.want {
				t.Errorf("serializedFieldName(%q, %q) = %q, want %q", tt.tag, tt.goName, got, tt.want)
			}
		})
	}
}

// TestTagMarksSecret covers the AST-side equivalent of FieldIsSecret, including the non-boolean
// tag values that must not be read as true.
func TestTagMarksSecret(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		tag  string
		want bool
	}{
		{"success_secret_true", `secret:"true"`, true},
		{"success_secret_one", `secret:"1"`, true},
		{"success_secret_false", `secret:"false"`, false},
		{"success_secret_empty", `secret:""`, false},
		{"success_secret_junk", `secret:"yesplease"`, false},
		{"edge_case_tag_absent", `flag:"x"`, false},
		{"edge_case_no_tags", ``, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tagMarksSecret(reflect.StructTag(tt.tag)); got != tt.want {
				t.Errorf("tagMarksSecret(%q) = %v, want %v", tt.tag, got, tt.want)
			}
		})
	}
}
