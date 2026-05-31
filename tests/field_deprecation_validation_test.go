package tests

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	_ "github.com/cyberark/idsec-sdk-golang/pkg"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
)

// tagBaseName strips the comma-separated options portion off a struct-tag
// value, returning just the field-identifier prefix.
func tagBaseName(v string) string {
	if i := strings.IndexByte(v, ','); i >= 0 {
		return v[:i]
	}
	return v
}

// TestActionSchemasDeprecationReplacements is a single SDK-wide gate that
// walks every registered service, collects every action schema and asserts
// that every `deprecated:"<replacement>,..."` tag points at a real sibling
// field in the SAME enclosing struct.
func TestActionSchemasDeprecationReplacements(t *testing.T) {
	allConfigs := services.AllServiceConfigs()
	if len(allConfigs) == 0 {
		t.Skip("No service configurations registered")
	}

	sort.Slice(allConfigs, func(i, j int) bool {
		return allConfigs[i].ServiceName < allConfigs[j].ServiceName
	})

	for _, config := range allConfigs {
		config := config
		t.Run(config.ServiceName, func(t *testing.T) {
			if len(config.ActionSchemas) == 0 {
				t.Skip("No action schemas defined for this service")
				return
			}

			actionNames := make([]string, 0, len(config.ActionSchemas))
			for name := range config.ActionSchemas {
				actionNames = append(actionNames, name)
			}
			sort.Strings(actionNames)

			for _, actionName := range actionNames {
				rawSchema := config.ActionSchemas[actionName]
				t.Run(actionName, func(t *testing.T) {
					schema, _ := actions.UnwrapSchema(rawSchema)
					if schema == nil {
						return
					}
					if errs := validateDeprecationReplacements(reflect.TypeOf(schema)); len(errs) > 0 {
						for _, e := range errs {
							t.Errorf("%s: %v", actionName, e)
						}
					}
				})
			}
		})
	}
}

// validateDeprecationReplacements walks and returns one error per
// `deprecated:"<replacement>,..."` tag whose <replacement> does not name a
// sibling field in the same struct. A field is a valid replacement target
// when its `flag:` or `mapstructure:` tag value equals <replacement>.
func validateDeprecationReplacements(t reflect.Type) []error {
	if t == nil {
		return nil
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil
	}
	errs := []error{}
	validateDeprecationStruct(t, &errs, map[reflect.Type]struct{}{})
	return errs
}

// validateDeprecationStruct does the recursive work for
// validateDeprecationReplacements. The seen map breaks cycles in
// self-referential struct types.
func validateDeprecationStruct(t reflect.Type, errs *[]error, seen map[reflect.Type]struct{}) {
	if _, ok := seen[t]; ok {
		return
	}
	seen[t] = struct{}{}

	siblings := siblingTagNames(t)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if dep := actions.FieldDeprecation(f); dep != nil && dep.Replacement != "" {
			if !siblings[dep.Replacement] {
				*errs = append(*errs, fmt.Errorf(
					"%s.%s: deprecated replacement %q does not match any sibling field's `flag:` or `mapstructure:` tag",
					t.Name(), f.Name, dep.Replacement,
				))
			}
		}
		descendInto(f.Type, errs, seen)
	}
}

// descendInto recurses into struct, pointer-to-struct, and struct-typed
// slice / array / map element types so nested deprecated tags are validated
// against their own enclosing struct's siblings.
func descendInto(t reflect.Type, errs *[]error, seen map[reflect.Type]struct{}) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		validateDeprecationStruct(t, errs, seen)
	case reflect.Slice, reflect.Array, reflect.Map:
		descendInto(t.Elem(), errs, seen)
	}
}

// siblingTagNames returns the set of `flag:` and `mapstructure:` tag values
// found on it's fields.
func siblingTagNames(t reflect.Type) map[string]bool {
	names := make(map[string]bool, t.NumField()*2)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if v := f.Tag.Get("flag"); v != "" {
			if base := tagBaseName(v); base != "" {
				names[base] = true
			}
		}
		if v := f.Tag.Get("mapstructure"); v != "" {
			if base := tagBaseName(v); base != "" {
				names[base] = true
			}
		}
	}
	return names
}
