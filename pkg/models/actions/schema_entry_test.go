package actions

import "testing"

type fakeSchema struct{}

func TestUnwrapSchema(t *testing.T) {
	raw := &fakeSchema{}
	dep := Deprecation{Message: "merged", Replacement: "new"}
	wrapped := Deprecated(raw, dep)
	wrappedNil := DeprecatedNil(dep)
	emptyWrapper := Deprecated(raw, Deprecation{})

	tests := []struct {
		name       string
		value      interface{}
		wantSchema interface{}
		wantDep    *Deprecation
	}{
		{"raw_pointer_returns_self_and_nil_dep", raw, raw, nil},
		{"raw_nil_returns_nil_and_nil_dep", nil, nil, nil},
		{"wrapped_value_returns_inner_schema_and_dep", wrapped, raw, &dep},
		{"wrapped_pointer_returns_inner_schema_and_dep", &wrapped, raw, &dep},
		{"nil_wrapped_pointer_returns_nil_nil", (*SchemaEntry)(nil), nil, nil},
		{"deprecated_nil_returns_nil_schema_and_dep", wrappedNil, nil, &dep},
		{"empty_wrapper_still_returns_non_nil_dep", emptyWrapper, raw, &Deprecation{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotSchema, gotDep := UnwrapSchema(tt.value)

			if gotSchema != tt.wantSchema {
				t.Errorf("schema: want %v, got %v", tt.wantSchema, gotSchema)
			}
			switch {
			case tt.wantDep == nil && gotDep != nil:
				t.Errorf("dep: want nil, got %+v", *gotDep)
			case tt.wantDep != nil && gotDep == nil:
				t.Errorf("dep: want %+v, got nil", *tt.wantDep)
			case tt.wantDep != nil && *tt.wantDep != *gotDep:
				t.Errorf("dep: want %+v, got %+v", *tt.wantDep, *gotDep)
			}
		})
	}
}

func TestDeprecatedConstructors(t *testing.T) {
	raw := &fakeSchema{}
	dep := Deprecation{Replacement: "new"}

	if entry := Deprecated(raw, dep); entry.Schema != raw || entry.Deprecation != dep {
		t.Errorf("Deprecated: want schema=%v dep=%+v, got schema=%v dep=%+v", raw, dep, entry.Schema, entry.Deprecation)
	}
	if entry := DeprecatedNil(dep); entry.Schema != nil || entry.Deprecation != dep {
		t.Errorf("DeprecatedNil: want schema=nil dep=%+v, got schema=%v dep=%+v", dep, entry.Schema, entry.Deprecation)
	}
}
