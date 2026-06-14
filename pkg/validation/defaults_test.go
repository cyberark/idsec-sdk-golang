package validation

import (
	"reflect"
	"testing"
)

func TestApplyDefaults(t *testing.T) {
	type nested struct {
		Inner string `default:"inner-default"`
	}
	type sample struct {
		Str        string   `default:"GMT"`
		StrSet     string   `default:"GMT"`
		Bool       bool     `default:"true"`
		Int        int      `default:"5"`
		Float      float64  `default:"1.5"`
		Ints       []int    `default:"0,1,2,3,4,5,6"`
		Strs       []string `default:"a,b,c"`
		NoTag      string
		Nested     nested
		NestedPtr  *nested
		unexported string //nolint:unused
	}

	s := &sample{StrSet: "Asia/Jerusalem", NestedPtr: &nested{}}
	ApplyDefaults(s)

	if s.Str != "GMT" {
		t.Errorf("Str: want GMT, got %q", s.Str)
	}
	if s.StrSet != "Asia/Jerusalem" {
		t.Errorf("StrSet: caller value overwritten, got %q", s.StrSet)
	}
	if !s.Bool {
		t.Error("Bool: want true")
	}
	if s.Int != 5 {
		t.Errorf("Int: want 5, got %d", s.Int)
	}
	if s.Float != 1.5 {
		t.Errorf("Float: want 1.5, got %v", s.Float)
	}
	if !reflect.DeepEqual(s.Ints, []int{0, 1, 2, 3, 4, 5, 6}) {
		t.Errorf("Ints: got %v", s.Ints)
	}
	if !reflect.DeepEqual(s.Strs, []string{"a", "b", "c"}) {
		t.Errorf("Strs: got %v", s.Strs)
	}
	if s.NoTag != "" {
		t.Errorf("NoTag: want empty, got %q", s.NoTag)
	}
	if s.Nested.Inner != "inner-default" {
		t.Errorf("Nested.Inner: want inner-default, got %q", s.Nested.Inner)
	}
	if s.NestedPtr.Inner != "inner-default" {
		t.Errorf("NestedPtr.Inner: want inner-default, got %q", s.NestedPtr.Inner)
	}
}

func TestApplyDefaultsIgnoresNonStructPointers(t *testing.T) {
	ApplyDefaults(nil)
	x := 5
	ApplyDefaults(&x)
	ApplyDefaults(sample{})
}

type sample struct{}

func TestApplyDefaultsViaValidateStruct(t *testing.T) {
	type withDefault struct {
		Zone string `validate:"required" default:"GMT"`
	}
	if err := ValidateStruct(&withDefault{}); err != nil {
		t.Errorf("empty Zone should pick up GMT default and pass required, got: %v", err)
	}

	type withoutDefault struct {
		Zone string `validate:"required"`
	}
	if err := ValidateStruct(&withoutDefault{}); err == nil {
		t.Error("empty Zone with no default should fail required")
	}
}

func TestValidateStructDoesNotMutateOriginal(t *testing.T) {
	type cfg struct {
		Zone string `validate:"required" default:"GMT"`
	}
	original := &cfg{}
	_ = ValidateStruct(original)
	if original.Zone != "" {
		t.Errorf("ValidateStruct mutated original: Zone = %q, want empty", original.Zone)
	}
}

func TestValidateStructDoesNotMutateNestedPointer(t *testing.T) {
	type inner struct {
		Val string `validate:"required" default:"filled"`
	}
	type outer struct {
		Ptr *inner
	}
	nested := &inner{}
	original := &outer{Ptr: nested}
	_ = ValidateStruct(original)
	if nested.Val != "" {
		t.Errorf("ValidateStruct mutated nested pointer target: Val = %q, want empty", nested.Val)
	}
}
