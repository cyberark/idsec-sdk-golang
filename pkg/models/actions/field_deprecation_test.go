package actions

import (
	"reflect"
	"testing"
)

type fieldDepSample struct {
	Plain         string `flag:"plain"`
	MarkerOnly    string `flag:"marker-only" deprecated:""`
	ReplOnly      string `flag:"repl-only" deprecated:"new-flag"`
	MsgOnly       string `flag:"msg-only" deprecated:",will be removed"`
	Both          string `flag:"both" deprecated:"new-flag,use the new flag"`
	MessageCommas string `flag:"msg-commas" deprecated:"new-flag,merged into new-flag, see docs, please"`
	UnrelatedTg   string `flag:"unrelated" validate:"required"`
}

func TestFieldDeprecation(t *testing.T) {
	tests := []struct {
		field   string
		wantNil bool
		wantMsg string
		wantRep string
	}{
		{"Plain", true, "", ""},
		{"MarkerOnly", false, "", ""},
		{"ReplOnly", false, "", "new-flag"},
		{"MsgOnly", false, "will be removed", ""},
		{"Both", false, "use the new flag", "new-flag"},
		{"MessageCommas", false, "merged into new-flag, see docs, please", "new-flag"},
		{"UnrelatedTg", true, "", ""},
	}

	rt := reflect.TypeOf(fieldDepSample{})
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			f, ok := rt.FieldByName(tt.field)
			if !ok {
				t.Fatalf("field %s not found", tt.field)
			}
			got := FieldDeprecation(f)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("want nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("want non-nil deprecation")
			}
			if got.Message != tt.wantMsg || got.Replacement != tt.wantRep {
				t.Errorf("got %+v, want {Message:%q Replacement:%q}", got, tt.wantMsg, tt.wantRep)
			}
		})
	}
}
