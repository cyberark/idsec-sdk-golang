package internal

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCCEVersionIfChanged(t *testing.T) {
	tests := []struct {
		name     string
		desired  string
		current  string
		expected string
	}{
		{name: "changed", desired: "0.1.0", current: "0.0.1", expected: "0.1.0"},
		{name: "unchanged", desired: "0.0.1", current: "0.0.1", expected: ""},
		{name: "desired_empty", desired: "", current: "0.0.1", expected: ""},
		{name: "both_empty", desired: "", current: "", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, CCEVersionIfChanged(tt.desired, tt.current))
		})
	}
}

func TestCCEVersionLogValue(t *testing.T) {
	require.Equal(t, "0.1.0", CCEVersionLogValue("0.1.0"))
	require.Equal(t, "unchanged, not sent", CCEVersionLogValue(""))
}
