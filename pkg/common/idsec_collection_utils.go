package common

// NilToEmptyMap returns a non-nil empty map when m is nil, otherwise m.
func NilToEmptyMap[V any](m map[string]V) map[string]V {
	if m == nil {
		return map[string]V{}
	}
	return m
}

// NilToEmptySlice returns a non-nil empty slice when s is nil, otherwise s.
func NilToEmptySlice[V any](s []V) []V {
	if s == nil {
		return []V{}
	}
	return s
}
