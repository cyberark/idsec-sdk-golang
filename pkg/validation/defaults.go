package validation

import (
	"reflect"
	"strconv"
	"strings"
)

// ApplyDefaults walks s and fills any zero-value field that declares a
// `default:"..."` struct tag with the parsed default value. It recurses
// into nested structs and non-nil struct pointers. s must be a non-nil
// pointer to a struct; other inputs are ignored.
//
// Only fields that currently hold their type's zero value are touched, so
// caller-supplied values are never overwritten. This runs before validation
// so that rules like `timezone` see the declared default (e.g. "GMT")
// instead of an empty string.
func ApplyDefaults(s interface{}) {
	v := reflect.ValueOf(s)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return
	}
	elem := v.Elem()
	if elem.Kind() != reflect.Struct {
		return
	}
	applyDefaults(elem)
}

func applyDefaults(v reflect.Value) {
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if !field.CanSet() {
			continue
		}

		switch field.Kind() {
		case reflect.Struct:
			applyDefaults(field)
			continue
		case reflect.Ptr:
			if !field.IsNil() && field.Elem().Kind() == reflect.Struct {
				cp := reflect.New(field.Elem().Type())
				cp.Elem().Set(field.Elem())
				field.Set(cp)
				applyDefaults(cp.Elem())
			}
			continue
		}

		if !field.IsZero() {
			continue
		}
		def, ok := t.Field(i).Tag.Lookup("default")
		if !ok || def == "" {
			continue
		}
		setDefault(field, def)
	}
}

func setDefault(field reflect.Value, def string) {
	switch field.Kind() {
	case reflect.String:
		field.SetString(def)
	case reflect.Bool:
		if b, err := strconv.ParseBool(def); err == nil {
			field.SetBool(b)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if n, err := strconv.ParseInt(def, 10, 64); err == nil {
			field.SetInt(n)
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if n, err := strconv.ParseUint(def, 10, 64); err == nil {
			field.SetUint(n)
		}
	case reflect.Float32, reflect.Float64:
		if f, err := strconv.ParseFloat(def, 64); err == nil {
			field.SetFloat(f)
		}
	case reflect.Slice:
		setSliceDefault(field, def)
	}
}

// setSliceDefault handles comma-separated defaults for []int and []string,
// which are the only slice types used in SDK model `default:` tags.
// All-or-nothing: if any element fails to parse, the entire default is skipped.
func setSliceDefault(field reflect.Value, def string) {
	parts := strings.Split(def, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	switch field.Type().Elem().Kind() {
	case reflect.String:
		field.Set(reflect.ValueOf(parts))
	case reflect.Int:
		ints := make([]int, 0, len(parts))
		for _, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil {
				return // unparseable element — skip entire default
			}
			ints = append(ints, n)
		}
		field.Set(reflect.ValueOf(ints))
	}
}
