package actions

// SchemaEntry is an in-band wrapper for values stored in ActionToSchemaMap
// that need extra metadata (currently only deprecation).
// This wrapper simply attaches optional Deprecation metadata that downstream surfaces (CLI, Terraform, docs)
type SchemaEntry struct {
	Schema      interface{}
	Deprecation Deprecation
}

// Deprecated wraps an existing schema value (struct pointer or nil) together
// with deprecation metadata.
func Deprecated(schema interface{}, dep Deprecation) SchemaEntry {
	return SchemaEntry{Schema: schema, Deprecation: dep}
}

// DeprecatedNil is a convenience wrapper for actions that have no input
// schema but still need to advertise a deprecation.
func DeprecatedNil(dep Deprecation) SchemaEntry {
	return SchemaEntry{Schema: nil, Deprecation: dep}
}

// UnwrapSchema returns the underlying schema value plus deprecation metadata
// for any entry in ActionToSchemaMap.
func UnwrapSchema(value interface{}) (interface{}, *Deprecation) {
	switch v := value.(type) {
	case SchemaEntry:
		dep := v.Deprecation
		return v.Schema, &dep
	case *SchemaEntry:
		if v == nil {
			return nil, nil
		}
		dep := v.Deprecation
		return v.Schema, &dep
	default:
		return value, nil
	}
}
