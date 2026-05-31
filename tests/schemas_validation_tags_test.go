package tests

import (
	"errors"
	"reflect"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/actions"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	"github.com/cyberark/idsec-sdk-golang/pkg/validation"

	_ "github.com/cyberark/idsec-sdk-golang/pkg"
)

// TestAllSchemasParseValidationTags runs validation.ValidateStruct over a
// zero-valued instance of every registered action schema across every
// registered service.
func TestAllSchemasParseValidationTags(t *testing.T) {
	allConfigs := services.AllServiceConfigs()
	if len(allConfigs) == 0 {
		t.Skip("no service configurations registered")
	}

	for _, config := range allConfigs {
		config := config
		t.Run(config.ServiceName, func(t *testing.T) {
			for actionName, rawSchema := range config.ActionSchemas {
				actionName := actionName
				rawSchema := rawSchema
				t.Run(actionName, func(t *testing.T) {
					schemaIface, _ := actions.UnwrapSchema(rawSchema)
					if schemaIface == nil {
						return
					}

					schemaType := reflect.TypeOf(schemaIface)
					if schemaType.Kind() == reflect.Ptr {
						schemaType = schemaType.Elem()
					}
					if schemaType.Kind() != reflect.Struct {
						return
					}

					defer func() {
						if r := recover(); r != nil {
							t.Fatalf("validation.ValidateStruct panicked on zero-valued %s: %v", schemaType, r)
						}
					}()

					zero := reflect.New(schemaType).Interface()
					err := validation.ValidateStruct(zero)
					if err == nil {
						return
					}
					var validationErrs validator.ValidationErrors
					if !errors.As(err, &validationErrs) {
						t.Fatalf("non-ValidationErrors failure on zero-valued %s — likely a malformed validate tag: %v", schemaType, err)
					}
				})
			}
		})
	}
}
