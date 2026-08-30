package gcp

import (
	"reflect"
	"unsafe"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
)

// setupGCPService creates an IdsecCCEGCPService with the given mock ISP client.
func setupGCPService(client *isp.IdsecISPServiceClient) *IdsecCCEGCPService {
	ispBase := &services.IdsecISPBaseService{}
	// Use reflection to set the private client field for testing
	v := reflect.ValueOf(ispBase).Elem()
	clientField := v.FieldByName("client")
	clientField = reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr())).Elem()
	clientField.Set(reflect.ValueOf(client))

	return &IdsecCCEGCPService{
		IdsecBaseService: &services.IdsecBaseService{
			Logger: common.GlobalLogger,
		},
		IdsecISPBaseService: ispBase,
	}
}
