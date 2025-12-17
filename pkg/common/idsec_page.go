// Package common provides shared utilities and types for the IDSEC SDK.
//
// This package contains shared types and functionality used across the Idsec SDK,
// including pagination support and common data structures for API responses.
package common

// IdsecPage represents a generic paginated response container from the Idsec service.
//
// IdsecPage is a type-safe generic structure that wraps paginated API responses.
// It provides a consistent interface for handling collections of items returned
// from Idsec service endpoints. The generic type parameter T allows for strongly
// typed access to the contained items while maintaining flexibility across
// different data types.
//
// The structure supports JSON unmarshaling and mapstructure decoding, making it
// suitable for use with various serialization libraries and configuration
// management tools.
//
// Type Parameters:
//   - T: The type of items contained in the paginated response
//
// Fields:
//   - Items: Slice of pointers to items of type T, representing the paginated data
//
// Example:
//
//	// For a paginated response of user objects
//	type User struct {
//	    ID   string `json:"id"`
//	    Name string `json:"name"`
//	}
//
//	var userPage IdsecPage[User]
//	err := json.Unmarshal(responseData, &userPage)
//	if err != nil {
//	    // handle error
//	}
//
//	for _, user := range userPage.Items {
//	    fmt.Printf("User: %s (ID: %s)\n", user.Name, user.ID)
//	}
type IdsecPage[T any] struct {
	Items []*T `json:"items" mapstructure:"items"`
}
