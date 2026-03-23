package models

import "fmt"

// RightsBits represents a pair of 32-bit integers encoding access-control rights.
//
// Hi and Lo together form a 64-bit bitmask split into two uint32 halves, matching
// the server-side RightsBits (acl.cs, RightsBits : ulong) representation.
type RightsBits struct {
	Hi uint32
	Lo uint32
}

// NewRightsBits creates a new RightsBits with the given high and low 32-bit values.
//
// Parameters:
//   - hi: The upper 32 bits of the rights mask.
//   - lo: The lower 32 bits of the rights mask.
//
// Returns a RightsBits initialised with the provided values.
func NewRightsBits(hi, lo uint32) RightsBits {
	return RightsBits{Hi: hi, Lo: lo}
}

// RightsBitsFromBit creates a RightsBits whose Lo field is set to bit and Hi to 0.
//
// Parameters:
//   - bit: A single bit value that will be placed in the Lo half.
//
// Returns a RightsBits representing that single bit.
func RightsBitsFromBit(bit uint32) RightsBits {
	return NewRightsBits(0x00000000, bit)
}

// RightsBitsFromArr merges a slice of RightsBits into a single combined RightsBits.
//
// Each non-zero element in the slice is OR-ed together via Merge.
//
// Parameters:
//   - arr: Slice of RightsBits values to combine.
//
// Returns the merged RightsBits.
func RightsBitsFromArr(arr []RightsBits) RightsBits {
	result := NewRightsBits(0, 0)
	for _, rb := range arr {
		result.Merge(rb)
	}
	return result
}

// IsXSet reports whether any of the bits specified by maskLo are set in Lo.
//
// Parameters:
//   - maskLo: A bitmask to test against the Lo field.
//
// Returns true if at least one masked bit is set in Lo.
func (r *RightsBits) IsXSet(maskLo uint32) bool {
	return (r.Lo & maskLo) != 0
}

// IsSet reports whether all bits of rights are set in the receiver.
//
// Parameters:
//   - rights: The RightsBits whose bits must all be present in the receiver.
//
// Returns true only when every bit in rights is also set in the receiver.
func (r *RightsBits) IsSet(rights RightsBits) bool {
	t := r.And(rights)
	return t.Lo == rights.Lo && t.Hi == rights.Hi
}

// Merge OR-s the bits of input into the receiver in-place and returns the receiver.
//
// Parameters:
//   - input: The RightsBits whose bits are merged into the receiver.
//
// Returns a pointer to the modified receiver to allow chaining.
func (r *RightsBits) Merge(input RightsBits) *RightsBits {
	r.Hi |= input.Hi
	r.Lo |= input.Lo
	return r
}

// And returns a new RightsBits containing only the bits that are set in both
// the receiver and input.
//
// Parameters:
//   - input: The RightsBits to AND with the receiver.
//
// Returns a new RightsBits that is the bitwise AND of the receiver and input.
func (r *RightsBits) And(input RightsBits) RightsBits {
	return RightsBits{
		Lo: r.Lo & input.Lo,
		Hi: r.Hi & input.Hi,
	}
}

// Copy returns a deep copy of the receiver.
//
// Returns a new RightsBits with identical Hi and Lo values.
func (r RightsBits) Copy() RightsBits {
	return NewRightsBits(r.Hi, r.Lo)
}

// String returns a human-readable hex representation of the rights mask.
//
// Returns a string in the format "0x<hi>:0x<lo>".
func (r RightsBits) String() string {
	return fmt.Sprintf("0x%x:0x%x", r.Hi, r.Lo)
}

// Rights mirrors the server-side RightsBits enum (acl.cs, public enum RightsBits : ulong).
// Each field is a pre-built RightsBits corresponding to a named permission level.
var Rights = struct {
	None      RightsBits
	Owner     RightsBits
	Read      RightsBits
	Write     RightsBits
	List      RightsBits
	Create    RightsBits
	Delete    RightsBits
	Execute   RightsBits
	Automatic RightsBits
}{
	None:      NewRightsBits(0x0, 0<<0),
	Owner:     NewRightsBits(0x0, 1<<0),
	Read:      NewRightsBits(0x0, 1<<2),
	Write:     NewRightsBits(0x0, 1<<3),
	List:      NewRightsBits(0x0, 1<<4),
	Create:    NewRightsBits(0x0, 1<<5),
	Delete:    NewRightsBits(0x0, 1<<6),
	Execute:   NewRightsBits(0x0, 1<<7),
	Automatic: NewRightsBits(0x0, 1<<31),
}
