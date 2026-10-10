// Package core holds shared identity and error primitives for cautem modules.
package core

// ID is an opaque sandbox or resource identifier.
type ID string

var ErrNotImplemented = errNotImplemented{}

type errNotImplemented struct{}

func (errNotImplemented) Error() string { return "cautem-core: not implemented" }
