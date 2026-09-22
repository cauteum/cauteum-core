// Package core holds shared identity and error primitives for whaleshell modules.
package core

// ID is an opaque sandbox or resource identifier.
type ID string

var ErrNotImplemented = errNotImplemented{}

type errNotImplemented struct{}

func (errNotImplemented) Error() string { return "whaleshell-core: not implemented" }
