package relayproto

import "time"

// Operational defaults owned by this package.
const (
	defaultDialTimeout   = 10 * time.Second
	tcpKeepaliveInterval = 30 * time.Second
)
