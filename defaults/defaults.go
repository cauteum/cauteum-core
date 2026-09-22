// Package defaults holds shared ports, guest paths, and image names used across whaleshell modules.
package defaults

import (
	"fmt"
	"time"
)

// Well-known TCP ports.
const (
	ProxyPort    = 3128
	GatewayPort  = 7443
	NoVNCPort    = 6080
	GuestSSHPort = 2222
	HTTPSPort    = 443
	HTTPPort     = 80
)

// GatewayListen is the default whaleshell-gateway bind address.
const GatewayListen = "127.0.0.1:7443"

// ProxyListenHost is used when binding the sidecar on all interfaces inside the netns.
const ProxyListenHost = "0.0.0.0"

// Guest filesystem layout inside sandboxes.
const (
	GuestRoot   = "/whaleshell"
	GuestData   = "/whaleshell/data"
	GuestHome   = "/whaleshell/data/home"
	GuestBin    = "/whaleshell/data/bin"
	GuestCADir  = "/whaleshell/ca"
	GuestCAFile = "/whaleshell/ca/ca.pem"
	GuestPolicy = "/whaleshell/policy.yaml"
	GuestInit   = "/whaleshell/whaleshell-init"
	GuestPath   = "/whaleshell/data/home/.local/bin:/whaleshell/data/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

	// GuestEtcOSG is the reserved control tree for agent guidance (skills, payload).
	// Same role as OpenShell's /etc/openshell; whaleshell naming, MIT-owned content.
	GuestEtcOSG       = "/etc/whaleshell"
	GuestSkills       = "/etc/whaleshell/skills"
	GuestAgentPayload = "/etc/whaleshell/agent-payload"

	// GuestSandboxHome mirrors OpenShell harness HOME (/sandbox/home).
	// Symlinked to GuestHome on agent-config install so persist volume stays canonical.
	GuestSandboxRoot = "/sandbox"
	GuestSandboxHome = "/sandbox/home"
)

// NoProxyValue is the default NO_PROXY / no_proxy list for sandbox guests.
const NoProxyValue = "localhost,127.0.0.1,::1"

// Sandbox image tags (local dev) and GHCR catalog (OpenShell-style paths).
const (
	ImageDebian = "debian:bookworm"
	ImageLocal  = "whaleshell-sandbox:local"
	ImageGUI    = "whaleshell-sandbox:gui"
	ImageGPU    = "whaleshell-sandbox:gpu"
	ImageCursor = "whaleshell-sandbox:cursor"
	ImageClaude = "whaleshell-sandbox:claude"
	ImageCodex  = "whaleshell-sandbox:codex"

	// GHCR: separate image per flavor (like openshell-community/sandboxes/<name>).
	GHCROrg        = "ghcr.io/whaleshell"
	GHCRGateway    = GHCROrg + "/whaleshell/gateway"
	GHCRSandboxes  = GHCROrg + "/whaleshell/sandboxes"
	ImageBaseRef   = GHCRSandboxes + "/base:latest"
	ImageGUIRef    = GHCRSandboxes + "/gui:latest"
	ImageGPURef    = GHCRSandboxes + "/gpu:latest"
	ImageCursorRef = GHCRSandboxes + "/cursor:latest"
	ImageClaudeRef = GHCRSandboxes + "/claude:latest"
	ImageCodexRef  = GHCRSandboxes + "/codex:latest"
)

// Guest SSH layout (whaleshell-sshd).
const (
	GuestSSHDir            = "/whaleshell/ssh"
	GuestSSHAuthorizedKeys = "/whaleshell/ssh/authorized_keys"
	GuestSSHHostKey        = "/whaleshell/ssh/host_ed25519"
)

// HeaderBinary is an optional HTTP header naming the egress client binary (tests / ops).
const HeaderBinary = "X-WHALESHELL-Binary"

// EnvTrustBinaryHeader enables trusting HeaderBinary when set to 1/true/yes.
const EnvTrustBinaryHeader = "WHALESHELL_TRUST_BINARY_HEADER"

// RelayClientTimeout is the CLI/SDK wait for a gateway relay exec round-trip.
const RelayClientTimeout = 70 * time.Second

// ProxyEnvKeys lists host proxy variables forwarded into the sidecar (not the guest agent).
var ProxyEnvKeys = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
	"http_proxy", "https_proxy", "all_proxy", "no_proxy",
}

// ProxyListenLocal returns 127.0.0.1:<ProxyPort>.
func ProxyListenLocal() string {
	return fmt.Sprintf("127.0.0.1:%d", ProxyPort)
}
