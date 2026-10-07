// Package defaults holds shared ports, guest paths, and image names used across whaleshell modules.
package defaults

import (
	"fmt"
	"strings"
	"time"
)

// Well-known TCP ports.
const (
	ProxyPort   = 3128
	GatewayPort = 7443
	NoVNCPort   = 6080
	HTTPSPort   = 443
	HTTPPort    = 80
)

// GatewayListen is the default whaleshell-gateway bind address.
const GatewayListen = "127.0.0.1:7443"

// HostInternal is the host gateway alias injected into sandbox DNS.
const HostInternal = "host.whaleshell.internal"

// ProxyListenHost is used when binding the sidecar on all interfaces inside the netns.
const ProxyListenHost = "0.0.0.0"

// Guest filesystem layout inside sandboxes.
const (
	GuestRoot   = "/whaleshell"
	GuestData   = GuestRoot + "/data"
	GuestHome   = GuestData + "/home"
	GuestBin    = GuestData + "/bin"
	GuestCADir  = GuestRoot + "/ca"
	GuestCAFile = GuestCADir + "/ca.pem"
	GuestPolicy = GuestRoot + "/policy.yaml"
	GuestInit   = GuestRoot + "/whaleshell-init"
	GuestPath   = "/whaleshell/data/home/.local/bin:/whaleshell/data/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

	// GuestEtcOSG is the reserved control tree for supervisor-owned guidance.
	// Same role as OpenShell's /etc/openshell; whaleshell naming, Apache-2.0 project content.
	GuestEtcOSG = "/etc/whaleshell"
	GuestSkills = GuestEtcOSG + "/skills"
)

// NoProxyValue is the default NO_PROXY / no_proxy list for sandbox guests.
const NoProxyValue = "localhost,127.0.0.1,::1"

// Sandbox image tags (local dev) and GHCR catalog (OpenShell-style paths).
const (
	ImageDebian = "debian:bookworm"
	// ImageProxy is the slim base for egress sidecars (not the agent/sandbox image).
	ImageProxy  = "debian:bookworm-slim"
	ImageLocal  = "whaleshell-sandbox:local"
	ImageGUI    = "whaleshell-sandbox:gui"
	ImageGPU    = "whaleshell-sandbox:gpu"
	ImageCursor = "whaleshell-sandbox:cursor"
	ImageClaude = "whaleshell-sandbox:claude"
	ImageCodex  = "whaleshell-sandbox:codex"

	// SandboxPidsLimit is the OpenShell-aligned default PIDs cgroup limit when unset.
	SandboxPidsLimit int64 = 2048

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

// EnvImagePull controls pulling published images for missing local
// whaleshell-sandbox:* tags: "never" disables it (offline / local builds only).
const EnvImagePull = "WHALESHELL_IMAGE_PULL"

// PublishedImage maps a local whaleshell-sandbox:<flavor> tag to the GHCR image
// CI publishes for it, so installs work without building images locally.
func PublishedImage(local string) (string, bool) {
	flavor, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(local)), "whaleshell-sandbox:")
	if !ok {
		return "", false
	}
	switch flavor {
	case "local", "base":
		return ImageBaseRef, true
	case "gui":
		return ImageGUIRef, true
	case "gpu":
		return ImageGPURef, true
	case "cursor":
		return ImageCursorRef, true
	case "claude":
		return ImageClaudeRef, true
	case "codex":
		return ImageCodexRef, true
	}
	return "", false
}

// Guest SSH layout (whaleshell-sshd). The socket directory is a volume shared
// with the proxy sidecar (supervisor relay); sshd never listens on TCP.
const (
	GuestSSHD      = GuestRoot + "/whaleshell-sshd"
	GuestSSHDir    = GuestRoot + "/ssh"
	GuestSSHSocket = GuestSSHDir + "/sshd.sock"
	GuestSSHLog    = GuestSSHDir + "/sshd.log"
	GuestWorkspace = "/workspace"
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

// Inference API defaults. Provider configuration can override these endpoints.
const (
	InferenceOpenAI    = "https://api.openai.com"
	InferenceAnthropic = "https://api.anthropic.com"
	InferenceNVIDIA    = "https://integrate.api.nvidia.com"
	InferenceDeepInfra = "https://api.deepinfra.com"
	InferenceOllama    = "http://" + HostInternal + ":11434"
)
