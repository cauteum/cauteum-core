// Package policy defines the OpenShell-shaped sandbox policy YAML schema.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/cautem/cautem-core/internal/hostpattern"
	"gopkg.in/yaml.v3"
)

// Document is the canonical sandbox policy (OpenShell YAML naming).
type Document struct {
	Version            uint32                   `yaml:"version" json:"version"`
	FilesystemPolicy   *FilesystemPolicy        `yaml:"filesystem_policy,omitempty" json:"filesystem_policy,omitempty"`
	Landlock           *Landlock                `yaml:"landlock,omitempty" json:"landlock,omitempty"`
	Process            *Process                 `yaml:"process,omitempty" json:"process,omitempty"`
	NetworkPolicies    map[string]NetworkPolicy `yaml:"network_policies,omitempty" json:"network_policies,omitempty"`
	NetworkMiddlewares map[string]yaml.Node     `yaml:"network_middlewares,omitempty" json:"network_middlewares,omitempty"`
	Inference          *Inference               `yaml:"inference,omitempty" json:"inference,omitempty"`
	Display            *Display                 `yaml:"display,omitempty" json:"display,omitempty"`
	Credentials        *Credentials             `yaml:"credentials,omitempty" json:"credentials,omitempty"`
	// Binaries is a top-level TOFU path allowlist (globs). Empty = no global binary gate.
	Binaries []string `yaml:"binaries,omitempty" json:"binaries,omitempty"`
}

func (d *Document) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("policy: document must be a JSON object")
	}
	seen := map[string]struct{}{}
	versionPresent := false
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("policy: invalid JSON document")
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("policy: document keys must be strings")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("policy: duplicate field %q", key)
		}
		seen[key] = struct{}{}
		if key == "version" {
			versionPresent = true
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("policy: invalid JSON document")
		}
		if key == "version" {
			var version uint32
			if string(value) == "null" || json.Unmarshal(value, &version) != nil {
				return fmt.Errorf("policy: version must be an unsigned 32-bit integer")
			}
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return fmt.Errorf("policy: invalid JSON document")
	}
	if !versionPresent {
		return fmt.Errorf("policy: missing required field %q", "version")
	}
	type documentAlias Document
	var decoded documentAlias
	strict := json.NewDecoder(bytes.NewReader(data))
	strict.DisallowUnknownFields()
	if err := strict.Decode(&decoded); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	var trailing any
	if err := strict.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("policy: multiple JSON values")
	}
	*d = Document(decoded)
	return nil
}

// FilesystemPolicy is Landlock path policy + workdir include flag.
type FilesystemPolicy struct {
	IncludeWorkdir bool `yaml:"include_workdir" json:"include_workdir"`
	// IncludeWorkdirSet preserves an explicit false while omitted fields use
	// OpenShell's default of true.
	IncludeWorkdirSet bool     `yaml:"-" json:"-"`
	ReadOnly          []string `yaml:"read_only,omitempty" json:"read_only,omitempty"`
	ReadWrite         []string `yaml:"read_write,omitempty" json:"read_write,omitempty"`
}

func (f *FilesystemPolicy) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("filesystem_policy must be a mapping")
	}
	f.IncludeWorkdir = true
	seen := map[string]struct{}{}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return fmt.Errorf("filesystem_policy keys must be strings")
		}
		if _, duplicate := seen[key.Value]; duplicate {
			return fmt.Errorf("filesystem_policy has duplicate field %q", key.Value)
		}
		seen[key.Value] = struct{}{}
		switch key.Value {
		case "include_workdir":
			if value.Tag != "!!bool" {
				return fmt.Errorf("filesystem_policy.include_workdir must be a boolean")
			}
			if err := value.Decode(&f.IncludeWorkdir); err != nil {
				return fmt.Errorf("filesystem_policy.include_workdir: %w", err)
			}
			f.IncludeWorkdirSet = true
		case "read_only":
			if value.Kind != yaml.SequenceNode {
				return fmt.Errorf("filesystem_policy.read_only must be a sequence")
			}
			if err := value.Decode(&f.ReadOnly); err != nil {
				return fmt.Errorf("filesystem_policy.read_only: %w", err)
			}
		case "read_write":
			if value.Kind != yaml.SequenceNode {
				return fmt.Errorf("filesystem_policy.read_write must be a sequence")
			}
			if err := value.Decode(&f.ReadWrite); err != nil {
				return fmt.Errorf("filesystem_policy.read_write: %w", err)
			}
		default:
			return fmt.Errorf("filesystem_policy has unknown field %q", key.Value)
		}
	}
	return nil
}

func (f FilesystemPolicy) MarshalYAML() (any, error) {
	type yamlFilesystemPolicy struct {
		IncludeWorkdir *bool    `yaml:"include_workdir,omitempty"`
		ReadOnly       []string `yaml:"read_only,omitempty"`
		ReadWrite      []string `yaml:"read_write,omitempty"`
	}
	var include *bool
	if f.IncludeWorkdirSet {
		include = &f.IncludeWorkdir
	}
	return yamlFilesystemPolicy{IncludeWorkdir: include, ReadOnly: f.ReadOnly, ReadWrite: f.ReadWrite}, nil
}

func (f *FilesystemPolicy) UnmarshalJSON(data []byte) error {
	type jsonFilesystemPolicy struct {
		IncludeWorkdir json.RawMessage `json:"include_workdir"`
		ReadOnly       json.RawMessage `json:"read_only"`
		ReadWrite      json.RawMessage `json:"read_write"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value jsonFilesystemPolicy
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("filesystem_policy: multiple JSON values")
		}
		return err
	}
	f.IncludeWorkdir, f.IncludeWorkdirSet = true, false
	if len(value.IncludeWorkdir) != 0 {
		if string(value.IncludeWorkdir) == "null" {
			return fmt.Errorf("filesystem_policy.include_workdir must be a boolean")
		}
		if err := json.Unmarshal(value.IncludeWorkdir, &f.IncludeWorkdir); err != nil {
			return fmt.Errorf("filesystem_policy.include_workdir: %w", err)
		}
		f.IncludeWorkdirSet = true
	}
	if err := decodeFilesystemPathList("read_only", value.ReadOnly, &f.ReadOnly); err != nil {
		return err
	}
	if err := decodeFilesystemPathList("read_write", value.ReadWrite, &f.ReadWrite); err != nil {
		return err
	}
	return nil
}

func decodeFilesystemPathList(key string, raw json.RawMessage, target *[]string) error {
	if len(raw) == 0 {
		*target = nil
		return nil
	}
	if string(raw) == "null" {
		return fmt.Errorf("filesystem_policy.%s must be a sequence", key)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("filesystem_policy.%s: %w", key, err)
	}
	return nil
}

func (f FilesystemPolicy) MarshalJSON() ([]byte, error) {
	type jsonFilesystemPolicy struct {
		IncludeWorkdir bool     `json:"include_workdir"`
		ReadOnly       []string `json:"read_only,omitempty"`
		ReadWrite      []string `json:"read_write,omitempty"`
	}
	return json.Marshal(jsonFilesystemPolicy{
		IncludeWorkdir: f.IncludeWorkdirEnabled(),
		ReadOnly:       f.ReadOnly,
		ReadWrite:      f.ReadWrite,
	})
}

func (f FilesystemPolicy) IncludeWorkdirEnabled() bool {
	return f.IncludeWorkdir || !f.IncludeWorkdirSet
}

// Landlock configures Landlock compatibility mode.
type Landlock struct {
	// Compatibility: best_effort | hard_requirement.
	Compatibility string `yaml:"compatibility,omitempty" json:"compatibility,omitempty"`
}

func (l *Landlock) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("landlock must be a mapping")
	}
	l.Compatibility = "best_effort"
	seen := make(map[string]struct{}, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return fmt.Errorf("landlock keys must be strings")
		}
		if _, duplicate := seen[key.Value]; duplicate {
			return fmt.Errorf("landlock has duplicate field %q", key.Value)
		}
		seen[key.Value] = struct{}{}
		if key.Value != "compatibility" {
			return fmt.Errorf("landlock has unknown field %q", key.Value)
		}
		if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
			return fmt.Errorf("landlock.compatibility must be a string")
		}
		if value.Value == "" {
			return fmt.Errorf("landlock.compatibility must be best_effort|hard_requirement")
		}
		l.Compatibility = value.Value
	}
	return nil
}

func (l *Landlock) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("landlock must be an object")
	}
	l.Compatibility = "best_effort"
	seen := map[string]struct{}{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("landlock: invalid JSON object")
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("landlock keys must be strings")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("landlock has duplicate field %q", key)
		}
		seen[key] = struct{}{}
		if key != "compatibility" {
			return fmt.Errorf("landlock has unknown field %q", key)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil || string(value) == "null" {
			return fmt.Errorf("landlock.compatibility must be a string")
		}
		if err := json.Unmarshal(value, &l.Compatibility); err != nil {
			return fmt.Errorf("landlock.compatibility must be a string")
		}
		if l.Compatibility == "" {
			return fmt.Errorf("landlock.compatibility must be best_effort|hard_requirement")
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return fmt.Errorf("landlock: invalid JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("landlock: multiple JSON values")
	}
	return nil
}

// Process is sandbox process identity (omit to let the compute driver choose).
type Process struct {
	RunAsUser  string `yaml:"run_as_user,omitempty" json:"run_as_user,omitempty"`
	RunAsGroup string `yaml:"run_as_group,omitempty" json:"run_as_group,omitempty"`
}

func (p *Process) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("process must be a mapping")
	}
	*p = Process{}
	seen := map[string]struct{}{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return fmt.Errorf("process keys must be strings")
		}
		if _, duplicate := seen[key.Value]; duplicate {
			return fmt.Errorf("process has duplicate field %q", key.Value)
		}
		seen[key.Value] = struct{}{}
		if key.Value != "run_as_user" && key.Value != "run_as_group" {
			return fmt.Errorf("process has unknown field %q", key.Value)
		}
		if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
			return fmt.Errorf("process.%s must be a string", key.Value)
		}
		if key.Value == "run_as_user" {
			p.RunAsUser = value.Value
		} else {
			p.RunAsGroup = value.Value
		}
	}
	return nil
}

func (p *Process) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("process must be an object")
	}
	*p = Process{}
	seen := map[string]struct{}{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("process: invalid JSON object")
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("process keys must be strings")
		}
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("process has duplicate field %q", key)
		}
		seen[key] = struct{}{}
		if key != "run_as_user" && key != "run_as_group" {
			return fmt.Errorf("process has unknown field %q", key)
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil || string(value) == "null" {
			return fmt.Errorf("process.%s must be a string", key)
		}
		var identity string
		if err := json.Unmarshal(value, &identity); err != nil {
			return fmt.Errorf("process.%s must be a string", key)
		}
		if key == "run_as_user" {
			p.RunAsUser = identity
		} else {
			p.RunAsGroup = identity
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return fmt.Errorf("process: invalid JSON object")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("process: multiple JSON values")
	}
	return nil
}

// NetworkPolicy is one named egress policy (map value under network_policies).
type NetworkPolicy struct {
	Name      string          `yaml:"name,omitempty" json:"name,omitempty"`
	Endpoints []AllowRule     `yaml:"endpoints,omitempty" json:"endpoints,omitempty"`
	Binaries  []NetworkBinary `yaml:"binaries,omitempty" json:"binaries,omitempty"`
}

// NetworkBinary restricts which binaries may use the rule (empty = any).
type NetworkBinary struct {
	Path    string `yaml:"path" json:"path"`
	Harness bool   `yaml:"harness,omitempty" json:"-"` // deprecated by OpenShell; accepted and ignored
}

// AllowRule is one egress endpoint (L4 + optional L7). Used under
// network_policies.*.endpoints and as the flattened engine view.
type AllowRule struct {
	ID       string   `yaml:"id,omitempty" json:"id,omitempty"`
	Host     string   `yaml:"host,omitempty" json:"host,omitempty"`
	Port     int      `yaml:"port,omitempty" json:"port,omitempty"`
	Ports    []int    `yaml:"ports,omitempty" json:"ports,omitempty"`
	Binaries []string `yaml:"binaries,omitempty" json:"binaries,omitempty"`

	// L7. Empty Protocol = L4 CONNECT tunnel only.
	Protocol   string       `yaml:"protocol,omitempty" json:"protocol,omitempty"` // rest | websocket | graphql | json-rpc | mcp
	TLS        string       `yaml:"tls,omitempty" json:"tls,omitempty"`           // skip disables TLS inspection; terminate/passthrough are deprecated Auto aliases
	Access     string       `yaml:"access,omitempty" json:"access,omitempty"`     // read-only | read-write | full
	Path       string       `yaml:"path,omitempty" json:"path,omitempty"`
	Rules      []L7Rule     `yaml:"rules,omitempty" json:"rules,omitempty"`
	DenyRules  []L7DenyRule `yaml:"deny_rules,omitempty" json:"deny_rules,omitempty"`
	AllowedIPs []string     `yaml:"allowed_ips,omitempty" json:"allowed_ips,omitempty"`
	// Enforcement is enforce (default) or audit.
	Enforcement string `yaml:"enforcement,omitempty" json:"enforcement,omitempty"`
	// CredentialKeys binds cautem:resolve:env:KEY rewrite to this endpoint.
	CredentialKeys               []string                       `yaml:"credential_keys,omitempty" json:"credential_keys,omitempty"`
	CredentialSigning            string                         `yaml:"credential_signing,omitempty" json:"credential_signing,omitempty"`
	SigningService               string                         `yaml:"signing_service,omitempty" json:"signing_service,omitempty"`
	SigningRegion                string                         `yaml:"signing_region,omitempty" json:"signing_region,omitempty"`
	WebsocketCredentialRewrite   bool                           `yaml:"websocket_credential_rewrite,omitempty" json:"websocket_credential_rewrite,omitempty"`
	RequestBodyCredentialRewrite bool                           `yaml:"request_body_credential_rewrite,omitempty" json:"request_body_credential_rewrite,omitempty"`
	PersistedQueries             string                         `yaml:"persisted_queries,omitempty" json:"persisted_queries,omitempty"`
	GraphQLPersistedQueries      map[string]GraphQLOperationDef `yaml:"graphql_persisted_queries,omitempty" json:"graphql_persisted_queries,omitempty"`
	GraphQLMaxBodyBytes          *uint32                        `yaml:"graphql_max_body_bytes,omitempty" json:"graphql_max_body_bytes,omitempty"`
	AllowEncodedSlash            bool                           `yaml:"allow_encoded_slash,omitempty" json:"allow_encoded_slash,omitempty"`
	AllowUninspectedCredentials  bool                           `yaml:"allow_uninspected_credentials,omitempty" json:"allow_uninspected_credentials,omitempty"`
	CredentialBinding            *CredentialBinding             `yaml:"credential_binding,omitempty" json:"credential_binding,omitempty"`
	JSONRPC                      *JSONRPCConfig                 `yaml:"json_rpc,omitempty" json:"json_rpc,omitempty"`
	MCP                          *MCPConfig                     `yaml:"mcp,omitempty" json:"mcp,omitempty"`

	// networkPolicyKey/name preserve the source map identity across flattening
	// and SetNetworkAllows updates. They are not part of the serialized schema.
	networkPolicyKey  string
	networkPolicyName string
}

// CredentialBinding names an attached, endpointless provider instance whose
// credentials may be used only for this endpoint.
type CredentialBinding struct {
	Provider string `yaml:"provider" json:"provider"`
}

// GraphQLOperationDef is one trusted persisted GraphQL operation.
type GraphQLOperationDef struct {
	OperationType string   `yaml:"operation_type,omitempty" json:"operation_type,omitempty"`
	OperationName string   `yaml:"operation_name,omitempty" json:"operation_name,omitempty"`
	Fields        []string `yaml:"fields,omitempty" json:"fields,omitempty"`
}

// GraphQLOperation is the parsed policy-visible request shape.
type GraphQLOperation struct {
	OperationType      string
	OperationName      string
	Fields             []string
	Persisted          bool
	PersistedQueryHash string
	PersistedQueryID   string
}

// MCPConfig mirrors OpenShell's endpoint-level MCP options.
type MCPConfig struct {
	Versions                []string `yaml:"versions,omitempty" json:"versions,omitempty"`
	MaxBodyBytes            uint32   `yaml:"max_body_bytes,omitempty" json:"max_body_bytes,omitempty"`
	StrictToolNames         *bool    `yaml:"strict_tool_names,omitempty" json:"strict_tool_names,omitempty"`
	AllowAllKnownMCPMethods *bool    `yaml:"allow_all_known_mcp_methods,omitempty" json:"allow_all_known_mcp_methods,omitempty"`
}

// JSONRPCConfig mirrors the OpenShell generic JSON-RPC endpoint options.
type JSONRPCConfig struct {
	MaxBodyBytes *uint32 `yaml:"max_body_bytes,omitempty" json:"max_body_bytes,omitempty"`
}

// Display is the noVNC surface (cautem product extension).
type Display struct {
	Mode    string `yaml:"mode,omitempty" json:"mode,omitempty"` // none | novnc
	Publish string `yaml:"publish,omitempty" json:"publish,omitempty"`
	Port    int    `yaml:"port,omitempty" json:"port,omitempty"`
	Auth    string `yaml:"auth,omitempty" json:"auth,omitempty"`
	Browser string `yaml:"browser,omitempty" json:"browser,omitempty"`
}

// Credentials controls host-side env injection (cautem product extension).
type Credentials struct {
	EnvAllow    []string `yaml:"env_allow,omitempty" json:"env_allow,omitempty"`
	WriteToDisk bool     `yaml:"write_to_disk,omitempty" json:"write_to_disk,omitempty"`
}

// Load reads and parses a policy YAML file.
func Load(path string) (Document, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Document{}, err
	}
	return Parse(b)
}

// Parse unmarshals OpenShell-shaped policy YAML.
func Parse(data []byte) (Document, error) {
	if err := rejectRemovedSchema(data); err != nil {
		return Document{}, err
	}
	if _, err := parseRequiredVersion(data); err != nil {
		return Document{}, err
	}
	var d Document
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return Document{}, fmt.Errorf("policy: parse: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Document{}, fmt.Errorf("policy: parse: multiple YAML documents are not supported")
		}
		return Document{}, fmt.Errorf("policy: parse trailing document: %w", err)
	}
	if err := validateNetworkMiddlewareSchema(data); err != nil {
		return Document{}, err
	}
	return d, nil
}

// parseRequiredVersion mirrors the pinned OpenShell PolicyFile's required u32
// field. yaml.v3 accepts missing/null scalar fields into Go's zero values, so
// validate presence, duplicate keys and the unsigned width before decoding the
// full document.
func parseRequiredVersion(data []byte) (uint32, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return 0, nil // The strict document decoder below reports syntax errors.
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return 0, fmt.Errorf("policy: root must be a mapping with required version")
	}
	var versionNode *yaml.Node
	seenFields := make(map[string]struct{}, len(root.Content[0].Content)/2)
	content := root.Content[0].Content
	for i := 0; i+1 < len(content); i += 2 {
		key, value := content[i], content[i+1]
		if key.Kind == yaml.ScalarNode && key.Tag == "!!str" {
			if _, duplicate := seenFields[key.Value]; duplicate {
				return 0, fmt.Errorf("policy: duplicate field %q", key.Value)
			}
			seenFields[key.Value] = struct{}{}
			if key.Value == "version" {
				versionNode = value
			}
		}
	}
	if versionNode == nil {
		return 0, fmt.Errorf("policy: missing required field %q", "version")
	}
	if versionNode.Kind != yaml.ScalarNode || versionNode.Tag != "!!int" {
		return 0, fmt.Errorf("policy: version must be an unsigned 32-bit integer")
	}
	var version uint32
	if err := versionNode.Decode(&version); err != nil {
		return 0, fmt.Errorf("policy: version must be an unsigned 32-bit integer")
	}
	return version, nil
}

// rejectRemovedSchema fails closed on the removed keys (filesystem / network).
func rejectRemovedSchema(data []byte) error {
	var probe struct {
		Filesystem yaml.Node `yaml:"filesystem"`
		Network    yaml.Node `yaml:"network"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return nil
	}
	if probe.Filesystem.Kind != 0 {
		return fmt.Errorf("policy: key \"filesystem\" removed; use OpenShell naming filesystem_policy / landlock")
	}
	if probe.Network.Kind != 0 {
		return fmt.Errorf("policy: key \"network\" removed; use OpenShell naming network_policies")
	}
	return nil
}

func validateNetworkMiddlewareSchema(data []byte) error {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil || len(document.Content) == 0 {
		return nil // The strict document decoder above reports syntax and shape errors.
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil
	}
	middlewares, ok, err := yamlMappingField(root, "network_middlewares", "policy")
	if err != nil || !ok {
		return err
	}
	if middlewares.Kind != yaml.MappingNode {
		return fmt.Errorf("policy: network_middlewares must be a mapping")
	}
	seen := map[string]struct{}{}
	for i := 0; i < len(middlewares.Content); i += 2 {
		key, value := middlewares.Content[i], middlewares.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return fmt.Errorf("policy: network_middlewares keys must be strings")
		}
		if _, duplicate := seen[key.Value]; duplicate {
			return fmt.Errorf("policy: network_middlewares has duplicate key %q", key.Value)
		}
		seen[key.Value] = struct{}{}
		if err := validateNetworkMiddlewareEntry(key.Value, value); err != nil {
			return err
		}
	}
	return nil
}

func validateNetworkMiddlewareEntry(name string, node *yaml.Node) error {
	prefix := fmt.Sprintf("policy: network_middlewares.%s", name)
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("%s must be an object", prefix)
	}
	allowed := map[string]bool{"name": true, "middleware": true, "order": true, "config": true, "on_error": true, "endpoints": true}
	fields := map[string]*yaml.Node{}
	for i := 0; i < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return fmt.Errorf("%s field names must be strings", prefix)
		}
		if !allowed[key.Value] {
			return fmt.Errorf("%s has unknown field %q", prefix, key.Value)
		}
		if _, duplicate := fields[key.Value]; duplicate {
			return fmt.Errorf("%s has duplicate field %q", prefix, key.Value)
		}
		fields[key.Value] = value
	}
	if _, ok := fields["middleware"]; !ok {
		return fmt.Errorf("%s.middleware is required", prefix)
	}
	for _, key := range []string{"name", "middleware", "on_error"} {
		if value, ok := fields[key]; ok && (value.Kind != yaml.ScalarNode || value.Tag != "!!str") {
			return fmt.Errorf("%s.%s must be a string", prefix, key)
		}
	}
	if order, ok := fields["order"]; ok {
		var value int32
		if order.Kind != yaml.ScalarNode || order.Tag != "!!int" || order.Decode(&value) != nil {
			return fmt.Errorf("%s.order must be an i32", prefix)
		}
	}
	if config, ok := fields["config"]; ok {
		if config.Kind != yaml.MappingNode {
			return fmt.Errorf("%s.config must be an object", prefix)
		}
		if err := validateJSONCompatibleYAML(config, 0); err != nil {
			return fmt.Errorf("%s.config: %w", prefix, err)
		}
	}
	if endpoints, ok := fields["endpoints"]; ok {
		if endpoints.Kind != yaml.MappingNode {
			return fmt.Errorf("%s.endpoints must be an object", prefix)
		}
		selectorFields := map[string]*yaml.Node{}
		for i := 0; i < len(endpoints.Content); i += 2 {
			key, value := endpoints.Content[i], endpoints.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" || key.Value != "include" && key.Value != "exclude" {
				return fmt.Errorf("%s.endpoints has unknown field", prefix)
			}
			if _, duplicate := selectorFields[key.Value]; duplicate {
				return fmt.Errorf("%s.endpoints has duplicate field %q", prefix, key.Value)
			}
			selectorFields[key.Value] = value
			if value.Kind != yaml.SequenceNode {
				return fmt.Errorf("%s.endpoints.%s must be an array of strings", prefix, key.Value)
			}
			for _, pattern := range value.Content {
				if pattern.Kind != yaml.ScalarNode || pattern.Tag != "!!str" {
					return fmt.Errorf("%s.endpoints.%s entries must be strings", prefix, key.Value)
				}
			}
		}
	}
	return nil
}

func validateJSONCompatibleYAML(node *yaml.Node, depth int) error {
	if depth > 64 {
		return fmt.Errorf("maximum nesting depth exceeded")
	}
	switch node.Kind {
	case yaml.AliasNode:
		if node.Alias == nil {
			return fmt.Errorf("invalid alias")
		}
		return validateJSONCompatibleYAML(node.Alias, depth+1)
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!str", "!!int", "!!float", "!!bool", "!!null":
			return nil
		default:
			return fmt.Errorf("value with YAML tag %q is not JSON-compatible", node.Tag)
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if err := validateJSONCompatibleYAML(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return fmt.Errorf("object keys must be strings")
			}
			if err := validateJSONCompatibleYAML(value, depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported YAML node")
	}
}

func yamlMappingField(mapping *yaml.Node, name, context string) (*yaml.Node, bool, error) {
	var found *yaml.Node
	for i := 0; i < len(mapping.Content); i += 2 {
		key, value := mapping.Content[i], mapping.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			continue
		}
		if key.Value == name {
			if found != nil {
				return nil, false, fmt.Errorf("policy: %s has duplicate field %q", context, name)
			}
			found = value
		}
	}
	return found, found != nil, nil
}

// Validate performs fail-closed structural checks.
func (d Document) Validate() error {
	if d.Landlock != nil {
		c := strings.ToLower(strings.TrimSpace(d.Landlock.Compatibility))
		if c == "" {
			c = "best_effort"
		}
		switch c {
		case "best_effort", "hard_requirement":
		default:
			return fmt.Errorf("policy: landlock.compatibility must be best_effort|hard_requirement")
		}
	}
	if d.FilesystemPolicy != nil {
		paths := append(append([]string{}, d.FilesystemPolicy.ReadOnly...), d.FilesystemPolicy.ReadWrite...)
		if len(paths) > 256 {
			return fmt.Errorf("policy: too many filesystem paths (%d)", len(paths))
		}
		for _, p := range paths {
			if err := validateFSPath(p); err != nil {
				return err
			}
		}
		if slices.Contains(d.FilesystemPolicy.ReadWrite, "/") {
			return fmt.Errorf("policy: filesystem_policy.read_write must not include '/'")
		}
	}
	if d.Process != nil {
		if err := validateProcessIdentity("run_as_user", d.Process.RunAsUser); err != nil {
			return err
		}
		if err := validateProcessIdentity("run_as_group", d.Process.RunAsGroup); err != nil {
			return err
		}
	}
	for key, rule := range d.NetworkPolicies {
		name := rule.Name
		if name == "" {
			name = key
		}
		bins := binaryPaths(rule.Binaries)
		for j, ep := range rule.Endpoints {
			r := ep
			if r.ID == "" {
				r.ID = name
			}
			if len(r.Binaries) == 0 && len(bins) > 0 {
				r.Binaries = bins
			}
			prefix := fmt.Sprintf("network_policies[%q].endpoints[%d]", key, j)
			if err := validateAllowRule(prefix, r); err != nil {
				return err
			}
		}
		for j, bin := range rule.Binaries {
			if !path.IsAbs(bin.Path) || hasDotSegment(bin.Path) {
				return fmt.Errorf("policy: network_policies[%q].binaries[%d]: absolute path without dot segments required", key, j)
			}
		}
	}
	if d.Inference != nil {
		if _, err := ExpandInferenceRules(d.Inference); err != nil {
			return err
		}
		for i, rule := range d.Inference.Allow {
			if rule.CredentialBinding != nil {
				return fmt.Errorf("policy: inference.allow[%d]: credential_binding is only valid on network_policies endpoints", i)
			}
			if err := validateAllowRule(fmt.Sprintf("inference.allow[%d]", i), rule); err != nil {
				return err
			}
		}
	}
	if d.Display != nil {
		mode := strings.ToLower(strings.TrimSpace(d.Display.Mode))
		if mode == "" {
			mode = "none"
		}
		switch mode {
		case "none", "novnc":
		default:
			return fmt.Errorf("policy: display.mode must be none|novnc")
		}
	}
	for i, b := range d.Binaries {
		b = strings.TrimSpace(b)
		if b == "" {
			return fmt.Errorf("policy: binaries[%d]: empty", i)
		}
		if !path.IsAbs(b) || hasDotSegment(b) {
			return fmt.Errorf("policy: binaries[%d]: must be absolute without dot segments", i)
		}
	}
	if err := validateNetworkMiddlewares(d.NetworkMiddlewares, d.NetworkPolicies); err != nil {
		return err
	}
	return nil
}

func validateNetworkMiddlewares(middlewares map[string]yaml.Node, networkPolicies map[string]NetworkPolicy) error {
	const maxConfigs = 10
	const maxSelectorPatterns = 32
	if len(middlewares) > maxConfigs {
		return fmt.Errorf("policy: network_middlewares has %d entries; maximum is %d", len(middlewares), maxConfigs)
	}
	type endpointSelector struct {
		Include []string `yaml:"include"`
		Exclude []string `yaml:"exclude"`
	}
	type middlewareConfig struct {
		Middleware string            `yaml:"middleware"`
		Order      int32             `yaml:"order"`
		OnError    string            `yaml:"on_error"`
		Endpoints  *endpointSelector `yaml:"endpoints"`
	}
	orders := make(map[int32]string, len(middlewares))
	for name, node := range middlewares {
		prefix := fmt.Sprintf("policy: network_middlewares[%q]", name)
		if name == "" {
			return fmt.Errorf("%s: name must not be empty", prefix)
		}
		var config middlewareConfig
		if err := node.Decode(&config); err != nil {
			return fmt.Errorf("%s: %w", prefix, err)
		}
		if config.Middleware == "" {
			return fmt.Errorf("%s.middleware must not be empty", prefix)
		}
		if previous, exists := orders[config.Order]; exists {
			return fmt.Errorf("policy: network_middlewares %q and %q share order %d", previous, name, config.Order)
		}
		orders[config.Order] = name
		if config.OnError != "" && config.OnError != "fail_closed" && config.OnError != "fail_open" {
			return fmt.Errorf("%s.on_error must be fail_closed|fail_open", prefix)
		}
		if config.Endpoints == nil {
			return fmt.Errorf("%s.endpoints is required", prefix)
		}
		if len(config.Endpoints.Include) == 0 {
			return fmt.Errorf("%s.endpoints.include must contain at least one host pattern", prefix)
		}
		patternCount := len(config.Endpoints.Include) + len(config.Endpoints.Exclude)
		if patternCount > maxSelectorPatterns {
			return fmt.Errorf("%s.endpoints has %d patterns; maximum is %d", prefix, patternCount, maxSelectorPatterns)
		}
		includes := make([]hostpattern.Pattern, 0, len(config.Endpoints.Include))
		excludes := make([]hostpattern.Pattern, 0, len(config.Endpoints.Exclude))
		for _, pattern := range config.Endpoints.Include {
			compiled, err := hostpattern.Parse(pattern)
			if err != nil {
				return fmt.Errorf("%s.endpoints has invalid host pattern %q: %w", prefix, pattern, err)
			}
			includes = append(includes, compiled)
		}
		for _, pattern := range config.Endpoints.Exclude {
			compiled, err := hostpattern.Parse(pattern)
			if err != nil {
				return fmt.Errorf("%s.endpoints has invalid host pattern %q: %w", prefix, pattern, err)
			}
			excludes = append(excludes, compiled)
		}
		if config.OnError == "" || config.OnError == "fail_closed" {
			for policyKey, networkPolicy := range networkPolicies {
				policyName := networkPolicy.Name
				if policyName == "" {
					policyName = policyKey
				}
				for _, endpoint := range networkPolicy.Endpoints {
					if endpoint.TLS != "skip" {
						continue
					}
					candidate, err := hostpattern.Parse(endpoint.Host)
					if err == nil && hostpattern.SelectorMayMatchPattern(includes, excludes, candidate) {
						return fmt.Errorf("policy: middleware %q may inspect endpoint %q in network policy %q with tls: skip", name, endpoint.Host, policyName)
					}
				}
			}
		}
	}
	return nil
}

func binaryPaths(bins []NetworkBinary) []string {
	var out []string
	for _, b := range bins {
		if p := strings.TrimSpace(b.Path); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// EffectivePorts returns ports, falling back to single Port.
func (r AllowRule) EffectivePorts() []int {
	if len(r.Ports) > 0 {
		return r.Ports
	}
	if r.Port != 0 {
		return []int{r.Port}
	}
	return nil
}

// TLSWarnings returns OpenShell-compatible advisory messages for deprecated
// TLS aliases and for tls:skip combined with L7 rules on port 443.
func (d Document) TLSWarnings() []string {
	var out []string
	seen := map[string]struct{}{}
	add := func(msg string) {
		if _, ok := seen[msg]; ok {
			return
		}
		seen[msg] = struct{}{}
		out = append(out, msg)
	}
	keys := make([]string, 0, len(d.NetworkPolicies))
	for k := range d.NetworkPolicies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		np := d.NetworkPolicies[key]
		locBase := "network_policies." + key
		if np.Name != "" {
			locBase = "network_policies." + np.Name
		}
		for i, ep := range np.Endpoints {
			loc := fmt.Sprintf("%s.endpoints[%d]", locBase, i)
			tlsMode := strings.ToLower(strings.TrimSpace(ep.TLS))
			proto := strings.ToLower(strings.TrimSpace(ep.Protocol))
			switch tlsMode {
			case TLSTerminate:
				add("'tls: terminate' is deprecated; TLS termination is now automatic. Use 'tls: skip' to explicitly disable. This field will be removed in a future version.")
			case TLSPassthrough:
				add("'tls: passthrough' is deprecated; TLS termination is now automatic. Use 'tls: skip' to explicitly disable. This field will be removed in a future version.")
			}
			if tlsMode == "skip" && proto != "" {
				for _, port := range ep.EffectivePorts() {
					if port == 443 {
						add(fmt.Sprintf("%s: 'tls: skip' with L7 rules on port 443 — L7 inspection cannot work on encrypted traffic", loc))
						break
					}
				}
			}
		}
	}
	return out
}

// HardenMode returns best_effort|required from landlock.compatibility.
func (d Document) HardenMode() string {
	if d.Landlock == nil {
		return "best_effort"
	}
	c := strings.ToLower(strings.TrimSpace(d.Landlock.Compatibility))
	if c == "hard_requirement" {
		return "required"
	}
	return "best_effort"
}

// FSRead returns filesystem_policy.read_only (nil-safe).
func (d Document) FSRead() []string {
	if d.FilesystemPolicy == nil {
		return nil
	}
	return d.FilesystemPolicy.ReadOnly
}

// FSWrite returns filesystem_policy.read_write (nil-safe).
func (d Document) FSWrite() []string {
	if d.FilesystemPolicy == nil {
		return nil
	}
	return d.FilesystemPolicy.ReadWrite
}

// IncludeWorkdir reports filesystem_policy.include_workdir.
func (d Document) IncludeWorkdir() bool {
	return d.FilesystemPolicy == nil || d.FilesystemPolicy.IncludeWorkdirEnabled()
}

// ProcessUser returns process.run_as_user.
func (d Document) ProcessUser() string {
	if d.Process == nil {
		return ""
	}
	return d.Process.RunAsUser
}

// ProcessGroup returns process.run_as_group.
func (d Document) ProcessGroup() string {
	if d.Process == nil {
		return ""
	}
	return d.Process.RunAsGroup
}

// NetworkAllows flattens network_policies endpoints (no inference).
func (d Document) NetworkAllows() []AllowRule {
	if len(d.NetworkPolicies) == 0 {
		return nil
	}
	// Stable-ish order: sort keys.
	keys := make([]string, 0, len(d.NetworkPolicies))
	for k := range d.NetworkPolicies {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []AllowRule
	for _, key := range keys {
		rule := d.NetworkPolicies[key]
		name := rule.Name
		if name == "" {
			name = key
		}
		bins := binaryPaths(rule.Binaries)
		for _, ep := range rule.Endpoints {
			r := ep
			r.networkPolicyKey = key
			r.networkPolicyName = rule.Name
			if r.ID == "" {
				r.ID = name
			}
			if len(r.Binaries) == 0 && len(bins) > 0 {
				r.Binaries = append([]string{}, bins...)
			}
			out = append(out, r)
		}
	}
	return out
}

// AllowRules returns network_policies endpoints plus expanded inference rules.
func (d Document) AllowRules() []AllowRule {
	out := d.NetworkAllows()
	inf, err := ExpandInferenceRules(d.Inference)
	if err == nil {
		out = append(out, inf...)
	}
	return out
}

// SetNetworkAllows replaces network_policies with one entry per allow rule id.
func (d *Document) SetNetworkAllows(rules []AllowRule) {
	if len(rules) == 0 {
		d.NetworkPolicies = nil
		return
	}
	out := make(map[string]NetworkPolicy, len(rules))
	for i, r := range rules {
		key := strings.TrimSpace(r.networkPolicyKey)
		if key == "" {
			key = strings.TrimSpace(r.ID)
		}
		if key == "" {
			key = fmt.Sprintf("rule_%d", i)
		}
		name := strings.TrimSpace(r.networkPolicyName)
		if name == "" {
			name = key
		}
		ep := r
		ep.ID = ""
		ep.networkPolicyKey = key
		ep.networkPolicyName = name
		bins := r.Binaries
		ep.Binaries = nil
		var nb []NetworkBinary
		for _, b := range bins {
			nb = append(nb, NetworkBinary{Path: b})
		}
		if existing, ok := out[key]; ok {
			existing.Endpoints = append(existing.Endpoints, ep)
			if len(existing.Binaries) == 0 {
				existing.Binaries = nb
			}
			out[key] = existing
			continue
		}
		out[key] = NetworkPolicy{
			Name:      name,
			Endpoints: []AllowRule{ep},
			Binaries:  nb,
		}
	}
	d.NetworkPolicies = out
}

// Enforcement modes.
const (
	EnforcementEnforce = "enforce"
	EnforcementAudit   = "audit"
)

// IsAudit reports whether L7 violations should be logged and allowed.
func (r AllowRule) IsAudit() bool {
	return strings.EqualFold(strings.TrimSpace(r.Enforcement), EnforcementAudit)
}

// ValidateAllowRule validates one network allow entry (exported for provider profiles).
func ValidateAllowRule(prefix string, rule AllowRule) error {
	return validateAllowRule(prefix, rule)
}

func validateAllowRule(prefix string, rule AllowRule) error {
	if strings.TrimSpace(rule.Host) == "" && len(rule.AllowedIPs) == 0 {
		return fmt.Errorf("policy: %s: host or allowed_ips required", prefix)
	}
	if binding := rule.CredentialBinding; binding != nil {
		if strings.TrimSpace(rule.Host) == "" {
			return fmt.Errorf("policy: %s: credential-bound endpoint must define a host", prefix)
		}
		provider := strings.TrimSpace(binding.Provider)
		if provider == "" {
			return fmt.Errorf("policy: %s.credential_binding.provider required", prefix)
		}
		if provider != binding.Provider {
			return fmt.Errorf("policy: %s.credential_binding.provider must not contain leading or trailing whitespace", prefix)
		}
	}
	if rule.RequestBodyCredentialRewrite && strings.ToLower(strings.TrimSpace(rule.Protocol)) != ProtocolREST {
		return fmt.Errorf("policy: %s: request_body_credential_rewrite requires protocol: rest", prefix)
	}
	if rule.RequestBodyCredentialRewrite && strings.TrimSpace(rule.CredentialSigning) != "" {
		return fmt.Errorf("policy: %s: credential_signing and request_body_credential_rewrite are mutually exclusive", prefix)
	}
	ports := rule.EffectivePorts()
	if len(ports) == 0 {
		return fmt.Errorf("policy: %s: port or ports required", prefix)
	}
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("policy: %s: invalid port %d", prefix, p)
		}
	}
	if rule.Host != "" && isTLDWildcard(rule.Host) {
		return fmt.Errorf("policy: %s: TLD wildcard host %q rejected", prefix, rule.Host)
	}
	enf := strings.ToLower(strings.TrimSpace(rule.Enforcement))
	switch enf {
	case "", EnforcementEnforce, EnforcementAudit:
	default:
		return fmt.Errorf("policy: %s: enforcement must be enforce|audit (got %q)", prefix, rule.Enforcement)
	}
	for j, cidr := range rule.AllowedIPs {
		if err := validateCIDROrIP(fmt.Sprintf("%s.allowed_ips[%d]", prefix, j), cidr); err != nil {
			return err
		}
	}
	return validateL7(prefix, rule)
}

func validateL7(prefix string, rule AllowRule) error {
	proto := strings.ToLower(strings.TrimSpace(rule.Protocol))
	access := strings.ToLower(strings.TrimSpace(rule.Access))
	if rule.Rules != nil && len(rule.Rules) == 0 {
		return fmt.Errorf("policy: %s.rules must not be empty", prefix)
	}
	if rule.DenyRules != nil && len(rule.DenyRules) == 0 {
		return fmt.Errorf("policy: %s.deny_rules must not be empty", prefix)
	}

	switch proto {
	case "", ProtocolREST, ProtocolWebsocket, ProtocolGraphQL, ProtocolSQL, ProtocolTCP, ProtocolMCP, ProtocolJSONRPC:
	default:
		return fmt.Errorf("policy: %s: protocol must be tcp|rest|websocket|graphql|sql|json-rpc|mcp (got %q)", prefix, rule.Protocol)
	}
	if rule.MCP != nil && proto != ProtocolMCP {
		return fmt.Errorf("policy: %s: mcp options require protocol: mcp", prefix)
	}
	if rule.JSONRPC != nil && rule.JSONRPC.MaxBodyBytes != nil && *rule.JSONRPC.MaxBodyBytes == 0 {
		return fmt.Errorf("policy: %s.json_rpc.max_body_bytes must be a positive integer", prefix)
	}
	if rule.GraphQLMaxBodyBytes != nil && *rule.GraphQLMaxBodyBytes == 0 {
		return fmt.Errorf("policy: %s.graphql_max_body_bytes must be a positive integer", prefix)
	}
	if mode := rule.PersistedQueries; mode != "" && mode != "deny" && mode != "allow_registered" {
		return fmt.Errorf("policy: %s.persisted_queries must be deny|allow_registered", prefix)
	}
	for id, operation := range rule.GraphQLPersistedQueries {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("policy: %s.graphql_persisted_queries contains an empty id", prefix)
		}
		if operation.OperationType != "query" && operation.OperationType != "mutation" && operation.OperationType != "subscription" {
			return fmt.Errorf("policy: %s.graphql_persisted_queries[%q].operation_type must be query|mutation|subscription", prefix, id)
		}
		if err := validateGraphQLFields(fmt.Sprintf("%s.graphql_persisted_queries[%q].fields", prefix, id), operation.Fields); err != nil {
			return err
		}
	}
	if rule.MCP != nil {
		if rule.MCP.Versions != nil && len(rule.MCP.Versions) == 0 {
			return fmt.Errorf("policy: %s.mcp.versions: must not be empty when specified", prefix)
		}
		seenVersions := make(map[string]struct{}, len(rule.MCP.Versions))
		for i, version := range rule.MCP.Versions {
			if version != "2025-03-26" && version != "2025-06-18" && version != "2025-11-25" {
				return fmt.Errorf("policy: %s.mcp.versions[%d]: unsupported MCP version %q", prefix, i, version)
			}
			if _, exists := seenVersions[version]; exists {
				return fmt.Errorf("policy: %s.mcp.versions[%d]: duplicate MCP version %q", prefix, i, version)
			}
			seenVersions[version] = struct{}{}
		}
	}
	// OpenShell treats only "skip" specially. "terminate" and "passthrough"
	// are deprecated aliases for automatic TLS handling; other string values
	// also follow the pinned parser's Auto fallback.
	switch access {
	case "", AccessReadOnly, AccessReadWrite, AccessFull:
	default:
		return fmt.Errorf("policy: %s: access must be read-only|read-write|full (got %q)", prefix, rule.Access)
	}
	if access != "" && len(rule.Rules) > 0 {
		return fmt.Errorf("policy: %s: access and rules are mutually exclusive", prefix)
	}
	if rule.HasL7Policy() {
		switch proto {
		case ProtocolREST, ProtocolWebsocket, ProtocolGraphQL, ProtocolSQL, ProtocolMCP, ProtocolJSONRPC:
		case "":
			return fmt.Errorf("policy: %s: L7 fields require protocol", prefix)
		default:
			return fmt.Errorf("policy: %s: protocol %q unsupported", prefix, proto)
		}
		if proto == ProtocolTCP {
			return fmt.Errorf("policy: %s: protocol tcp does not support access, rules, or deny_rules; remove those L7 fields", prefix)
		}
		if proto == ProtocolSQL && !rule.IsAudit() {
			return fmt.Errorf("policy: %s: SQL enforcement requires full SQL parsing (not available in v1). Use enforcement: audit", prefix)
		}
		if proto == ProtocolSQL {
			for i, item := range rule.Rules {
				if item.Allow == nil || strings.TrimSpace(item.Allow.Command) == "" {
					return fmt.Errorf("policy: %s.rules[%d].allow.command required for sql", prefix, i)
				}
			}
			for i, item := range rule.DenyRules {
				if strings.TrimSpace(item.Command) == "" {
					return fmt.Errorf("policy: %s.deny_rules[%d].command required for sql", prefix, i)
				}
			}
		}
		allowAllMCPMethods := proto == ProtocolMCP && rule.MCP != nil && rule.MCP.AllowAllKnownMCPMethods != nil && *rule.MCP.AllowAllKnownMCPMethods
		methodProtocol := proto == ProtocolMCP || proto == ProtocolJSONRPC
		if access == "" && len(rule.Rules) == 0 && len(rule.DenyRules) == 0 && !allowAllMCPMethods {
			return fmt.Errorf("policy: %s: protocol %q requires access or rules", prefix, proto)
		}
		if access != "" {
			if methodProtocol {
				return fmt.Errorf("policy: %s: access presets are not supported for %s; specify method rules", prefix, proto)
			}
			if rule.ExpandedL7Allows() == nil {
				return fmt.Errorf("policy: %s: invalid access %q", prefix, rule.Access)
			}
		}
		strictToolNames := rule.MCP == nil || rule.MCP.StrictToolNames == nil || *rule.MCP.StrictToolNames
		for i, deny := range rule.DenyRules {
			if err := validateQuerySelectors(deny.Query, proto); err != nil {
				return fmt.Errorf("policy: %s.deny_rules[%d]: %w", prefix, i, err)
			}
			if err := validateToolSelector(deny.Tool, deny.Params, proto, deny.Method, strictToolNames); err != nil {
				return fmt.Errorf("policy: %s.deny_rules[%d]: %w", prefix, i, err)
			}
		}
		if proto == ProtocolSQL {
			for i, item := range rule.Rules {
				a := item.Allow
				if a != nil && (a.Method != "" || a.Path != "" || len(a.Query) > 0 || a.Tool != nil || len(a.Params) > 0 || a.OperationType != "" || a.OperationName != "" || len(a.Fields) > 0) {
					return fmt.Errorf("policy: %s.rules[%d]: SQL rules support command only", prefix, i)
				}
			}
			for i, item := range rule.DenyRules {
				if item.Method != "" || item.Path != "" || len(item.Query) > 0 || item.Tool != nil || len(item.Params) > 0 || item.OperationType != "" || item.OperationName != "" || len(item.Fields) > 0 {
					return fmt.Errorf("policy: %s.deny_rules[%d]: SQL rules support command only", prefix, i)
				}
			}
		}
		for i, r := range rule.Rules {
			if r.Allow == nil {
				return fmt.Errorf("policy: %s.rules[%d]: allow required", prefix, i)
			}
			if err := validateQuerySelectors(r.Allow.Query, proto); err != nil {
				return fmt.Errorf("policy: %s.rules[%d]: %w", prefix, i, err)
			}
			if err := validateToolSelector(r.Allow.Tool, r.Allow.Params, proto, r.Allow.Method, strictToolNames); err != nil {
				return fmt.Errorf("policy: %s.rules[%d]: %w", prefix, i, err)
			}
			if methodProtocol && strings.TrimSpace(r.Allow.Method) == "" && !allowAllMCPMethods {
				return fmt.Errorf("policy: %s.rules[%d].allow.method required for %s", prefix, i, proto)
			}
			if proto == ProtocolJSONRPC {
				method := strings.TrimSpace(r.Allow.Method)
				if method != "*" && strings.ContainsAny(method, "*?[]") {
					return fmt.Errorf("policy: %s.rules[%d].allow.method: JSON-RPC supports exact methods or *", prefix, i)
				}
				if r.Allow.Tool != nil {
					return fmt.Errorf("policy: %s.rules[%d].allow.tool is only valid for MCP", prefix, i)
				}
			}
			if proto == ProtocolGraphQL || (proto == ProtocolWebsocket && hasGraphQLSelectors(r.Allow.OperationType, r.Allow.OperationName, r.Allow.Fields)) {
				if err := validateGraphQLRule(fmt.Sprintf("%s.rules[%d].allow", prefix, i), r.Allow.OperationType, r.Allow.Fields); err != nil {
					return err
				}
				if r.Allow.Tool != nil {
					return fmt.Errorf("policy: %s.rules[%d].allow.tool is only valid for MCP", prefix, i)
				}
			}
		}
		if proto == ProtocolJSONRPC {
			for i, deny := range rule.DenyRules {
				method := strings.TrimSpace(deny.Method)
				if method == "" {
					return fmt.Errorf("policy: %s.deny_rules[%d].method required for json-rpc", prefix, i)
				}
				if method != "*" && strings.ContainsAny(method, "*?[]") {
					return fmt.Errorf("policy: %s.deny_rules[%d].method: JSON-RPC supports exact methods or *", prefix, i)
				}
				if deny.Tool != nil {
					return fmt.Errorf("policy: %s.deny_rules[%d].tool is only valid for MCP", prefix, i)
				}
			}
		}
		if proto == ProtocolGraphQL || proto == ProtocolWebsocket {
			for i, deny := range rule.DenyRules {
				if proto == ProtocolGraphQL || hasGraphQLSelectors(deny.OperationType, deny.OperationName, deny.Fields) {
					if err := validateGraphQLRule(fmt.Sprintf("%s.deny_rules[%d]", prefix, i), deny.OperationType, deny.Fields); err != nil {
						return err
					}
					if deny.Tool != nil {
						return fmt.Errorf("policy: %s.deny_rules[%d].tool is only valid for MCP", prefix, i)
					}
				}
			}
		}
		// TLS is auto-detected for L7 endpoints by OpenShell. Explicit skip is
		// accepted as an opt-out even though encrypted L7 rules cannot run then.
	}
	return nil
}

func hasGraphQLSelectors(operationType, operationName string, fields []string) bool {
	return operationType != "" || operationName != "" || len(fields) > 0
}

func validateGraphQLRule(prefix, operationType string, fields []string) error {
	if operationType == "" {
		return fmt.Errorf("policy: %s.operation_type required for GraphQL rules", prefix)
	}
	switch strings.ToLower(operationType) {
	case "query", "mutation", "subscription", "*":
	default:
		return fmt.Errorf("policy: %s.operation_type must be query|mutation|subscription|*", prefix)
	}
	return validateGraphQLFields(prefix+".fields", fields)
}

func validateGraphQLFields(prefix string, fields []string) error {
	if fields != nil && len(fields) == 0 {
		return fmt.Errorf("policy: %s must not be empty when specified", prefix)
	}
	for i, field := range fields {
		if strings.TrimSpace(field) == "" {
			return fmt.Errorf("policy: %s[%d] must not be empty", prefix, i)
		}
	}
	return nil
}

func validateCIDROrIP(prefix, s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("policy: %s: empty", prefix)
	}
	if _, _, err := net.ParseCIDR(s); err == nil {
		return nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return nil
	}
	return fmt.Errorf("policy: %s: invalid IP/CIDR %q", prefix, s)
}

func validateFSPath(p string) error {
	if p == "" {
		return fmt.Errorf("policy: empty filesystem path")
	}
	if len(p) > 4096 {
		return fmt.Errorf("policy: filesystem path too long (%d)", len(p))
	}
	if !path.IsAbs(p) {
		return fmt.Errorf("policy: filesystem path must be absolute: %q", p)
	}
	if hasDotSegment(p) {
		return fmt.Errorf("policy: filesystem path must not contain dot segments: %q", p)
	}
	return nil
}

func hasDotSegment(p string) bool {
	for segment := range strings.SplitSeq(p, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

func validateProcessIdentity(field, value string) error {
	if value == "" {
		return nil
	}
	if value == "sandbox" {
		return nil
	}
	n, err := strconv.ParseUint(value, 10, 32)
	if err == nil && n > 0 && n < (1<<32)-1 {
		return nil
	}
	return fmt.Errorf("policy: process.%s must be 'sandbox' or a numeric UID/GID in range [1, 4294967294], got %q", field, value)
}

func isTLDWildcard(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "*" || h == "**" {
		return true
	}
	if strings.HasPrefix(h, "*.") && !strings.Contains(h[2:], ".") {
		return true
	}
	if strings.HasPrefix(h, "**.") && !strings.Contains(h[3:], ".") {
		return true
	}
	return false
}
