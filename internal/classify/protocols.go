// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package classify

import (
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"sync"

	classifydata "github.com/karalabe/uniblue/classify"
	"github.com/karalabe/uniblue/internal/checks"
	"gopkg.in/yaml.v3"
)

// TransportClass describes the protection associated with a protocol name.
type TransportClass string

const (
	// TransportE2E identifies protocols with native end-to-end encryption.
	TransportE2E TransportClass = "e2e"
	// TransportTLS identifies a TLS-protected protocol variant.
	TransportTLS TransportClass = "tls"
	// TransportCleartextAuth identifies cleartext services with an authentication mechanism.
	TransportCleartextAuth TransportClass = "cleartext-auth"
	// TransportCleartextNoAuth identifies cleartext services with anonymous baseline operations.
	TransportCleartextNoAuth TransportClass = "cleartext-noauth"
	// TransportUnknown leaves protection to endpoint-specific evidence.
	TransportUnknown TransportClass = "unknown"
)

// AuthModel describes the authentication normally available to a protocol client.
type AuthModel string

const (
	// AuthRequired means the service requires client authentication.
	AuthRequired AuthModel = "required"
	// AuthOptional means the service can allow authenticated or anonymous clients.
	AuthOptional AuthModel = "optional"
	// AuthNone means the protocol provides no client authentication.
	AuthNone AuthModel = "none"
	// AuthDevicePaired identifies protocols with a device pairing or enrollment step.
	AuthDevicePaired AuthModel = "device-paired"
)

// ProtocolTrait describes protocol defaults for a service identified by name.
type ProtocolTrait struct {
	// TransportClass describes transport protection, or unknown when it depends on negotiation.
	TransportClass TransportClass `yaml:"transport_class"`
	// AuthModel describes how clients normally authenticate to the service.
	AuthModel AuthModel `yaml:"auth_model"`
	// AnonGrants lists baseline anonymous operations, subject to the endpoint's access policy.
	AnonGrants []checks.GrantEffect `yaml:"anon_grants,omitempty"`
	// Hub identifies protocols commonly used to broker access to other devices.
	Hub bool `yaml:"hub"`
}

// LoadProtocols reads and validates the protocol catalog in fsys.
func LoadProtocols(fsys fs.FS) (map[string]ProtocolTrait, error) {
	f, err := fsys.Open("protocols.yaml")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// A missing hub declaration would otherwise decode as an ordinary leaf service.
	var entries map[string]struct {
		TransportClass TransportClass       `yaml:"transport_class"`
		AuthModel      AuthModel            `yaml:"auth_model"`
		AnonGrants     []checks.GrantEffect `yaml:"anon_grants"`
		Hub            *bool                `yaml:"hub"`
	}
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode protocols.yaml: %w", err)
	}
	catalog := make(map[string]ProtocolTrait, len(entries))
	for name, trait := range entries {
		if name == "" || strings.ToLower(strings.TrimSpace(name)) != name {
			return nil, fmt.Errorf("invalid protocol name %q", name)
		}
		switch trait.TransportClass {
		case TransportE2E, TransportTLS, TransportCleartextAuth, TransportCleartextNoAuth, TransportUnknown:
		default:
			return nil, fmt.Errorf("protocol %s: invalid transport_class %q", name, trait.TransportClass)
		}
		switch trait.AuthModel {
		case AuthRequired, AuthOptional, AuthNone, AuthDevicePaired:
		default:
			return nil, fmt.Errorf("protocol %s: invalid auth_model %q", name, trait.AuthModel)
		}
		for _, effect := range trait.AnonGrants {
			if !effect.Valid() {
				return nil, fmt.Errorf("protocol %s: invalid anonymous grant %q", name, effect)
			}
		}
		if trait.Hub == nil {
			return nil, fmt.Errorf("protocol %s: missing hub declaration", name)
		}
		catalog[name] = ProtocolTrait{
			TransportClass: trait.TransportClass, AuthModel: trait.AuthModel,
			AnonGrants: trait.AnonGrants, Hub: *trait.Hub,
		}
	}
	return catalog, nil
}

// Keep one validated copy of the embedded catalog for concurrent lookups.
var builtinProtocols = sync.OnceValue(func() map[string]ProtocolTrait {
	traits, err := LoadProtocols(classifydata.BuiltinFS)
	if err != nil {
		panic(err)
	}
	return traits
})

// LookupProtocol returns the built-in traits for a protocol name reported by a service fingerprint.
func LookupProtocol(name string) (ProtocolTrait, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	// Nerva uses the full product name for PostgreSQL.
	if name == "postgresql" {
		name = "postgres"
	}
	trait, ok := builtinProtocols()[name]
	// Clone AnonGrants so callers cannot mutate the shared built-in catalog.
	trait.AnonGrants = slices.Clone(trait.AnonGrants)
	return trait, ok
}
