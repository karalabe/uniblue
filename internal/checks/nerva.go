// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checks

import (
	"fmt"
	"strings"

	"github.com/karalabe/uniblue/internal/probe"
)

// FindingsFromProfiles converts high-signal, noise-filtered Nerva protocol
// findings discovered during host fingerprinting into first-class Finding
// values so they flow through UniBlue's UniFi blast-radius scoring, state
// diffing, and webhook alerting alongside declarative YAML checks.
//
// Any Nerva finding on a (host, port) whose security property is already
// reported by an existing UniBlue check is skipped so operators never see
// duplicate entries, while independent properties on the same port (such as an
// expired TLS certificate alongside an HTTP product finding) are preserved.
func FindingsFromProfiles(profiles []probe.HostProfile, existing []Finding) []Finding {
	// Key deduplication strictly by (hostIP, port, transport, property) so
	// independent security properties on the same endpoint (e.g., an HTTP
	// product check vs. an expired TLS cert, TLS protocol version vs. TLS weak
	// cipher, or SMBv1 vs. SMB signing) never suppress each other.
	coveredByExisting := make(map[string]struct{}, len(existing))
	for _, f := range existing {
		prop := existingFindingProperty(f)
		if prop == "" {
			continue
		}
		for _, ip := range f.EndpointIPs() {
			key := fmt.Sprintf("%s|%d|%s|%s", ip, f.Port, f.EffectiveTransport(), prop)
			coveredByExisting[key] = struct{}{}
		}
	}

	// Track the highest-severity Nerva finding per dedup key so weaker findings
	// emitted earlier on the same port/property never drop higher-severity ones.
	bestIdxByKey := make(map[string]int)
	var out []Finding
	for _, hp := range profiles {
		for _, svc := range hp.Services {
			if len(svc.Findings) == 0 {
				continue
			}
			transport := strings.ToLower(strings.TrimSpace(svc.Transport))
			if transport == "" {
				transport = "tcp"
			}

			var targets []string
			if hp.ProbeIP != "" {
				targets = []string{hp.ProbeIP}
			}
			ips := observationIPs(hp.Client, svc.AddressFamily, targets)
			endpoint := hp.Client.PrimaryIP() + "|" + svc.AddressFamily + "|unknown"
			if len(ips) == 1 {
				endpoint = ips[0]
			}
			for _, sf := range svc.Findings {
				prop := nervaFindingProperty(sf.ID)
				key := fmt.Sprintf("%s|%d|%s|%s", endpoint, svc.Port, transport, prop)
				if _, ok := coveredByExisting[key]; ok {
					continue
				}

				sev, err := ParseSeverity(sf.Severity)
				if err != nil {
					sev = SeverityLow
				}
				title, summary, actions := describeNervaFinding(sf, svc)
				evidence := sf.Evidence
				if evidence == "" {
					evidence = fmt.Sprintf("detected on %s %s/%d (%s)", svc.Protocol, transport, svc.Port, sf.ID)
				}

				candidate := Finding{
					CheckID:           normalizeNervaCheckID(sf.ID),
					Title:             title,
					Category:          nervaCategory(sf.ID),
					ClaimKind:         nervaClaimKind(sf.ID),
					Property:          prop,
					Transport:         transport,
					ObservedIPs:       ips,
					BaseSeverity:      sev,
					EffectiveSeverity: sev,
					Client:            hp.Client,
					Port:              svc.Port,
					Evidence:          evidence,
					Remediation: Remediation{
						Summary:      summary,
						UniFiActions: actions,
					},
				}
				if idx, seen := bestIdxByKey[key]; seen {
					if candidate.BaseSeverity > out[idx].BaseSeverity {
						out[idx] = candidate
					}
					continue
				}
				bestIdxByKey[key] = len(out)
				out = append(out, candidate)
			}
		}
	}
	return out
}

func existingFindingProperty(f Finding) string {
	if p := strings.ToLower(strings.TrimSpace(f.Property)); p != "" {
		return p
	}
	if f.IsInventoryOnly() {
		return "service-identity"
	}
	id := strings.ToUpper(f.CheckID)
	switch id {
	case "UB-0026", "UB-0048", "UB-0044", "UB-0002", "UB-0040", "UB-0030",
		"UB-0029", "UB-0005", "UB-0041", "UB-0031", "UB-0032", "UB-0006",
		"UB-0022", "UB-0034", "UB-0023", "UB-0007", "UB-0024", "UB-0025":
		return "auth-anon"
	}
	switch {
	case id == "UB-0009" || strings.Contains(id, "TLS-LEGACY"):
		return "tls-protocol"
	case strings.Contains(id, "TLS-CERT") || strings.Contains(id, "CERTIFICATE"):
		return "tls-cert"
	case strings.Contains(id, "SMB-V1"):
		return "smb-v1"
	case strings.Contains(id, "SMB-SIGNING"):
		return "smb-signing"
	case strings.EqualFold(f.Category, "unauth-control") || strings.Contains(id, "UNAUTH") || strings.Contains(id, "ANON"):
		return "auth-anon"
	default:
		return strings.ToLower(f.CheckID)
	}
}

func nervaFindingProperty(rawID string) string {
	id := strings.ToLower(strings.TrimSpace(rawID))
	switch {
	case strings.Contains(id, "cert"):
		return "tls-cert"
	case strings.Contains(id, "weak-key") || strings.Contains(id, "key-size"):
		return "tls-weak-key"
	case isTLSCipherFinding(id):
		return nervaTLSCipherProperty(id)
	case strings.HasPrefix(id, "tls-"):
		return "tls-protocol"
	case id == "smb-v1-enabled":
		return "smb-v1"
	case id == "smb-signing-not-required":
		return "smb-signing"
	case isNervaUnauthFinding(id):
		return "auth-anon"
	default:
		return id
	}
}

// nervaTLSCipherProperty separates distinct weak TLS cipher classes (anonymous,
// null, export, RC4, DES/3DES) so multiple distinct cipher findings on the same
// port never deduplicate each other.
func nervaTLSCipherProperty(id string) string {
	switch {
	case strings.Contains(id, "anon"):
		return "tls-cipher-anon"
	case strings.Contains(id, "null"):
		return "tls-cipher-null"
	case strings.Contains(id, "export"):
		return "tls-cipher-export"
	case strings.Contains(id, "rc4"):
		return "tls-cipher-rc4"
	case strings.Contains(id, "3des") || strings.Contains(id, "-des"):
		return "tls-cipher-des"
	default:
		return "tls-cipher"
	}
}

func isTLSCipherFinding(id string) bool {
	if !strings.HasPrefix(id, "tls-") {
		return false
	}
	return strings.Contains(id, "cipher") ||
		strings.Contains(id, "anon") ||
		strings.Contains(id, "null") ||
		strings.Contains(id, "export") ||
		strings.Contains(id, "rc4") ||
		strings.Contains(id, "3des") ||
		strings.Contains(id, "-des")
}

func isNervaUnauthFinding(id string) bool {
	if strings.HasPrefix(id, "tls-") || strings.HasPrefix(id, "smb-") {
		return false
	}
	return strings.Contains(id, "unauth") ||
		strings.Contains(id, "no-auth") ||
		strings.Contains(id, "anon") ||
		strings.HasSuffix(id, "-none")
}

func nervaClaimKind(rawID string) ClaimKind {
	id := strings.ToLower(strings.TrimSpace(rawID))
	switch {
	case isNervaUnauthFinding(id):
		return ClaimConfirmedPermission
	default:
		return ClaimServiceObserved
	}
}

// normalizeNervaCheckID creates a concise, uppercase check identifier (e.g.,
// "smb-v1-enabled" -> "NERVA-SMB-V1-ENABLED", "service:1.2.3-anon-access" ->
// "NERVA-SERVICE-ANON-ACCESS") so deduplication keys stay stable across minor
// software version bumps.
func normalizeNervaCheckID(rawID string) string {
	id := strings.ToLower(strings.TrimSpace(rawID))
	// Strip embedded version strings like "service:1.2.3-anon-access" -> "service-anon-access"
	// so state.json keys remain stable across minor software updates.
	if prefix, rest, ok := strings.Cut(id, ":"); ok {
		if idx := strings.IndexByte(rest, '-'); idx >= 0 {
			id = prefix + rest[idx:]
		} else {
			id = prefix + "-" + rest
		}
	}
	id = strings.ReplaceAll(id, ":", "-")
	id = strings.ReplaceAll(id, "_", "-")
	return "NERVA-" + strings.ToUpper(id)
}

// describeNervaFinding fills in clear human titles and actionable remediation
// guidance for common LAN protocol misconfigurations surfaced by Nerva.
func describeNervaFinding(sf probe.ServiceFinding, svc probe.Service) (title, summary string, actions []string) {
	id := strings.ToLower(sf.ID)
	switch {
	case id == "smb-v1-enabled":
		return "Legacy SMBv1 Protocol Enabled",
			"Server negotiates deprecated SMBv1 (vulnerable to historic wormable exploits like EternalBlue and lacks modern encryption). Disable SMBv1 / NT1 in your NAS SMB settings and require SMB2/SMB3.",
			[]string{"disable_smbv1_on_server", "restrict_inter_vlan_smb"}
	case id == "smb-signing-not-required":
		return "SMB Signing Not Enforced",
			"SMB server supports signing but does not require it, leaving LAN SMB traffic susceptible to NTLM relay / MITM attacks. Enable mandatory SMB signing or SMB3 encryption on your NAS.",
			[]string{"require_smb_signing"}
	case id == "tls-certificate-expired":
		return "Expired Local TLS Certificate",
			"Service presents an expired TLS certificate. Renew or regenerate the local certificate so clients can verify identity cleanly.",
			[]string{"renew_tls_certificate"}
	case isNervaUnauthFinding(id):
		label := strings.ToUpper(svc.Protocol)
		if name, _, ok := strings.Cut(sf.ID, ":"); ok && name != "" {
			label = strings.ToUpper(name[:1]) + name[1:]
		}
		title = sf.Title
		if title == "" || strings.Contains(id, "anon-access") {
			title = fmt.Sprintf("Unauthenticated / Anonymous %s Access", label)
		}
		summary = sf.Description
		if summary == "" {
			summary = fmt.Sprintf("%s responded to an unauthenticated endpoint query without credentials. Disable anonymous access if this service exposes dashboards, metrics, or control endpoints.", label)
		}
		return title, summary, []string{"disable_anonymous_access", "restrict_inter_vlan_access"}
	default:
		title = sf.Title
		if title == "" {
			title = fmt.Sprintf("%s Misconfiguration (%s)", strings.ToUpper(svc.Protocol), sf.ID)
		}
		summary = sf.Description
		if summary == "" {
			summary = fmt.Sprintf("Review %s service configuration on port %d (%s).", svc.Protocol, svc.Port, sf.ID)
		}
		return title, summary, []string{"review_service_configuration"}
	}
}

// nervaCategory groups Nerva findings into UniBlue's standard finding categories.
func nervaCategory(rawID string) string {
	id := strings.ToLower(strings.TrimSpace(rawID))
	switch {
	case isNervaUnauthFinding(id):
		return "unauth-control"
	case strings.HasPrefix(id, "smb-"):
		return "exposed-protocol"
	case strings.HasPrefix(id, "tls-"):
		return "misconfig"
	default:
		return "misconfig"
	}
}
