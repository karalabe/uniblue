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
	coveredNonTLS := make(map[string]struct{}, len(existing))
	coveredTLS := make(map[string]struct{}, len(existing))
	for _, f := range existing {
		key := fmt.Sprintf("%s|%d", f.Client.IP, f.Port)
		coveredNonTLS[key] = struct{}{}
		if f.CheckID == "UB-0020" || strings.Contains(strings.ToLower(f.CheckID), "tls") {
			coveredTLS[key] = struct{}{}
		}
	}

	var out []Finding
	for _, hp := range profiles {
		for _, svc := range hp.Services {
			if len(svc.Findings) == 0 {
				continue
			}

			for _, sf := range svc.Findings {
				key := fmt.Sprintf("%s|%d", hp.Client.IP, svc.Port)
				isTLS := strings.HasPrefix(strings.ToLower(sf.ID), "tls-")
				isTLSCert := strings.Contains(strings.ToLower(sf.ID), "cert")
				// Never suppress an independent TLS certificate finding (e.g., expired
				// cert) because of an HTTP app check or deprecated-TLS protocol check.
				if isTLS {
					if !isTLSCert {
						if _, ok := coveredTLS[key]; ok {
							continue
						}
					}
				} else {
					if _, ok := coveredNonTLS[key]; ok {
						continue
					}
				}
				sev, err := ParseSeverity(sf.Severity)
				if err != nil {
					sev = SeverityLow
				}
				title, summary, actions := describeNervaFinding(sf, svc)
				evidence := sf.Evidence
				if evidence == "" {
					evidence = fmt.Sprintf("detected on %s port %d (%s)", svc.Protocol, svc.Port, sf.ID)
				}

				out = append(out, Finding{
					CheckID:           normalizeNervaCheckID(sf.ID),
					Title:             title,
					Category:          nervaCategory(sf.ID),
					BaseSeverity:      sev,
					EffectiveSeverity: sev,
					Client:            hp.Client,
					Port:              svc.Port,
					Evidence:          evidence,
					Remediation: Remediation{
						Summary:      summary,
						UniFiActions: actions,
					},
				})
			}
		}
	}
	return out
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
	case strings.Contains(id, "anon-access") || svc.AnonymousAccess:
		label := strings.ToUpper(svc.Protocol)
		if name, _, ok := strings.Cut(sf.ID, ":"); ok && name != "" {
			label = strings.ToUpper(name[:1]) + name[1:]
		}
		return fmt.Sprintf("Unauthenticated / Anonymous %s Access", label),
			fmt.Sprintf("%s responded to an unauthenticated endpoint query without credentials. Disable anonymous access if this service exposes dashboards, metrics, or control endpoints.", label),
			[]string{"disable_anonymous_access", "restrict_inter_vlan_access"}
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
	id := strings.ToLower(rawID)
	switch {
	case strings.Contains(id, "anon"):
		return "unauth-control"
	case strings.HasPrefix(id, "smb-"):
		return "exposed-protocol"
	case strings.HasPrefix(id, "tls-"):
		return "misconfig"
	default:
		return "misconfig"
	}
}
