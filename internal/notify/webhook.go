// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package notify delivers concise, low-noise security alerts to a configured
// HTTP webhook in JSON, Discord, Slack, or ntfy format.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/risk"
)

// Notifier formats and delivers change-driven alerts from a risk.Diff.
type Notifier struct {
	// webhookURL is the target HTTP(S) endpoint; empty disables delivery.
	webhookURL string

	// format chooses the outgoing payload layout ("json", "discord", "slack", "ntfy").
	format string

	// minSeverity suppresses findings below this threshold.
	minSeverity checks.Severity

	// httpClient bounds outbound webhook delivery time.
	httpClient *http.Client
}

// New creates a Notifier from NotifyConfig. If WebhookURL is empty, Send is a
// safe no-op.
func New(cfg config.NotifyConfig) (*Notifier, error) {
	minSev, err := checks.ParseSeverity(cfg.MinSeverity)
	if err != nil {
		return nil, fmt.Errorf("notify min_severity: %w", err)
	}
	return &Notifier{
		webhookURL:  strings.TrimSpace(cfg.WebhookURL),
		format:      strings.ToLower(strings.TrimSpace(cfg.Format)),
		minSeverity: minSev,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// Send delivers an alert for diff if a webhook URL is configured and at least
// one item meets the minimum severity threshold.
func (n *Notifier) Send(ctx context.Context, site string, diff risk.Diff) error {
	if n.webhookURL == "" || !diff.HasAlerts(n.minSeverity) {
		return nil
	}

	// Filter findings down to those meeting minSeverity so noisy low-priority
	// items never clutter the alert payload.
	filtered := filterDiff(diff, n.minSeverity)
	summary := formatSummary(site, filtered)

	var (
		body        []byte
		contentType string
		headers     = map[string]string{}
		err         error
	)

	switch n.format {
	case "discord":
		body, err = json.Marshal(map[string]string{"content": truncate(summary, 1900)})
		contentType = "application/json"
	case "slack":
		body, err = json.Marshal(map[string]string{"text": summary})
		contentType = "application/json"
	case "ntfy":
		body = []byte(summary)
		contentType = "text/plain; charset=utf-8"
		headers["Title"] = fmt.Sprintf("UniBlue Alert (%s)", site)
		headers["Priority"] = ntfyPriority(filtered)
	default: // "json"
		body, err = json.Marshal(map[string]any{
			"site":    site,
			"summary": summary,
			"diff":    filtered,
		})
		contentType = "application/json"
	}
	if err != nil {
		return fmt.Errorf("marshal notification: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "UniBlue/0.1")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send webhook: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// filterDiff returns a copy of diff containing only findings at or above minSev.
func filterDiff(d risk.Diff, minSev checks.Severity) risk.Diff {
	out := risk.Diff{
		ResolvedKeys:      d.ResolvedKeys,
		NewTrustedClients: d.NewTrustedClients,
		NewPortForwards:   d.NewPortForwards,
	}
	for _, f := range d.NewFindings {
		if f.EffectiveSeverity >= minSev {
			out.NewFindings = append(out.NewFindings, f)
		}
	}
	for _, f := range d.EscalatedFindings {
		if f.EffectiveSeverity >= minSev {
			out.EscalatedFindings = append(out.EscalatedFindings, f)
		}
	}
	return out
}

// formatSummary renders a compact, readable alert digest suitable for chat
// webhooks and push notifications.
func formatSummary(site string, d risk.Diff) string {
	var b strings.Builder
	fmt.Fprintf(&b, "UniBlue alert on site %q:\n", site)

	for _, f := range d.NewFindings {
		fmt.Fprintf(&b, "- [NEW %s] %s on %s (%s) — %s\n",
			strings.ToUpper(f.EffectiveSeverity.String()), f.Title, f.Client.DisplayName(), f.Client.IP, f.Evidence)
	}
	for _, f := range d.EscalatedFindings {
		fmt.Fprintf(&b, "- [ESCALATED %s] %s on %s (%s) — %s\n",
			strings.ToUpper(f.EffectiveSeverity.String()), f.Title, f.Client.DisplayName(), f.Client.IP, strings.Join(f.RiskReasons, "; "))
	}
	for _, cl := range d.NewTrustedClients {
		fmt.Fprintf(&b, "- [NEW TRUSTED DEVICE] %s (%s / %s) joined %s\n",
			cl.DisplayName(), cl.IP, cl.MAC, cl.NetworkName)
	}
	for _, pf := range d.NewPortForwards {
		fmt.Fprintf(&b, "- [NEW PORT FORWARD] %s: %s WAN:%s -> %s:%s\n",
			pf.Name, pf.Proto, pf.DstPort, pf.FwdIP, pf.FwdPort)
	}
	return strings.TrimSpace(b.String())
}

// ntfyPriority maps the highest finding severity in the diff to an ntfy
// priority level ("default", "high", or "urgent").
func ntfyPriority(d risk.Diff) string {
	highest := checks.SeverityMedium
	for _, f := range append(append([]checks.Finding(nil), d.NewFindings...), d.EscalatedFindings...) {
		if f.EffectiveSeverity > highest {
			highest = f.EffectiveSeverity
		}
	}
	switch highest {
	case checks.SeverityCritical:
		return "urgent"
	case checks.SeverityHigh:
		return "high"
	default:
		return "default"
	}
}

// truncate clips s to maxLen bytes with an ellipsis so chat platforms with
// strict message length limits (such as Discord's 2000-character cap) accept it.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
