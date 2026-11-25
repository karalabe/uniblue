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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/risk"
)

const (
	// maxDiscordBodyBytes stays safely below Discord's 2000-character message limit.
	maxDiscordBodyBytes = 1900

	// maxNtfyBodyBytes stays safely below ntfy's default 4096-byte message limit.
	maxNtfyBodyBytes = 3900
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
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			// Do not follow 3xx redirects: following a 301/302 converts POST into a
			// body-less GET and can silently drop alerts while returning HTTP 200.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
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

	var (
		body        []byte
		contentType string
		headers     = map[string]string{}
		err         error
	)

	switch n.format {
	case "discord":
		body, err = json.Marshal(map[string]any{
			"content": truncate(formatSummary(site, filtered, escapeDiscord), maxDiscordBodyBytes),
			"allowed_mentions": map[string]any{
				"parse": []string{},
			},
		})
		contentType = "application/json"
	case "slack":
		body, err = json.Marshal(map[string]string{
			"text": formatSummary(site, filtered, escapeSlack),
		})
		contentType = "application/json"
	case "ntfy":
		body = []byte(truncate(formatSummary(site, filtered, nil), maxNtfyBodyBytes))
		contentType = "text/plain; charset=utf-8"
		headers["Title"] = fmt.Sprintf("UniBlue Alert (%s)", site)
		headers["Priority"] = ntfyPriority(filtered)
	default: // "json"
		body, err = json.Marshal(map[string]any{
			"site":    site,
			"summary": formatSummary(site, filtered, nil),
			"diff":    filtered,
		})
		contentType = "application/json"
	}
	if err != nil {
		return fmt.Errorf("marshal notification: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", sanitizeTransportError(n.webhookURL, err))
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "UniBlue/0.1")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send webhook: %w", sanitizeTransportError(n.webhookURL, err))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return fmt.Errorf("webhook returned redirect HTTP %d (redirects are disabled)", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// sanitizeWebhookTarget returns only scheme://host (omitting path, query,
// fragment, and userinfo) so embedded webhook tokens and topics are never logged.
func sanitizeWebhookTarget(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "<redacted-url>"
	}
	if u.Scheme != "" {
		return u.Scheme + "://" + u.Host
	}
	return u.Host
}

// sanitizeTransportError unwraps *url.Error values and replaces the full
// webhook URL with scheme://host so embedded secrets are never leaked into logs.
func sanitizeTransportError(fallbackURL string, err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		target := sanitizeWebhookTarget(uerr.URL)
		if target == "<redacted-url>" {
			target = sanitizeWebhookTarget(fallbackURL)
		}
		op := uerr.Op
		if op == "" {
			op = "request"
		}
		return fmt.Errorf("%s %s: %w", op, target, uerr.Err)
	}
	return err
}

// escapeDiscord neutralizes mentions (@everyone, @here, <@id>) and markdown
// constructs (such as masked links) in untrusted text before embedding it in a
// Discord webhook payload.
func escapeDiscord(s string) string {
	r := strings.NewReplacer(
		"\\", "\\\\",
		"@", "@\u200b",
		"[", "\\[",
		"]", "\\]",
		"(", "\\(",
		")", "\\)",
		"<", "\\<",
		">", "\\>",
		"`", "\\`",
		"*", "\\*",
		"_", "\\_",
		"~", "\\~",
		"|", "\\|",
		"\r", " ",
		"\n", " ",
	)
	return r.Replace(s)
}

// escapeSlack neutralizes Slack mrkdwn sequences (<!channel>, <!here>, <@user>,
// <url|label> masked links) and bare @ mentions in untrusted text.
func escapeSlack(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"@", "@\u200b",
		"\r", " ",
		"\n", " ",
	)
	return r.Replace(s)
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
// webhooks and push notifications. When escape is non-nil, dynamic fields are
// escaped before interpolation.
func formatSummary(site string, d risk.Diff, escape func(string) string) string {
	esc := func(s string) string {
		if escape != nil {
			return escape(s)
		}
		return s
	}

	var b strings.Builder
	fmt.Fprintf(&b, "UniBlue alert on site %q:\n", esc(site))

	for _, f := range d.NewFindings {
		fmt.Fprintf(&b, "- [NEW %s] %s on %s (%s): %s\n",
			strings.ToUpper(f.EffectiveSeverity.String()), esc(f.Title), esc(f.Client.DisplayName()), esc(f.Client.IP), esc(f.Evidence))
	}
	for _, f := range d.EscalatedFindings {
		reasons := make([]string, len(f.RiskReasons))
		for i, r := range f.RiskReasons {
			reasons[i] = esc(r)
		}
		fmt.Fprintf(&b, "- [ESCALATED %s] %s on %s (%s): %s\n",
			strings.ToUpper(f.EffectiveSeverity.String()), esc(f.Title), esc(f.Client.DisplayName()), esc(f.Client.IP), strings.Join(reasons, "; "))
	}
	for _, cl := range d.NewTrustedClients {
		fmt.Fprintf(&b, "- [NEW TRUSTED DEVICE] %s (%s / %s) joined %s\n",
			esc(cl.DisplayName()), esc(cl.IP), esc(cl.MAC), esc(cl.NetworkName))
	}
	for _, pf := range d.NewPortForwards {
		fmt.Fprintf(&b, "- [NEW PORT FORWARD] %s: %s WAN:%s -> %s:%s\n",
			esc(pf.Name), esc(pf.Proto), esc(pf.DstPort), esc(pf.FwdIP), esc(pf.FwdPort))
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

// truncate clips s to at most maxLen bytes on a valid UTF-8 rune boundary with
// an ellipsis so platforms with strict message length limits accept it.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		cut := maxLen
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		return s[:cut]
	}
	cut := maxLen - 3
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}
