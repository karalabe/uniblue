// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/unifi"
)

// TestNotifierFormatsAndFiltering verifies that Notifier suppresses diffs below
// minSeverity and formats urgent ntfy headers and bodies when high-severity findings fire.
func TestNotifierFormatsAndFiltering(t *testing.T) {
	var receivedBody string
	var receivedTitle string
	var receivedPriority string
	calls := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)
		receivedTitle = r.Header.Get("Title")
		receivedPriority = r.Header.Get("Priority")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n, err := New(config.NotifyConfig{
		WebhookURL:  srv.URL,
		Format:      "ntfy",
		MinSeverity: "high",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Medium finding below minSeverity="high" should not fire the webhook.
	lowDiff := risk.Diff{
		NewFindings: []checks.Finding{
			{CheckID: "UB-0006", Title: "Panel", EffectiveSeverity: checks.SeverityMedium, Client: unifi.Client{IP: "192.168.1.20"}},
		},
	}
	if err := n.Send(context.Background(), "default", lowDiff); err != nil {
		t.Fatalf("Send(lowDiff): %v", err)
	}
	if calls != 0 {
		t.Fatalf("expected 0 webhook calls for filtered diff, got %d", calls)
	}

	// Critical finding should deliver an urgent ntfy alert.
	critDiff := risk.Diff{
		NewFindings: []checks.Finding{
			{
				CheckID:           "UB-0005",
				Title:             "Unauthenticated VNC",
				EffectiveSeverity: checks.SeverityCritical,
				Client:            unifi.Client{IP: "192.168.1.30", Name: "workstation"},
				Evidence:          "RFB security type None",
			},
		},
	}
	if err := n.Send(context.Background(), "default", critDiff); err != nil {
		t.Fatalf("Send(critDiff): %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 webhook call, got %d", calls)
	}
	if receivedPriority != "urgent" || !strings.Contains(receivedTitle, "UniBlue") || !strings.Contains(receivedBody, "Unauthenticated VNC") {
		t.Fatalf("unexpected ntfy delivery: title=%q priority=%q body=%q", receivedTitle, receivedPriority, receivedBody)
	}
}

// TestNotifierRejectsRedirects verifies that Notifier refuses to follow HTTP
// 301/302 redirects (which convert POST into a body-less GET) and reports a
// delivery error instead of silently succeeding.
func TestNotifierRejectsRedirects(t *testing.T) {
	targetHits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits++
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/secret-topic", http.StatusMovedPermanently)
	}))
	defer redirector.Close()

	n, err := New(config.NotifyConfig{
		WebhookURL:  redirector.URL + "/secret-topic",
		Format:      "ntfy",
		MinSeverity: "medium",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	diff := risk.Diff{
		NewFindings: []checks.Finding{
			{CheckID: "UB-0001", Title: "Open Admin", EffectiveSeverity: checks.SeverityHigh, Client: unifi.Client{IP: "192.168.1.10"}},
		},
	}
	err = n.Send(context.Background(), "default", diff)
	if err == nil {
		t.Fatal("expected error on 301 redirect, got nil")
	}
	if !strings.Contains(err.Error(), "301") {
		t.Fatalf("expected error to mention HTTP 301, got: %v", err)
	}
	if strings.Contains(err.Error(), "secret-topic") {
		t.Fatalf("redirect error leaked webhook path: %v", err)
	}
	if targetHits != 0 {
		t.Fatalf("expected redirect target not to be requested, got %d hits", targetHits)
	}
}

// TestNotifierSanitizesTransportErrors verifies that transport failures unwrap
// *url.Error and log only scheme://host without leaking embedded webhook
// tokens, credentials, paths, or query parameters.
func TestNotifierSanitizesTransportErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := srv.URL
	srv.Close()

	secretURL := strings.Replace(closedURL, "http://", "http://alice:superpass@", 1) +
		"/api/webhooks/987654/SUPER-SECRET-TOKEN?auth=topsecret"

	n, err := New(config.NotifyConfig{
		WebhookURL:  secretURL,
		Format:      "discord",
		MinSeverity: "medium",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	diff := risk.Diff{
		NewFindings: []checks.Finding{
			{CheckID: "UB-0001", Title: "Alert", EffectiveSeverity: checks.SeverityHigh, Client: unifi.Client{IP: "192.168.1.10"}},
		},
	}
	err = n.Send(context.Background(), "default", diff)
	if err == nil {
		t.Fatal("expected transport error against closed server, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, closedURL) {
		t.Fatalf("expected error to include scheme://host %q, got: %s", closedURL, msg)
	}
	for _, secret := range []string{"SUPER-SECRET-TOKEN", "987654", "superpass", "alice", "topsecret", "/api/webhooks"} {
		if strings.Contains(msg, secret) {
			t.Fatalf("transport error leaked %q: %s", secret, msg)
		}
	}
}

// TestNotifierEscapesDiscordAndSlackPayloads verifies that untrusted device
// names and finding titles cannot trigger @everyone/@here/<!channel>/<!here>
// mentions or masked links in Discord and Slack payloads, and that Discord
// explicitly sets allowed_mentions.parse to an empty list.
func TestNotifierEscapesDiscordAndSlackPayloads(t *testing.T) {
	maliciousDiff := risk.Diff{
		NewFindings: []checks.Finding{
			{
				CheckID:           "UB-0002",
				Title:             "Alert [click](https://evil.example) <https://evil.example|phish>",
				EffectiveSeverity: checks.SeverityHigh,
				Client:            unifi.Client{IP: "192.168.1.40", Name: "@everyone @here <!channel> <!here>"},
				Evidence:          "banner <@12345>",
			},
		},
	}

	t.Run("discord", func(t *testing.T) {
		var rawBody []byte
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		n, err := New(config.NotifyConfig{WebhookURL: srv.URL, Format: "discord", MinSeverity: "medium"})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if err := n.Send(context.Background(), "default", maliciousDiff); err != nil {
			t.Fatalf("Send: %v", err)
		}

		var payload struct {
			Content         string `json:"content"`
			AllowedMentions struct {
				Parse []string `json:"parse"`
			} `json:"allowed_mentions"`
		}
		if err := json.Unmarshal(rawBody, &payload); err != nil {
			t.Fatalf("Unmarshal discord payload: %v (raw=%s)", err, string(rawBody))
		}
		if payload.AllowedMentions.Parse == nil || len(payload.AllowedMentions.Parse) != 0 {
			t.Fatalf("expected allowed_mentions.parse=[], got %#v (raw=%s)", payload.AllowedMentions.Parse, string(rawBody))
		}
		for _, forbidden := range []string{"@everyone", "@here", "[click](https://evil.example)", "<@12345>"} {
			if strings.Contains(payload.Content, forbidden) {
				t.Fatalf("discord content still contains unescaped %q: %s", forbidden, payload.Content)
			}
		}
	})

	t.Run("slack", func(t *testing.T) {
		var rawBody []byte
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawBody, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		n, err := New(config.NotifyConfig{WebhookURL: srv.URL, Format: "slack", MinSeverity: "medium"})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if err := n.Send(context.Background(), "default", maliciousDiff); err != nil {
			t.Fatalf("Send: %v", err)
		}

		var payload struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(rawBody, &payload); err != nil {
			t.Fatalf("Unmarshal slack payload: %v", err)
		}
		for _, forbidden := range []string{"<!channel>", "<!here>", "@everyone", "@here", "<https://evil.example|phish>", "<@12345>"} {
			if strings.Contains(payload.Text, forbidden) {
				t.Fatalf("slack text still contains unescaped %q: %s", forbidden, payload.Text)
			}
		}
		if !strings.Contains(payload.Text, "&lt;!channel&gt;") || !strings.Contains(payload.Text, "&lt;https://evil.example|phish&gt;") {
			t.Fatalf("expected Slack mrkdwn escaping in text, got: %s", payload.Text)
		}
	})
}

// TestNotifierTruncatesNtfyBody verifies that oversized alert digests sent via
// ntfy are truncated to safely stay under ntfy's 4096-byte message limit while
// remaining valid UTF-8.
func TestNotifierTruncatesNtfyBody(t *testing.T) {
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n, err := New(config.NotifyConfig{
		WebhookURL:  srv.URL,
		Format:      "ntfy",
		MinSeverity: "medium",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var diff risk.Diff
	for i := 0; i < 80; i++ {
		diff.NewFindings = append(diff.NewFindings, checks.Finding{
			CheckID:           fmt.Sprintf("UB-%04d", i),
			Title:             "Large Digest Finding Title With Plenty Of Context",
			EffectiveSeverity: checks.SeverityHigh,
			Client:            unifi.Client{IP: fmt.Sprintf("192.168.1.%d", i+1), Name: fmt.Sprintf("host-%02d", i)},
			Evidence:          strings.Repeat("evidence-payload-", 4),
		})
	}

	if err := n.Send(context.Background(), "default", diff); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(receivedBody) >= 4096 || len(receivedBody) > maxNtfyBodyBytes {
		t.Fatalf("expected ntfy body < 4096 bytes (<= %d), got %d bytes", maxNtfyBodyBytes, len(receivedBody))
	}
	if !strings.HasSuffix(string(receivedBody), "...") {
		t.Fatalf("expected truncated ntfy body to end with ellipsis, got tail %q", string(receivedBody[len(receivedBody)-16:]))
	}
	if !utf8.Valid(receivedBody) {
		t.Fatal("truncated ntfy body is not valid UTF-8")
	}
}

// TestNotifierStandardWebhooksSigning verifies unsigned fallback when no secret
// is set, Standard Webhooks HMAC-SHA256 signing for both raw and whsec_<base64>
// secrets, secret redaction on invalid whsec_ input, and stable webhook-id with
// fresh webhook-timestamp across SendWithID retries.
func TestNotifierStandardWebhooksSigning(t *testing.T) {
	diff := risk.Diff{
		NewFindings: []checks.Finding{
			{
				CheckID:           "UB-0001",
				Title:             "Telnet open",
				EffectiveSeverity: checks.SeverityHigh,
				Client:            unifi.Client{IP: "192.168.1.10", Name: "router"},
				Evidence:          "TCP 23 login banner",
			},
		},
	}

	verifySig := func(t *testing.T, key []byte, hdr http.Header, body []byte) {
		t.Helper()
		id := hdr.Get("webhook-id")
		ts := hdr.Get("webhook-timestamp")
		sig := hdr.Get("webhook-signature")
		if !strings.HasPrefix(id, "msg_") || len(id) < 12 {
			t.Fatalf("expected msg_* webhook-id, got %q", id)
		}
		if _, err := strconv.ParseInt(ts, 10, 64); err != nil {
			t.Fatalf("expected Unix seconds webhook-timestamp, got %q: %v", ts, err)
		}
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(id + "." + ts + "."))
		_, _ = mac.Write(body)
		want := "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
		if sig != want {
			t.Fatalf("webhook-signature mismatch: got %q want %q", sig, want)
		}
	}

	t.Run("unsigned_when_secret_empty", func(t *testing.T) {
		var hdr http.Header
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hdr = r.Header.Clone()
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		n, err := New(config.NotifyConfig{WebhookURL: srv.URL, Format: "json", MinSeverity: "medium"})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if err := n.Send(context.Background(), "default", diff); err != nil {
			t.Fatalf("Send: %v", err)
		}
		for _, h := range []string{"webhook-id", "webhook-timestamp", "webhook-signature"} {
			if got := hdr.Get(h); got != "" {
				t.Fatalf("expected unsigned webhook to omit %s, got %q", h, got)
			}
		}
	})

	t.Run("raw_secret", func(t *testing.T) {
		var hdr http.Header
		var body []byte
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hdr = r.Header.Clone()
			body, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		n, err := New(config.NotifyConfig{
			WebhookURL:    srv.URL,
			WebhookSecret: "my-plain-shared-secret",
			Format:        "json",
			MinSeverity:   "medium",
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if err := n.Send(context.Background(), "default", diff); err != nil {
			t.Fatalf("Send: %v", err)
		}
		verifySig(t, []byte("my-plain-shared-secret"), hdr, body)
	})

	t.Run("whsec_base64_and_retry_fresh_timestamp", func(t *testing.T) {
		rawKey := []byte("0123456789abcdef0123456789abcdef")
		secret := "whsec_" + base64.StdEncoding.EncodeToString(rawKey)

		type capture struct {
			hdr  http.Header
			body []byte
		}
		var caps []capture
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			caps = append(caps, capture{hdr: r.Header.Clone(), body: b})
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		n, err := New(config.NotifyConfig{
			WebhookURL:    srv.URL,
			WebhookSecret: secret,
			Format:        "json",
			MinSeverity:   "medium",
		})
		if err != nil {
			t.Fatalf("New: %v", err)
		}

		now := time.Unix(1770000000, 0).UTC()
		n.nowFn = func() time.Time { return now }
		msgID := NewWebhookID()
		if err := n.SendWithID(context.Background(), msgID, "default", diff); err != nil {
			t.Fatalf("attempt 1: %v", err)
		}

		// Retry 400 seconds later must keep webhook-id but re-sign a fresh timestamp.
		now = now.Add(400 * time.Second)
		if err := n.SendWithID(context.Background(), msgID, "default", diff); err != nil {
			t.Fatalf("attempt 2: %v", err)
		}

		if len(caps) != 2 {
			t.Fatalf("expected 2 deliveries, got %d", len(caps))
		}
		verifySig(t, rawKey, caps[0].hdr, caps[0].body)
		verifySig(t, rawKey, caps[1].hdr, caps[1].body)
		if caps[0].hdr.Get("webhook-id") != msgID || caps[1].hdr.Get("webhook-id") != msgID {
			t.Fatalf("expected identical webhook-id %q across retries, got %q and %q",
				msgID, caps[0].hdr.Get("webhook-id"), caps[1].hdr.Get("webhook-id"))
		}
		if caps[0].hdr.Get("webhook-timestamp") != "1770000000" || caps[1].hdr.Get("webhook-timestamp") != "1770000400" {
			t.Fatalf("expected fresh timestamp on retry, got %q then %q",
				caps[0].hdr.Get("webhook-timestamp"), caps[1].hdr.Get("webhook-timestamp"))
		}
		if caps[0].hdr.Get("webhook-signature") == caps[1].hdr.Get("webhook-signature") {
			t.Fatal("expected distinct signature when timestamp changed on retry")
		}
	})

	t.Run("invalid_whsec_rejected_without_echoing_secret", func(t *testing.T) {
		for _, bad := range []string{
			"whsec_!!!NOT_BASE64_TOPSECRET!!!",
			"whsec_" + base64.RawStdEncoding.EncodeToString([]byte("unpadded-secret-1")), // missing '=' padding
		} {
			_, err := New(config.NotifyConfig{
				WebhookURL:    "https://hooks.example.test/x",
				WebhookSecret: bad,
				Format:        "json",
				MinSeverity:   "medium",
			})
			if err == nil {
				t.Fatalf("expected error for malformed/unpadded whsec_ secret %q", bad)
			}
			if strings.Contains(err.Error(), "TOPSECRET") || strings.Contains(err.Error(), "unpadded") {
				t.Fatalf("error leaked secret: %v", err)
			}
		}
	})
}
