package notify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/karalabe/uniblue/internal/checks"
	"github.com/karalabe/uniblue/internal/config"
	"github.com/karalabe/uniblue/internal/risk"
	"github.com/karalabe/uniblue/internal/unifi"
)

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
