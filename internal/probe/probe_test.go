package probe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/unifi"
	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestFingerprintHostAndExclusions(t *testing.T) {
	// Start a local HTTP listener simulating an embedded ventilation web panel.
	httpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "AirFlow-HTTP/1.0")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><title>  AirFlow Pro Ventilation  </title></head><body>ok</body></html>`))
	}))
	defer httpSrv.Close()

	_, portStr, err := net.SplitHostPort(httpSrv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	openPort, _ := strconv.Atoi(portStr)

	fp := NewFingerprinter([]int{openPort}, 4, 2*time.Second, map[string]struct{}{
		"127.0.0.2": {},
	})

	clients := []unifi.Client{
		{IP: "127.0.0.1", MAC: "aa:bb:cc:dd:ee:01", Hostname: "hvac"},
		{IP: "127.0.0.2", MAC: "aa:bb:cc:dd:ee:02", Hostname: "excluded"},
	}

	profiles := fp.FingerprintAll(context.Background(), clients)
	if len(profiles) != 1 {
		t.Fatalf("got %d profiles, want 1 (excluded IP should be skipped)", len(profiles))
	}
	if !profiles[0].HasPort(openPort) {
		t.Fatalf("expected port %d to be detected open", openPort)
	}

	// Verify HTTP banner extraction helper directly since httptest picks an
	// ephemeral port outside the fixed well-known HTTP port list.
	banner, ok := fp.fetchHTTPBanner(context.Background(), "http", "127.0.0.1", openPort)
	if !ok {
		t.Fatalf("expected HTTP banner to be fetched")
	}
	if banner.StatusCode != 200 || banner.Server != "AirFlow-HTTP/1.0" || banner.Title != "AirFlow Pro Ventilation" {
		t.Fatalf("unexpected banner: %+v", banner)
	}
}

func TestShouldKeepNervaFindingFiltersSyntheticHTTPAnonAccess(t *testing.T) {
	// Synthetic HTTP fingerprinter finding emitted on public /api/health or /login must be dropped.
	synthetic := plugins.SecurityFinding{
		ID:       "grafana:10.0.0-anon-access",
		Severity: plugins.SeverityMedium,
		Evidence: "Successfully queried endpoint without credentials",
	}
	if shouldKeepNervaFinding(synthetic) {
		t.Fatal("expected synthetic HTTP *-anon-access finding to be filtered out")
	}

	// Real verified protocol findings must be retained.
	for _, realFinding := range []plugins.SecurityFinding{
		{ID: "smb-v1-enabled", Severity: plugins.SeverityMedium, Evidence: "SMBv1 negotiate response received"},
		{ID: "ftp-anon-access", Severity: plugins.SeverityHigh, Evidence: "230 Anonymous login ok"},
		{ID: "tls-certificate-expired", Severity: plugins.SeverityLow, Evidence: "expired=2023-01-01"},
	} {
		if !shouldKeepNervaFinding(realFinding) {
			t.Fatalf("expected genuine finding %q to be kept", realFinding.ID)
		}
	}
}
