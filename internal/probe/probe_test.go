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
