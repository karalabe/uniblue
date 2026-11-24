package oui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSyncAndLongestPrefixLookup(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oui.csv", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Registry,Assignment,Organization Name,Organization Address\n" +
			"MA-L,001122,Acme Audio Corp.,USA\n" +
			"MA-L,0050C2,IEEE Registration Authority,USA\n"))
	})
	mux.HandleFunc("/mam.csv", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Registry,Assignment,Organization Name,Organization Address\n" +
			"MA-M,AABBCC1,Acme Medium Block Corp,USA\n"))
	})
	mux.HandleFunc("/oui36.csv", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Registry,Assignment,Organization Name,Organization Address\n" +
			"MA-S,0050C2AA1,Acme Sensor GmbH,Germany\n"))
	})
	mux.HandleFunc("/iab.csv", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("Registry,Assignment,Organization Name,Organization Address\n"))
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	db := New(t.TempDir())
	db.sources = []registrySource{
		{Name: "MA-L", URL: srv.URL + "/oui.csv", Nibbles: 6},
		{Name: "MA-M", URL: srv.URL + "/mam.csv", Nibbles: 7},
		{Name: "MA-S", URL: srv.URL + "/oui36.csv", Nibbles: 9},
		{Name: "IAB", URL: srv.URL + "/iab.csv", Nibbles: 9},
	}

	meta, err := db.Sync(context.Background(), nil)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if meta.MALCount != 2 || meta.MAMCount != 1 || meta.MASCount != 1 {
		t.Fatalf("unexpected meta counts: %+v", meta)
	}

	// Reload from disk into a fresh DB instance to verify gzip persistence.
	reloaded := New(db.Dir())
	if err := reloaded.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// 36-bit MA-S must beat MA-L's "IEEE Registration Authority" placeholder.
	mas := reloaded.Lookup("00:50:c2:aa:10:01")
	if mas.Vendor != "Acme Sensor GmbH" || mas.Registry != "MA-S" {
		t.Fatalf("MA-S lookup = %+v, want Acme Sensor GmbH (MA-S)", mas)
	}

	// 28-bit MA-M lookup.
	mam := reloaded.Lookup("aa:bb:cc:1f:00:01")
	if mam.Vendor != "Acme Medium Block Corp" || mam.Registry != "MA-M" {
		t.Fatalf("MA-M lookup = %+v, want Acme Medium Block Corp (MA-M)", mam)
	}

	// 24-bit MA-L lookup.
	mal := reloaded.Lookup("00:11:22:00:00:42")
	if mal.Vendor != "Acme Audio Corp." || mal.Registry != "MA-L" {
		t.Fatalf("MA-L lookup = %+v, want Acme Audio Corp. (MA-L)", mal)
	}

	// Built-in virtual MAC prefix (QEMU/KVM).
	vm := reloaded.Lookup("52:54:00:12:34:56")
	if !vm.IsVirtual || vm.Vendor != "QEMU/KVM" {
		t.Fatalf("virtual lookup = %+v, want QEMU/KVM virtual", vm)
	}

	// Locally-administered random MAC (bit 1 of first byte set: 0x02 = 0000_0010).
	priv := reloaded.Lookup("02:aa:bb:cc:dd:01")
	if !priv.IsLocallyAdministered || priv.Registry != "local" {
		t.Fatalf("local MAC lookup = %+v, want IsLocallyAdministered=true", priv)
	}
}
