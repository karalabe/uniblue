// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/karalabe/uniblue/internal/unifi"
	"github.com/praetorian-inc/nerva/pkg/plugins"
	"golang.org/x/crypto/ssh"
)

// TestFingerprintHostAndExclusions verifies open port discovery, exclude_ips
// enforcement, and HTTP landing-page title and header extraction.
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

// TestShouldKeepNervaFindingFiltersSyntheticHTTPAnonAccess verifies that
// Nerva's synthetic HTTP product-detection anon-access notices are dropped while
// real protocol misconfigurations (such as SMBv1) are kept.
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

// TestFingerprintingReportsPerPortProgress verifies that Nerva service
// identification and alternate-port fallback emit monotonic per-port progress
// updates naming the active host and port.
func TestFingerprintingReportsPerPortProgress(t *testing.T) {
	// Start an alternate-port SSH banner listener so both Nerva FastMode and the
	// unclassified-port fallback run and emit progress updates.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("SSH-2.0-OpenSSH_9.9\r\n"))
				time.Sleep(50 * time.Millisecond)
			}(conn)
		}
	}()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	altPort, _ := strconv.Atoi(portStr)

	type progressEvent struct {
		phase string
		done  int
		total int
		host  string
	}
	var (
		mu     sync.Mutex
		events []progressEvent
	)
	fp := NewFingerprinter([]int{altPort}, 4, time.Second, nil)
	fp.SetProgressFunc(func(phase string, done, total int, host string) {
		mu.Lock()
		events = append(events, progressEvent{phase: phase, done: done, total: total, host: host})
		mu.Unlock()
	})

	profiles := fp.FingerprintAll(context.Background(), []unifi.Client{
		{IP: "127.0.0.1", MAC: "aa:bb:cc:dd:ee:09", Name: "Lab Box"},
	})
	if len(profiles) != 1 || !profiles[0].HasPort(altPort) {
		t.Fatalf("expected open port %d on Lab Box, got %+v", altPort, profiles)
	}

	mu.Lock()
	defer mu.Unlock()
	wantHostPort := "Lab Box:" + portStr
	sawFPStart, sawFPComplete, sawFBComplete := false, false, false
	lastDone := make(map[string]int)
	for _, ev := range events {
		if prev, ok := lastDone[ev.phase]; ok && ev.done < prev {
			t.Fatalf("phase %q progress went backwards: %d -> %d (%+v)", ev.phase, prev, ev.done, events)
		}
		lastDone[ev.phase] = ev.done
		switch ev.phase {
		case "fingerprinting":
			if ev.done == 0 && ev.total == 1 {
				sawFPStart = true
			}
			if ev.done == 1 && ev.total == 1 && strings.HasPrefix(ev.host, wantHostPort) {
				sawFPComplete = true
			}
		case "fingerprinting-fallback":
			if ev.done == 1 && ev.total == 1 && strings.HasPrefix(ev.host, wantHostPort) {
				sawFBComplete = true
			}
		}
	}
	if !sawFPStart || !sawFPComplete {
		t.Fatalf("expected fingerprinting start and completion for %q, got %+v", wantHostPort, events)
	}
	if !sawFBComplete {
		t.Fatalf("expected fingerprinting-fallback completion for %q, got %+v", wantHostPort, events)
	}
}

// TestSMBNegotiationOnly captures every byte the client sends through connection close.
func TestSMBNegotiationOnly(t *testing.T) {
	for _, tc := range []struct {
		dialect   uint16
		name      string
		encrypted bool
	}{
		{0x0202, "2.0.2", false}, {0x0210, "2.1", false}, {0x0300, "3.0", true}, {0x0302, "3.0.2", true}, {0x0311, "3.1.1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			done := make(chan *SMBInfo, 1)
			go func() { info := negotiateSMB(client, time.Second); client.Close(); done <- info }()
			var frame [4]byte
			if _, err := io.ReadFull(server, frame[:]); err != nil {
				t.Fatal(err)
			}
			size := binary.BigEndian.Uint32(frame[:])
			if size < 110 || size > 512 {
				t.Fatalf("request length %d", size)
			}
			msg := make([]byte, size)
			if _, err := io.ReadFull(server, msg); err != nil {
				t.Fatal(err)
			}
			le := binary.LittleEndian
			if string(msg[:4]) != "\xfeSMB" || le.Uint16(msg[12:]) != 0 || le.Uint32(msg[20:]) != 0 || le.Uint16(msg[64:]) != 36 || le.Uint16(msg[66:]) != 5 {
				t.Fatal("expected a single standalone SMB2 NEGOTIATE")
			}
			reply := make([]byte, 4+128)
			b := reply[4:]
			copy(b, msg[:6])
			le.PutUint32(b[16:], 1)
			le.PutUint16(b[64:], 65)
			le.PutUint16(b[66:], 3)
			le.PutUint16(b[68:], tc.dialect)
			le.PutUint32(b[88:], 0x40)
			if tc.dialect == 0x0311 {
				le.PutUint32(b[88:], 0)
				le.PutUint32(b[124:], 128)
				le.PutUint16(b[70:], 1)
				// Reply with AES-128-GCM (cipher ID 2) to verify non-CCM SMB 3.1.1 servers.
				reply = append(reply, 2, 0, 4, 0, 0, 0, 0, 0, 1, 0, 2, 0)
			}
			binary.BigEndian.PutUint32(reply, uint32(len(reply)-4))
			if _, err := server.Write(reply); err != nil {
				t.Fatal(err)
			}
			if extra, err := io.ReadAll(server); err != nil || len(extra) != 0 {
				t.Fatalf("unexpected follow-up %x (%v)", extra, err)
			}
			info := <-done
			if info == nil || info.Dialect != tc.name || !info.SigningEnabled || !info.SigningRequired || info.EncryptionSupported != tc.encrypted {
				t.Fatal(info)
			}
		})
	}
}

// TestSSHHostKeysBeforeAuth checks key reuse and rotation without contacting an authentication handler.
func TestSSHHostKeysBeforeAuth(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	var auth atomic.Int32
	cfg := &ssh.ServerConfig{ServerVersion: "SSH-2.0-local_fixture", NoClientAuth: true,
		AuthLogCallback: func(ssh.ConnMetadata, string, error) { auth.Add(1) }}
	cfg.AddHostKey(signer)
	var profiles []HostProfile
	for _, mac := range []string{"02:00:00:00:00:11", "02:00:00:00:00:12"} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			conn, err := ln.Accept()
			if err == nil {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				_, _, _, err = ssh.NewServerConn(conn, cfg)
			}
			done <- err
		}()
		conn, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		info := observeSSH(conn, port, time.Second)
		conn.Close()
		ln.Close()
		if err := <-done; err == nil {
			t.Fatal("SSH session was established")
		}
		if info == nil || info.Port != port || info.Banner != cfg.ServerVersion || info.HostKeyType != ssh.KeyAlgoED25519 || info.HostKeyFingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
			t.Fatalf("wrong SSH observation: %+v", info)
		}
		profiles = append(profiles, HostProfile{Client: unifi.Client{MAC: mac}, SSH: info})
	}
	if auth.Load() != 0 {
		t.Fatalf("%d authentication attempts", auth.Load())
	}
	key := profiles[0].Client.MAC + "/" + strconv.Itoa(profiles[0].SSH.Port)
	previous := map[string]string{key: "older fingerprint"}
	next := CompareSSHHostKeys(profiles, previous)
	if !profiles[0].SSH.SharedHostKey || !profiles[1].SSH.SharedHostKey || !profiles[0].SSH.HostKeyChanged || profiles[1].SSH.HostKeyChanged ||
		next[key] != "older fingerprint" || previous[key] != "older fingerprint" {
		t.Fatalf("incorrect key comparison: %+v", next)
	}
}

// TestSSHKeyAuditSafetyAndPrivacy verifies private-key refusal, ephemeral
// canary rejection, hard per-host probe cap, RSA SHA-2 negotiation, and that
// accepted key maps are never serialized into JSON/webhook payloads.
func TestSSHKeyAuditSafetyAndPrivacy(t *testing.T) {
	dir := t.TempDir()
	privFile := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(privFile, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSSHPublicKeys([]string{privFile}); err == nil || !strings.Contains(strings.ToLower(err.Error()), "private key") {
		t.Fatalf("expected private key file to be refused, got %v", err)
	}

	// Generate an RSA key and an Ed25519 key to load from .pub files.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	edPubRaw, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, err := ssh.NewPublicKey(edPubRaw)
	if err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(dir, "audit.pub")
	if err := os.WriteFile(pubPath, append(ssh.MarshalAuthorizedKey(rsaPub), ssh.MarshalAuthorizedKey(edPub)...), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSSHPublicKeys([]string{pubPath})
	if err != nil || len(loaded) != 2 {
		t.Fatalf("LoadSSHPublicKeys failed: %v %+v", err, loaded)
	}

	// Host key for local test SSH servers.
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	hostFP := ssh.FingerprintSHA256(hostSigner.PublicKey())

	startServer := func(t *testing.T, acceptAll bool, acceptedFP string, attempts *atomic.Int32) string {
		t.Helper()
		cfg := &ssh.ServerConfig{
			ServerVersion: "SSH-2.0-local_audit",
			PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				attempts.Add(1)
				if acceptAll || ssh.FingerprintSHA256(key) == acceptedFP {
					return &ssh.Permissions{}, nil
				}
				return nil, fmt.Errorf("rejected")
			},
		}
		cfg.AddHostKey(hostSigner)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(2 * time.Second))
					_, _, _, _ = ssh.NewServerConn(c, cfg)
				}(conn)
			}
		}()
		return ln.Addr().String()
	}

	// 1. Canary false positive on SECOND username: must still discard all positives.
	var canaryConns atomic.Int32
	canaryCfg := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-local_audit",
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if conn.User() == "bob" {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("rejected")
		},
	}
	canaryCfg.AddHostKey(hostSigner)
	canaryLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { canaryLn.Close() })
	go func() {
		for {
			conn, err := canaryLn.Accept()
			if err != nil {
				return
			}
			canaryConns.Add(1)
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				_, _, _, _ = ssh.NewServerConn(c, canaryCfg)
			}(conn)
		}
	}()
	canaryInfo := &SSHInfo{Port: 22, HostKeyFingerprint: hostFP}
	AuditSSHKeys(context.Background(), canaryLn.Addr().String(), loaded[:1], []string{"alice", "bob"}, 3, 2*time.Second, canaryInfo)
	if !canaryInfo.CanaryFalsePositive || len(canaryInfo.AcceptedKeys) != 0 {
		t.Fatalf("per-username canary PK_OK must discard positives: %+v", canaryInfo)
	}

	// 2. Normal server accepting only rsaPub: negotiates rsa-sha2-512/256, respects
	//    strict <= 3 total connection cap (including canary), refuses to run when
	//    HostKeyChanged is set, and never leaks AcceptedKeys into JSON.
	var normalConns atomic.Int32
	rsaFP := ssh.FingerprintSHA256(rsaPub)
	normalAddr := startServer(t, false, rsaFP, &normalConns)
	changedInfo := &SSHInfo{Port: 22, HostKeyFingerprint: hostFP, HostKeyChanged: true}
	AuditSSHKeys(context.Background(), normalAddr, loaded, []string{"alice"}, 3, 2*time.Second, changedInfo)
	if normalConns.Load() != 0 {
		t.Fatalf("changed host key must block audit before connecting, got %d callbacks", normalConns.Load())
	}

	info := &SSHInfo{Port: 22, HostKeyFingerprint: hostFP}
	AuditSSHKeys(context.Background(), normalAddr, loaded, []string{"alice", "bob", "charlie", "dave"}, 3, 2*time.Second, info)
	if info.CanaryFalsePositive || len(info.AcceptedKeys) == 0 {
		t.Fatalf("expected accepted RSA key(s) within cap=3, got %+v", info)
	}
	got := info.AcceptedKeys[0]
	if got.Fingerprint != rsaFP || (got.Algorithm != ssh.KeyAlgoRSASHA512 && got.Algorithm != ssh.KeyAlgoRSASHA256) {
		t.Fatalf("expected RSA SHA-2 PK_OK, got %+v", got)
	}
	rawJSON, err := json.Marshal(HostProfile{Client: unifi.Client{IP: "192.0.2.5"}, SSH: info})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawJSON), rsaFP) || strings.Contains(string(rawJSON), "alice") || strings.Contains(string(rawJSON), "accepted_keys") {
		t.Fatalf("SSH key map leaked into serialized JSON: %s", rawJSON)
	}

	// 3. SMBv1 read-only NEGOTIATE (including signing flags) and malformed/valid SSH KEXINIT parsing.
	c1, s1 := net.Pipe()
	go func() {
		defer s1.Close()
		var hdr [4]byte
		if _, err := io.ReadFull(s1, hdr[:]); err != nil {
			return
		}
		req := make([]byte, binary.BigEndian.Uint32(hdr[:]))
		_, _ = io.ReadFull(s1, req)
		resp := make([]byte, 4+36)
		binary.BigEndian.PutUint32(resp[:4], 36)
		copy(resp[4:8], "\xffSMB")
		resp[8] = 0x72
		resp[36] = 17   // WordCount=17 (NT LM 0.12)
		resp[39] = 0x0c // Signing enabled (0x04) + signing required (0x08)
		_, _ = s1.Write(resp)
	}()
	v1OK, v1SignEn, v1SignReq := negotiateSMBv1(c1, time.Second)
	c1.Close()
	if !v1OK || !v1SignEn || !v1SignReq {
		t.Fatalf("expected negotiateSMBv1 to detect SMBv1 + signing required, got ok=%v en=%v req=%v", v1OK, v1SignEn, v1SignReq)
	}

	// Malformed KEXINIT with large padLen (4+pktLen-padLen < 22) must never panic.
	malformed := make([]byte, 24)
	binary.BigEndian.PutUint32(malformed[:4], 20)
	malformed[4] = 18
	malformed[5] = 20
	if wk, wc, wm := parseServerKexInit(malformed); len(wk)+len(wc)+len(wm) != 0 {
		t.Fatalf("malformed KEXINIT should return empty, got %v %v %v", wk, wc, wm)
	}

	// Build a minimal unencrypted SSH_MSG_KEXINIT packet advertising weak algorithms.
	var payload []byte
	payload = append(payload, 20)
	payload = append(payload, make([]byte, 16)...)
	for _, list := range []string{"diffie-hellman-group1-sha1", "ssh-ed25519", "aes128-cbc", "aes128-cbc", "hmac-sha1", "hmac-sha1"} {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(list)))
		payload = append(payload, l[:]...)
		payload = append(payload, list...)
	}
	pkt := make([]byte, 4+1+len(payload)+4)
	binary.BigEndian.PutUint32(pkt[:4], uint32(1+len(payload)+4))
	pkt[4] = 4
	copy(pkt[5:], payload)
	wk, wc, wm := parseServerKexInit(pkt)
	if len(wk) != 1 || len(wc) != 1 || len(wm) != 1 {
		t.Fatalf("expected weak kex/cipher/mac from KEXINIT, got kex=%v cipher=%v mac=%v", wk, wc, wm)
	}
}
