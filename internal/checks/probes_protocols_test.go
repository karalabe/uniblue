// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHigherLevelAppAndLANProtocolProbes(t *testing.T) {
	ctx := context.Background()

	// 1. Bitcoin P2P version handshake simulator (positive mainnet vs garbage negative).
	t.Run("bitcoin_p2p", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		_, portStr, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := strconv.Atoi(portStr)

		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					reqHdr := make([]byte, 24)
					if _, err := io.ReadFull(conn, reqHdr); err != nil {
						return
					}
					reqLen := binary.LittleEndian.Uint32(reqHdr[16:20])
					if reqLen > 4096 {
						return
					}
					_, _ = io.ReadFull(conn, make([]byte, reqLen))

					var pl bytes.Buffer
					_ = binary.Write(&pl, binary.LittleEndian, int32(70016))
					_ = binary.Write(&pl, binary.LittleEndian, uint64(1))
					_ = binary.Write(&pl, binary.LittleEndian, time.Now().Unix())
					pl.Write(make([]byte, 60)) // addr_recv + addr_from + nonce
					ua := "/Satoshi:27.0.0/"
					pl.WriteByte(byte(len(ua)))
					pl.WriteString(ua)
					_ = binary.Write(&pl, binary.LittleEndian, int32(870000))
					pl.WriteByte(0x01)

					pb := pl.Bytes()
					s1 := sha256.Sum256(pb)
					s2 := sha256.Sum256(s1[:])
					var resp bytes.Buffer
					resp.Write([]byte{0xf9, 0xbe, 0xb4, 0xd9})
					cmd := [12]byte{'v', 'e', 'r', 's', 'i', 'o', 'n'}
					resp.Write(cmd[:])
					_ = binary.Write(&resp, binary.LittleEndian, uint32(len(pb)))
					resp.Write(s2[:4])
					resp.Write(pb)
					_, _ = conn.Write(resp.Bytes())
				}(c)
			}
		}()

		ev, ok := probeBitcoinP2P(ctx, "127.0.0.1", port)
		if !ok || !strings.Contains(ev, "/Satoshi:27.0.0/") || !strings.Contains(ev, "mainnet") {
			t.Fatalf("expected Bitcoin P2P match with Satoshi agent, got ok=%v ev=%q", ok, ev)
		}
	})

	// 2. Bitcoin RPC (unauth 200 vs authenticated 401 vs unrelated JSON counterexample).
	t.Run("bitcoin_rpc", func(t *testing.T) {
		r := NewRunner(nil, 1)
		unauthSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, _ = io.WriteString(w, `{"id":"uniblue","result":{"version":270000,"subversion":"/Satoshi:27.0.0/","protocolversion":70016},"error":null}`)
		}))
		defer unauthSrv.Close()
		_, p1, _ := net.SplitHostPort(unauthSrv.Listener.Addr().String())
		port1, _ := strconv.Atoi(p1)

		authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.Header().Set("WWW-Authenticate", `Basic realm="jsonrpc"`)
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer authSrv.Close()
		_, p2, _ := net.SplitHostPort(authSrv.Listener.Addr().String())
		port2, _ := strconv.Atoi(p2)

		unrelatedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, _ = io.WriteString(w, `{"result":{"version":1}}`)
		}))
		defer unrelatedSrv.Close()
		_, p3, _ := net.SplitHostPort(unrelatedSrv.Listener.Addr().String())
		port3, _ := strconv.Atoi(p3)

		if ev, ok := r.probeBitcoinRPC(ctx, "127.0.0.1", port1); !ok || !strings.Contains(ev, "Satoshi:27.0.0") {
			t.Fatalf("expected unauth Bitcoin RPC match, got ok=%v ev=%q", ok, ev)
		}
		if _, ok := r.probeBitcoinRPC(ctx, "127.0.0.1", port2); ok {
			t.Fatal("401-authenticated Bitcoin RPC must NOT match")
		}
		if _, ok := r.probeBitcoinRPC(ctx, "127.0.0.1", port3); ok {
			t.Fatal("unrelated JSON {\"result\":{\"version\":1}} must NOT trigger Bitcoin RPC")
		}
	})

	// 3. Ethereum Engine API (missing JWT vs 401 JWT-enforced vs unrelated JSON).
	t.Run("eth_engine_api", func(t *testing.T) {
		r := NewRunner(nil, 1)
		openSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":["engine_newPayloadV3","engine_forkchoiceUpdatedV3"]}`)
		}))
		defer openSrv.Close()
		_, p1, _ := net.SplitHostPort(openSrv.Listener.Addr().String())
		port1, _ := strconv.Atoi(p1)

		jwtSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer jwtSrv.Close()
		_, p2, _ := net.SplitHostPort(jwtSrv.Listener.Addr().String())
		port2, _ := strconv.Atoi(p2)

		unrelatedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":["status"]}`)
		}))
		defer unrelatedSrv.Close()
		_, p3, _ := net.SplitHostPort(unrelatedSrv.Listener.Addr().String())
		port3, _ := strconv.Atoi(p3)

		if ev, ok := r.probeEthEngineAPI(ctx, "127.0.0.1", port1); !ok || !strings.Contains(ev, "2 capabilities") {
			t.Fatalf("expected unauth Eth Engine API match, got ok=%v ev=%q", ok, ev)
		}
		if _, ok := r.probeEthEngineAPI(ctx, "127.0.0.1", port2); ok {
			t.Fatal("JWT-protected Eth Engine API must NOT match")
		}
		if _, ok := r.probeEthEngineAPI(ctx, "127.0.0.1", port3); ok {
			t.Fatal("unrelated JSON {\"result\":[\"status\"]} must NOT trigger Eth Engine API")
		}
	})

	// 4. NUT upsd read-only VER + LIST UPS.
	t.Run("nut_upsd", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		_, pStr, _ := net.SplitHostPort(ln.Addr().String())
		port, _ := strconv.Atoi(pStr)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func(conn net.Conn) {
					defer conn.Close()
					buf := make([]byte, 128)
					n, _ := conn.Read(buf)
					if strings.HasPrefix(string(buf[:n]), "VER") {
						_, _ = conn.Write([]byte("Network UPS Tools upsd 2.8.1\n"))
					}
					n, _ = conn.Read(buf)
					if strings.HasPrefix(string(buf[:n]), "LIST UPS") {
						_, _ = conn.Write([]byte("BEGIN LIST UPS\nUPS rackups \"Rack APC\"\nEND LIST UPS\n"))
					}
				}(c)
			}
		}()
		ev, ok := probeNUT(ctx, "127.0.0.1", port)
		if !ok || !strings.Contains(ev, "1 UPS unit(s)") {
			t.Fatalf("expected NUT match with 1 UPS, got ok=%v ev=%q", ok, ev)
		}
	})

	// 5. PJLink (PJLINK 0 unauthenticated vs PJLINK 1 password-protected).
	t.Run("pjlink", func(t *testing.T) {
		startBanner := func(banner string) int {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			_, ps, _ := net.SplitHostPort(ln.Addr().String())
			p, _ := strconv.Atoi(ps)
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					_, _ = c.Write([]byte(banner))
					_ = c.Close()
				}
			}()
			return p
		}
		pOpen := startBanner("PJLINK 0\r")
		pAuth := startBanner("PJLINK 1 498e4a67\r")
		if _, ok := probePJLink(ctx, "127.0.0.1", pOpen); !ok {
			t.Fatal("expected PJLINK 0 to match unauthenticated projector")
		}
		if _, ok := probePJLink(ctx, "127.0.0.1", pAuth); ok {
			t.Fatal("PJLINK 1 password-protected projector must NOT match")
		}
	})

	// 6. UDP protocol probes: LIFX, NBNS, PCP v2, DNS Recursion, NTP, STUN.
	t.Run("udp_protocols", func(t *testing.T) {
		startUDP := func(handler func([]byte) []byte) int {
			pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen udp: %v", err)
			}
			t.Cleanup(func() { _ = pc.Close() })
			_, ps, _ := net.SplitHostPort(pc.LocalAddr().String())
			p, _ := strconv.Atoi(ps)
			go func() {
				buf := make([]byte, 1024)
				for {
					n, addr, err := pc.ReadFrom(buf)
					if err != nil {
						return
					}
					if reply := handler(buf[:n]); len(reply) > 0 {
						_, _ = pc.WriteTo(reply, addr)
					}
				}
			}()
			return p
		}

		lifxPort := startUDP(func(req []byte) []byte {
			if len(req) < 36 || binary.LittleEndian.Uint16(req[32:34]) != 32 {
				return nil
			}
			rep := make([]byte, 48)
			binary.LittleEndian.PutUint16(rep[0:2], 48)
			binary.LittleEndian.PutUint16(rep[2:4], 0x1400) // protocol 1024
			binary.LittleEndian.PutUint16(rep[32:34], 33)   // StateVersion
			binary.LittleEndian.PutUint32(rep[36:40], 1)    // LIFX vendor
			binary.LittleEndian.PutUint32(rep[40:44], 27)   // A19 product
			return rep
		})
		if ev, ok := probeLIFX(ctx, "127.0.0.1", lifxPort); !ok || !strings.Contains(ev, "product=27") {
			t.Fatalf("expected LIFX StateVersion match, got ok=%v ev=%q", ok, ev)
		}

		nbnsPort := startUDP(func(req []byte) []byte {
			if len(req) < 50 {
				return nil
			}
			rep := make([]byte, 57+18)
			rep[0], rep[1] = req[0], req[1]
			rep[2] = 0x84 // response
			rep[56] = 1   // 1 name
			rep[57+15] = 0x20
			return rep
		})
		if ev, ok := probeNBNS(ctx, "127.0.0.1", nbnsPort); !ok || !strings.Contains(ev, "file-server") {
			t.Fatalf("expected NBNS file-server match, got ok=%v ev=%q", ok, ev)
		}

		pcpPort := startUDP(func(req []byte) []byte {
			if len(req) < 24 || req[0] != 2 || req[1] != 0 {
				return nil
			}
			rep := make([]byte, 24)
			rep[0] = 2
			rep[1] = 0x80 // ANNOUNCE response
			rep[3] = 0    // SUCCESS
			binary.BigEndian.PutUint32(rep[8:12], 4200)
			return rep
		})
		if ev, ok := probePCP(ctx, "127.0.0.1", pcpPort); !ok || !strings.Contains(ev, "epoch=4200") {
			t.Fatalf("expected PCP v2 ANNOUNCE match, got ok=%v ev=%q", ok, ev)
		}

		dnsRecPort := startUDP(func(req []byte) []byte {
			if len(req) < 12 {
				return nil
			}
			rep := make([]byte, 12)
			rep[0], rep[1] = req[0], req[1]
			binary.BigEndian.PutUint16(rep[2:4], 0x8180) // QR=1, RD=1, RA=1, NOERROR
			binary.BigEndian.PutUint16(rep[6:8], 1)      // ANCOUNT=1
			return rep
		})
		dnsServfailPort := startUDP(func(req []byte) []byte {
			rep := make([]byte, 12)
			rep[0], rep[1] = req[0], req[1]
			binary.BigEndian.PutUint16(rep[2:4], 0x8182) // QR=1, RA=1, SERVFAIL, ANCOUNT=0
			return rep
		})
		dnsRefusedPort := startUDP(func(req []byte) []byte {
			rep := make([]byte, 12)
			rep[0], rep[1] = req[0], req[1]
			binary.BigEndian.PutUint16(rep[2:4], 0x8105) // QR=1, RA=0, REFUSED
			return rep
		})
		if _, ok := probeDNSRecursion(ctx, "127.0.0.1", dnsRecPort); !ok {
			t.Fatal("expected DNS recursion RA=1 NOERROR with answer to match")
		}
		if _, ok := probeDNSRecursion(ctx, "127.0.0.1", dnsServfailPort); ok {
			t.Fatal("DNS SERVFAIL with 0 answers must NOT match confirmed recursion")
		}
		if _, ok := probeDNSRecursion(ctx, "127.0.0.1", dnsRefusedPort); ok {
			t.Fatal("DNS REFUSED/RA=0 must NOT match recursion check")
		}

		ntpPort := startUDP(func(req []byte) []byte {
			if len(req) < 48 {
				return nil
			}
			rep := make([]byte, 48)
			rep[0] = 0x24 // VN=4, Mode=4 (server)
			rep[1] = 2    // Stratum 2
			return rep
		})
		if ev, ok := probeNTP(ctx, "127.0.0.1", ntpPort); !ok || !strings.Contains(ev, "stratum=2") {
			t.Fatalf("expected NTP server stratum=2 match, got ok=%v ev=%q", ok, ev)
		}

		stunPort := startUDP(func(req []byte) []byte {
			if len(req) < 20 {
				return nil
			}
			rep := make([]byte, 20)
			binary.BigEndian.PutUint16(rep[0:2], 0x0101)
			copy(rep[4:20], req[4:20])
			return rep
		})
		if _, ok := probeSTUN(ctx, "127.0.0.1", stunPort); !ok {
			t.Fatal("expected STUN Binding Success Response match")
		}
	})
}
