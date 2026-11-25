// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package unifi

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Event represents a real-time notification pushed by a UniFi controller over
// its WebSocket event stream.
type Event struct {
	// Message identifies the UniFi event stream topic (e.g., "sta:sync", "events", "device:sync").
	Message string `json:"message"`

	// Raw holds the decoded event payload objects for downstream inspection.
	Data []map[string]any `json:"data,omitempty"`
}

// SupportsWebSocket reports whether the active controller session can subscribe
// to UniFi's real-time WebSocket event stream. Ubiquiti's Integration API v1
// (X-API-Key) is currently REST-only, while cookie-authenticated UniFi OS and
// classic controllers support native WebSocket push.
func (c *Controller) SupportsWebSocket() bool {
	c.authMu.RLock()
	ct := c.controllerType
	c.authMu.RUnlock()
	return c.apiKey == "" && (ct == controllerUniFiOS || ct == controllerClassic)
}

// SubscribeEvents opens a read-only RFC 6455 WebSocket connection to UniFi's
// site event stream using the controller's active session cookies and forwards
// decoded events onto out until ctx is cancelled or the connection closes.
func (c *Controller) SubscribeEvents(ctx context.Context, out chan<- Event) error {
	c.authMu.RLock()
	ct := c.controllerType
	apiPrefix := c.apiPrefix
	site := c.site
	c.authMu.RUnlock()

	if c.apiKey != "" || (ct != controllerUniFiOS && ct != controllerClassic) {
		return fmt.Errorf("websocket events require cookie-authenticated session (active mode=%s)", ct)
	}

	parsed, err := url.Parse(c.baseURL)
	if err != nil {
		return fmt.Errorf("parse controller url: %w", err)
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	dialAddr := net.JoinHostPort(parsed.Hostname(), port)
	hostHeader := parsed.Host
	if hostHeader == "" {
		hostHeader = dialAddr
	}

	basePath := strings.TrimRight(parsed.Path, "/")
	wsPath := fmt.Sprintf("%s%s/wss/s/%s/events", basePath, apiPrefix, site)

	// Collect active session cookies from the controller's cookie jar.
	var cookiePairs []string
	if c.httpClient.Jar != nil {
		for _, ck := range c.httpClient.Jar.Cookies(parsed) {
			cookiePairs = append(cookiePairs, ck.Name+"="+ck.Value)
		}
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	if parsed.Scheme == "http" {
		conn, err = dialer.DialContext(ctx, "tcp", dialAddr)
	} else {
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config: &tls.Config{
				InsecureSkipVerify: c.insecureSkipVerify, //nolint:gosec // controlled by unifi.insecure_skip_verify
				ServerName:         parsed.Hostname(),
			},
		}
		conn, err = tlsDialer.DialContext(ctx, "tcp", dialAddr)
	}
	if err != nil {
		return fmt.Errorf("dial unifi websocket %s: %w", dialAddr, err)
	}
	defer conn.Close()

	// Cancel blocking reads immediately when ctx is done.
	stopWatch := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stopWatch()

	// Bound the upgrade handshake so a stalled server cannot hang the event loop.
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	keyBytes := make([]byte, 16)
	_, _ = rand.Read(keyBytes)
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	var reqBuf strings.Builder
	fmt.Fprintf(&reqBuf, "GET %s HTTP/1.1\r\n", wsPath)
	fmt.Fprintf(&reqBuf, "Host: %s\r\n", hostHeader)
	reqBuf.WriteString("Upgrade: websocket\r\n")
	reqBuf.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&reqBuf, "Sec-WebSocket-Key: %s\r\n", wsKey)
	reqBuf.WriteString("Sec-WebSocket-Version: 13\r\n")
	if len(cookiePairs) > 0 {
		fmt.Fprintf(&reqBuf, "Cookie: %s\r\n", strings.Join(cookiePairs, "; "))
	}
	reqBuf.WriteString("\r\n")

	if _, err := io.WriteString(conn, reqBuf.String()); err != nil {
		return fmt.Errorf("write websocket upgrade: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return fmt.Errorf("read websocket upgrade response: %w", err)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Session cookie expired; trigger a single-flight re-login so the next
		// redial immediately succeeds with fresh credentials.
		_ = c.relogin(ctx, c.currentAuthEpoch())
		return fmt.Errorf("websocket upgrade rejected: HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("websocket upgrade rejected: HTTP %d", resp.StatusCode)
	}
	_ = conn.SetDeadline(time.Time{})

	var fragBuf []byte
	inFragText := false
	for {
		fin, opcode, payload, err := readWSFrame(br)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		switch opcode {
		case 0x8: // Close frame
			return io.EOF
		case 0x9: // Ping -> reply with masked Pong
			_ = writeWSPong(conn, payload)
			continue
		case 0xa: // Pong
			continue
		case 0x1: // Text frame (start of single or fragmented text message)
			if !fin {
				fragBuf = append(fragBuf[:0], payload...)
				inFragText = true
				continue
			}
			inFragText = false
			fragBuf = fragBuf[:0]
			if err := emitWSEvent(ctx, out, payload); err != nil {
				return nil
			}
		case 0x0: // Continuation frame
			if !inFragText {
				continue
			}
			if len(fragBuf)+len(payload) > 8<<20 {
				return fmt.Errorf("websocket fragmented message too large")
			}
			fragBuf = append(fragBuf, payload...)
			if fin {
				msg := append([]byte(nil), fragBuf...)
				fragBuf = fragBuf[:0]
				inFragText = false
				if err := emitWSEvent(ctx, out, msg); err != nil {
					return nil
				}
			}
		default:
			// Ignore non-text data frames (e.g., binary 0x2) and reset text fragment state.
			inFragText = false
			fragBuf = fragBuf[:0]
		}
	}
}

func emitWSEvent(ctx context.Context, out chan<- Event, payload []byte) error {
	var frame struct {
		Meta struct {
			Message string `json:"message"`
		} `json:"meta"`
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(payload, &frame); err != nil || frame.Meta.Message == "" {
		return nil
	}
	select {
	case out <- Event{Message: frame.Meta.Message, Data: frame.Data}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// readWSFrame reads a single RFC 6455 WebSocket frame from r (server-to-client
// frames are unmasked per RFC 6455 section 5.1).
func readWSFrame(r *bufio.Reader) (bool, byte, []byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return false, 0, nil, err
	}
	fin := (hdr[0] & 0x80) != 0
	opcode := hdr[0] & 0x0f
	masked := (hdr[1] & 0x80) != 0
	length := uint64(hdr[1] & 0x7f)

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = uint64(ext[0])<<8 | uint64(ext[1])
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = 0
		for _, b := range ext {
			length = (length << 8) | uint64(b)
		}
	}
	if length > 8<<20 {
		return false, 0, nil, fmt.Errorf("websocket frame too large: %d bytes", length)
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return false, 0, nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return false, 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return fin, opcode, payload, nil
}

// writeWSPong sends a client-masked RFC 6455 Pong control frame.
func writeWSPong(w io.Writer, payload []byte) error {
	if len(payload) > 125 {
		payload = payload[:125]
	}
	var mask [4]byte
	_, _ = rand.Read(mask[:])
	frame := make([]byte, 0, 6+len(payload))
	frame = append(frame, 0x8a, byte(0x80|len(payload)), mask[0], mask[1], mask[2], mask[3])
	for i, b := range payload {
		frame = append(frame, b^mask[i%4])
	}
	_, err := w.Write(frame)
	return err
}
