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
	return c.apiKey == "" && (c.controllerType == controllerUniFiOS || c.controllerType == controllerClassic)
}

// SubscribeEvents opens a read-only RFC 6455 WebSocket connection to UniFi's
// site event stream using the controller's active session cookies and forwards
// decoded events onto out until ctx is cancelled or the connection closes.
func (c *Controller) SubscribeEvents(ctx context.Context, out chan<- Event) error {
	if !c.SupportsWebSocket() {
		return fmt.Errorf("websocket events require cookie-authenticated session (active mode=%s)", c.controllerType)
	}

	parsed, err := url.Parse(c.baseURL)
	if err != nil {
		return fmt.Errorf("parse controller url: %w", err)
	}
	host := parsed.Host
	if !strings.Contains(host, ":") {
		if parsed.Scheme == "http" {
			host += ":80"
		} else {
			host += ":443"
		}
	}

	wsPath := fmt.Sprintf("%s/wss/s/%s/events", c.apiPrefix, c.site)

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
		conn, err = dialer.DialContext(ctx, "tcp", host)
	} else {
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // local gateways routinely use self-signed certs
		}
		conn, err = tlsDialer.DialContext(ctx, "tcp", host)
	}
	if err != nil {
		return fmt.Errorf("dial unifi websocket %s: %w", host, err)
	}
	defer conn.Close()

	// Cancel blocking reads immediately when ctx is done.
	stopWatch := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stopWatch()

	keyBytes := make([]byte, 16)
	_, _ = rand.Read(keyBytes)
	wsKey := base64.StdEncoding.EncodeToString(keyBytes)

	var reqBuf strings.Builder
	fmt.Fprintf(&reqBuf, "GET %s HTTP/1.1\r\n", wsPath)
	fmt.Fprintf(&reqBuf, "Host: %s\r\n", host)
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
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("websocket upgrade rejected: HTTP %d", resp.StatusCode)
	}

	for {
		opcode, payload, err := readWSFrame(br)
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
		case 0x1: // Text frame
			var frame struct {
				Meta struct {
					Message string `json:"message"`
				} `json:"meta"`
				Data []map[string]any `json:"data"`
			}
			if err := json.Unmarshal(payload, &frame); err != nil || frame.Meta.Message == "" {
				continue
			}
			select {
			case out <- Event{Message: frame.Meta.Message, Data: frame.Data}:
			case <-ctx.Done():
				return nil
			}
		}
	}
}

// readWSFrame reads a single RFC 6455 WebSocket frame from r (server-to-client
// frames are unmasked per RFC 6455 section 5.1).
func readWSFrame(r *bufio.Reader) (byte, []byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	opcode := hdr[0] & 0x0f
	masked := (hdr[1] & 0x80) != 0
	length := uint64(hdr[1] & 0x7f)

	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(ext[0])<<8 | uint64(ext[1])
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return 0, nil, err
		}
		length = 0
		for _, b := range ext {
			length = (length << 8) | uint64(b)
		}
	}
	if length > 8<<20 {
		return 0, nil, fmt.Errorf("websocket frame too large: %d bytes", length)
	}

	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return opcode, payload, nil
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
