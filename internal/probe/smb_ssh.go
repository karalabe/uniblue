// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package probe

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/karalabe/uniblue/internal/config"
	"golang.org/x/crypto/ssh"
)

// SMBInfo describes the capabilities advertised during SMB protocol negotiation.
type SMBInfo struct {
	// Dialect is the protocol revision selected by the server (e.g., "3.1.1" or "1.0").
	Dialect string `json:"dialect"`
	// SigningEnabled records the server's signing support flag.
	SigningEnabled bool `json:"signing_enabled"`
	// SigningRequired records whether the server requires message signing.
	SigningRequired bool `json:"signing_required"`
	// EncryptionSupported describes server capability. Individual shares can use different settings.
	EncryptionSupported bool `json:"encryption_supported"`
	// SMBv1Enabled reports whether the server accepted legacy SMBv1 (NT LM 0.12) negotiation.
	SMBv1Enabled bool `json:"smbv1_enabled,omitempty"`
}

// negotiateSMB sends a single SMB2 NEGOTIATE message offering all standard
// dialects and all four SMB 3.1.1 encryption ciphers. No session is opened.
func negotiateSMB(conn net.Conn, timeout time.Duration) *SMBInfo {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	le := binary.LittleEndian
	// The 4-byte NetBIOS header precedes the 64-byte SMB2 header. Negotiate
	// context offsets are relative to the SMB2 header and 8-byte aligned.
	frame := make([]byte, 4+178)
	binary.BigEndian.PutUint32(frame, uint32(len(frame)-4))
	msg := frame[4:]
	copy(msg, "\xfeSMB")
	le.PutUint16(msg[4:], 64) // StructureSize (64-byte SMB2 header)
	le.PutUint16(msg[14:], 1) // CreditRequest = 1
	body := msg[64:]
	dialects := [...]uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}
	le.PutUint16(body, 36)                        // NEGOTIATE request StructureSize
	le.PutUint16(body[2:], uint16(len(dialects))) // DialectCount
	le.PutUint16(body[4:], 1)                     // SecurityMode: signing enabled
	le.PutUint32(body[8:], 0x40)                  // Capabilities: SMB2_GLOBAL_CAP_ENCRYPTION
	rand.Read(body[12:28])                        // ClientGuid
	le.PutUint32(body[28:], 112)                  // NegotiateContextOffset (64 hdr + 36 body + 10 dialects + 2 pad)
	le.PutUint16(body[32:], 2)                    // NegotiateContextCount
	for i, dialect := range dialects {
		le.PutUint16(body[36+2*i:], dialect)
	}
	preauth := msg[112:160]
	le.PutUint16(preauth, 1)       // SMB2_PREAUTH_INTEGRITY_CAPABILITIES
	le.PutUint16(preauth[2:], 38)  // DataLength (2 hash count + 2 salt len + 2 hash ID + 32 salt)
	le.PutUint16(preauth[8:], 1)   // HashAlgorithmCount
	le.PutUint16(preauth[10:], 32) // SaltLength
	le.PutUint16(preauth[12:], 1)  // SHA-512 with a fresh 32-byte salt.
	rand.Read(preauth[14:46])
	cipher := msg[160:]
	le.PutUint16(cipher, 2)      // SMB2_ENCRYPTION_CAPABILITIES
	le.PutUint16(cipher[2:], 10) // DataLength (2 count + 4*2 cipher IDs)
	le.PutUint16(cipher[8:], 4)  // Offer AES-128-CCM, AES-128-GCM, AES-256-CCM, AES-256-GCM.
	le.PutUint16(cipher[10:], 1)
	le.PutUint16(cipher[12:], 2)
	le.PutUint16(cipher[14:], 3)
	le.PutUint16(cipher[16:], 4)

	if _, err := conn.Write(frame); err != nil {
		return nil
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil
	}
	size := binary.BigEndian.Uint32(header[:])
	if size < 128 || size > 1<<16 {
		return nil
	}
	reply := make([]byte, size)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil
	}
	// Verify SMB2 magic, 64-byte header, STATUS_SUCCESS, NEGOTIATE command (0),
	// server-to-redir flag (bit 0), NextCommand=0, MessageId=0, and NEGOTIATE
	// response StructureSize=65.
	if !bytes.Equal(reply[:4], msg[:4]) || le.Uint16(reply[4:]) != 64 ||
		le.Uint32(reply[8:]) != 0 || le.Uint16(reply[12:]) != 0 ||
		le.Uint32(reply[16:])&1 == 0 || le.Uint32(reply[20:]) != 0 ||
		le.Uint64(reply[24:]) != 0 || le.Uint16(reply[64:]) != 65 {
		return nil
	}
	// Offsets 66 and 68 hold SecurityMode (bit 0 enabled, bit 1 required) and DialectRevision.
	mode, dialect := le.Uint16(reply[66:]), le.Uint16(reply[68:])
	names := [...]string{"2.0.2", "2.1", "3.0", "3.0.2", "3.1.1"}
	for i, d := range dialects {
		if dialect != d {
			continue
		}
		// SMB 3.0/3.0.2 advertise encryption via Capabilities bit 0x40 at offset 88.
		encryption := d >= 0x0300 && le.Uint32(reply[88:])&0x40 != 0
		if d == 0x0311 {
			// SMB 3.1.1 servers select an encryption cipher in an 8-byte-aligned
			// negotiate context (offset at 124, count at 70, context type 2).
			offset := int(le.Uint32(reply[124:]))
			for range le.Uint16(reply[70:]) {
				if offset < 128 || offset%8 != 0 || offset > len(reply)-8 {
					return nil
				}
				ctx := reply[offset:]
				csize := int(le.Uint16(ctx[2:]))
				if csize > len(ctx)-8 {
					return nil
				}
				if le.Uint16(ctx) == 2 && csize >= 4 {
					count := int(le.Uint16(ctx[8:]))
					for j := 0; j < count && 10+2*j+2 <= 8+csize; j++ {
						if le.Uint16(ctx[10+2*j:]) != 0 {
							encryption = true
							break
						}
					}
				}
				offset += (8 + csize + 7) &^ 7
			}
		}
		return &SMBInfo{Dialect: names[i], SigningEnabled: mode&1 != 0, SigningRequired: mode&2 != 0, EncryptionSupported: encryption}
	}
	return nil
}

// negotiateSMBv1 sends a single read-only SMB1 NEGOTIATE offering only
// "NT LM 0.12" and reports whether the server accepts SMBv1 along with its
// advertised signing flags (SecurityMode bits 0x04/0x08). No session is opened.
func negotiateSMBv1(conn net.Conn, timeout time.Duration) (ok, signingEnabled, signingRequired bool) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	const dialect = "\x02NT LM 0.12\x00"
	frame := make([]byte, 4+32+1+2+len(dialect))
	binary.BigEndian.PutUint32(frame, uint32(len(frame)-4))
	msg := frame[4:]
	copy(msg[0:4], "\xffSMB")
	msg[4] = 0x72                                                 // SMB_COM_NEGOTIATE
	msg[9] = 0x18                                                 // Flags: canonicalized + case-insensitive paths
	binary.LittleEndian.PutUint16(msg[10:], 0x4801)               // Flags2: long names (0x0001), extended security (0x0800), NT status (0x4000)
	msg[32] = 0                                                   // WordCount
	binary.LittleEndian.PutUint16(msg[33:], uint16(len(dialect))) // ByteCount
	copy(msg[35:], dialect)

	if _, err := conn.Write(frame); err != nil {
		return false, false, false
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return false, false, false
	}
	size := binary.BigEndian.Uint32(header[:])
	if size < 35 || size > 1<<16 {
		return false, false, false
	}
	reply := make([]byte, size)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return false, false, false
	}
	le := binary.LittleEndian
	// Verify SMB1 magic, SMB_COM_NEGOTIATE, STATUS_SUCCESS, WordCount >= 1,
	// and DialectIndex == 0 (accepted our sole offered NT LM 0.12 dialect).
	accepted := bytes.Equal(reply[:4], []byte("\xffSMB")) &&
		reply[4] == 0x72 &&
		le.Uint32(reply[5:]) == 0 &&
		reply[32] >= 1 &&
		le.Uint16(reply[33:]) == 0
	if !accepted {
		return false, false, false
	}
	// NT LM 0.12 response carries SecurityMode at offset 35 when WordCount >= 17.
	if reply[32] >= 17 && len(reply) >= 36 {
		mode := reply[35]
		signingEnabled = mode&0x04 != 0
		signingRequired = mode&0x08 != 0
	}
	return true, signingEnabled, signingRequired
}

// sshPort reports whether port is a recognized SSH listener on this host (ports
// 22, 2222, or a non-forged _ssh._tcp mDNS advertisement targeting ProbeIP) so
// it is handled by the dedicated pre-auth SSH observer rather than generic probes.
func (h HostProfile) sshPort(port int) bool {
	if port == 22 || port == 2222 {
		return true
	}
	for _, md := range h.MDNSServices {
		if md.Type == "_ssh._tcp" && md.Port == port && (!md.Reflected || md.TrustedReflector) && slices.Contains(md.TargetIPs, h.ProbeIP) {
			return true
		}
	}
	return false
}

// SSHAcceptedKey records a single (username, public key fingerprint) pair that
// an SSH server invited during an opt-in RFC 4252 section 7 PK_OK or "none"
// query. All fields are excluded from JSON serialization so key-to-host maps
// never leak into webhooks, state files, or external logs.
type SSHAcceptedKey struct {
	// Username is the account name queried (PK_OK only invites a signed request and does not establish a successful login).
	Username string `json:"-"`
	// Fingerprint is the OpenSSH SHA-256 fingerprint of the invited public key (empty for "none" auth).
	Fingerprint string `json:"-"`
	// Algorithm is the offered public-key algorithm echoed in SSH_MSG_USERAUTH_PK_OK (not separately negotiated).
	Algorithm string `json:"-"`
	// KeyLabel is the basename of the local .pub file that supplied this key.
	KeyLabel string `json:"-"`
	// Method records how the server responded ("publickey-ok" or "none").
	Method string `json:"-"`
	// Note explains caveats such as MFA, ForceCommand, or source-IP restrictions.
	Note string `json:"-"`
}

// SSHPublicKey holds a parsed local OpenSSH public key and its SHA-256 fingerprint.
type SSHPublicKey struct {
	// Key is the parsed OpenSSH public key.
	Key ssh.PublicKey
	// Fingerprint is the OpenSSH SHA-256 fingerprint of Key.
	Fingerprint string
	// Label is the basename of the local .pub file used for operator display.
	Label string
}

// SSHInfo identifies an SSH listener by its greeting, verified key exchange,
// and server-offered KEX/cipher/MAC algorithms.
type SSHInfo struct {
	// Port is the observed TCP listener.
	Port int `json:"port"`
	// Banner is the server identification line.
	Banner string `json:"banner"`
	// HostKeyType is the public key format offered by the server.
	HostKeyType string `json:"host_key_type,omitempty"`
	// HostKeyFingerprint is the OpenSSH SHA-256 fingerprint of the public host key.
	HostKeyFingerprint string `json:"host_key_fingerprint,omitempty"`
	// SharedHostKey reports a matching key on another inventory device.
	SharedHostKey bool `json:"shared_host_key,omitempty"`
	// HostKeyChanged reports a different key at the same device and port since a previous scan.
	HostKeyChanged bool `json:"host_key_changed,omitempty"`
	// WeakKex lists weak key-exchange algorithms advertised in SSH_MSG_KEXINIT.
	WeakKex []string `json:"weak_kex,omitempty"`
	// WeakCiphers lists weak symmetric ciphers advertised in SSH_MSG_KEXINIT.
	WeakCiphers []string `json:"weak_ciphers,omitempty"`
	// WeakMACs lists weak MAC algorithms advertised in SSH_MSG_KEXINIT.
	WeakMACs []string `json:"weak_macs,omitempty"`
	// AuthMethods lists the methods offered after the credential-free SSH query.
	AuthMethods []string `json:"auth_methods,omitempty"`
	// NoneAuthAccepted reports that the server accepted SSH without credentials.
	NoneAuthAccepted bool `json:"none_auth_accepted,omitempty"`
	// BruteForceProtected is set when the host refuses connections mid-audit (Fail2ban/rate-limit signal).
	BruteForceProtected bool `json:"brute_force_protected,omitempty"`
	// CanaryFalsePositive is set when the server replied PK_OK to a random ephemeral key; positives are discarded.
	CanaryFalsePositive bool `json:"canary_false_positive,omitempty"`
	// AcceptedKeys stores opt-in PK_OK/none invitations (fingerprints only, never serialized to webhooks/JSON).
	AcceptedKeys []SSHAcceptedKey `json:"-"`
}

// sshGreetingConn captures the server's identification line and its first
// unencrypted binary packet (SSH_MSG_KEXINIT) as the SSH library reads them.
type sshGreetingConn struct {
	net.Conn
	line   []byte
	banner string
	kexBuf []byte
}

// Read records the SSH greeting line and initial unencrypted KEXINIT bytes while
// passing the exact stream through to the SSH key exchange.
func (c *sshGreetingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	data := b[:n]
	if c.banner == "" {
		for idx, ch := range data {
			if ch == '\n' {
				if bytes.HasPrefix(c.line, []byte("SSH-")) {
					c.banner = sanitizeBanner(string(c.line))
					data = data[idx+1:]
					break
				}
				c.line = c.line[:0]
			} else if len(c.line) < 255 {
				c.line = append(c.line, ch)
			}
		}
	}
	if c.banner != "" && len(data) > 0 && len(c.kexBuf) < 8192 {
		rem := min(len(data), 8192-len(c.kexBuf))
		c.kexBuf = append(c.kexBuf, data[:rem]...)
	}
	return n, err
}

// parseServerKexInit inspects the server's first unencrypted SSH binary packet
// (RFC 4253 SSH_MSG_KEXINIT, type 20) and returns any deprecated KEX, cipher,
// or MAC names.
func parseServerKexInit(buf []byte) (weakKex, weakCiphers, weakMACs []string) {
	// Binary packet framing: 4-byte packet_length and 1-byte padding_length,
	// followed by the KEXINIT payload prefix: 1-byte message type
	// (20 = SSH_MSG_KEXINIT) and 16-byte random cookie.
	if len(buf) < 22 {
		return nil, nil, nil
	}
	pktLen := int(binary.BigEndian.Uint32(buf[:4]))
	padLen := int(buf[4])
	end := 4 + pktLen - padLen
	if pktLen < 18 || pktLen > len(buf)-4 || padLen >= pktLen-1 || buf[5] != 20 || end < 22 {
		return nil, nil, nil
	}
	payload := buf[22:end]
	readList := func() ([]string, bool) {
		if len(payload) < 4 {
			return nil, false
		}
		n := binary.BigEndian.Uint32(payload[:4])
		payload = payload[4:]
		if uint64(n) > uint64(len(payload)) {
			return nil, false
		}
		raw := string(payload[:int(n)])
		payload = payload[int(n):]
		if raw == "" {
			return nil, true
		}
		return strings.Split(raw, ","), true
	}
	// RFC 4253 section 7.1 name-lists: [0] kex_algorithms, [1] server_host_key_algorithms,
	// [2..3] encryption_algorithms (c2s, s2c), [4..5] mac_algorithms (c2s, s2c).
	var lists [6][]string
	for i := range lists {
		var ok bool
		if lists[i], ok = readList(); !ok {
			return nil, nil, nil
		}
	}
	addUnique := func(dst *[]string, v string) {
		if !slices.Contains(*dst, v) {
			*dst = append(*dst, v)
		}
	}
	for _, k := range lists[0] {
		switch {
		case k == "diffie-hellman-group1-sha1",
			k == "diffie-hellman-group14-sha1",
			k == "diffie-hellman-group-exchange-sha1",
			strings.HasPrefix(k, "gss-group1-sha1-"),
			strings.HasPrefix(k, "gss-gex-sha1-"):
			addUnique(&weakKex, k)
		}
	}
	for _, list := range [][]string{lists[2], lists[3]} {
		for _, c := range list {
			switch {
			case c == "none", c == "3des-cbc", c == "blowfish-cbc", c == "cast128-cbc",
				strings.HasPrefix(c, "arcfour"), strings.HasSuffix(c, "-cbc"):
				addUnique(&weakCiphers, c)
			}
		}
	}
	for _, list := range [][]string{lists[4], lists[5]} {
		for _, m := range list {
			switch {
			case m == "none", m == "hmac-sha1",
				strings.HasPrefix(m, "hmac-md5"),
				strings.HasPrefix(m, "hmac-sha1-96"),
				strings.HasPrefix(m, "umac-64"):
				addUnique(&weakMACs, m)
			}
		}
	}
	return weakKex, weakCiphers, weakMACs
}

// sshClientVersion uses the module version when available and identifies local builds as dev.
var sshClientVersion = sync.OnceValue(func() string {
	if build, ok := debug.ReadBuildInfo(); ok && build.Main.Version != "" && build.Main.Version != "(devel)" {
		return "SSH-2.0-UniBlue_" + strings.ReplaceAll(build.Main.Version, "-", "_")
	}
	return "SSH-2.0-UniBlue_dev"
})

// sshWeakAlgorithmFindings builds Nerva-compatible ServiceFindings for any weak
// KEX, cipher, or MAC algorithms parsed from a server's SSH_MSG_KEXINIT packet.
func sshWeakAlgorithmFindings(obs *SSHInfo) []ServiceFinding {
	if obs == nil {
		return nil
	}
	var out []ServiceFinding
	if len(obs.WeakKex) > 0 {
		out = append(out, ServiceFinding{ID: "ssh-weak-kex", Severity: "medium", Evidence: "Weak SSH key exchange offered: " + strings.Join(obs.WeakKex, ", ")})
	}
	if len(obs.WeakCiphers) > 0 {
		out = append(out, ServiceFinding{ID: "ssh-weak-cipher", Severity: "medium", Evidence: "Weak SSH cipher offered: " + strings.Join(obs.WeakCiphers, ", ")})
	}
	if len(obs.WeakMACs) > 0 {
		out = append(out, ServiceFinding{ID: "ssh-weak-mac", Severity: "low", Evidence: "Weak SSH MAC offered: " + strings.Join(obs.WeakMACs, ", ")})
	}
	return out
}

// observeSSH ends the handshake at the host-key callback, before the SSH library
// requests the authentication service or sends a username.
func observeSSH(conn net.Conn, port int, timeout time.Duration) *SSHInfo {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	c := &sshGreetingConn{Conn: conn}
	info := SSHInfo{Port: port}
	_, _, _, _ = ssh.NewClientConn(c, conn.RemoteAddr().String(), &ssh.ClientConfig{
		ClientVersion: sshClientVersion(),
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			info.HostKeyType = key.Type()
			info.HostKeyFingerprint = ssh.FingerprintSHA256(key)
			return errors.New("host key recorded")
		},
	})
	info.Banner = c.banner
	if info.Banner == "" {
		return nil
	}
	info.WeakKex, info.WeakCiphers, info.WeakMACs = parseServerKexInit(c.kexBuf)
	return &info
}

// sshBaselineKey returns the stable inventory key used to track an SSH host key
// across scans, or "" when the host has no stable MAC or controller ID.
func sshBaselineKey(hp HostProfile, port int) string {
	host := config.CanonicalMAC(hp.Client.MAC)
	if host == "" {
		host = strings.TrimSpace(hp.Client.ID)
	}
	if host == "" {
		return ""
	}
	return host + "/" + strconv.Itoa(port)
}

// CompareSSHHostKeys marks shared and changed keys and returns the next scan baseline.
// Missing observations keep their previous key. Only stable inventory identities can establish a change.
func CompareSSHHostKeys(profiles []HostProfile, previous map[string]string) map[string]string {
	next := make(map[string]string, len(previous))
	maps.Copy(next, previous)
	owners := make(map[string]string)
	shared := make(map[string]bool)
	for _, hp := range profiles {
		s := hp.SSH
		if s == nil || s.HostKeyFingerprint == "" {
			continue
		}
		key := sshBaselineKey(hp, s.Port)
		if key == "" {
			continue
		}
		host, _, _ := strings.Cut(key, "/")
		if previous[key] != "" && previous[key] != s.HostKeyFingerprint {
			// Keep the previous fingerprint pinned until the operator verifies
			// or clears state so a replacement endpoint cannot silently become
			// trusted on the following watch/serve cycle.
			s.HostKeyChanged = true
		} else {
			next[key] = s.HostKeyFingerprint
		}
		if owner := owners[s.HostKeyFingerprint]; owner != "" && owner != host {
			shared[s.HostKeyFingerprint] = true
		}
		owners[s.HostKeyFingerprint] = host
	}
	for _, hp := range profiles {
		if hp.SSH != nil {
			hp.SSH.SharedHostKey = shared[hp.SSH.HostKeyFingerprint]
		}
	}
	return next
}

// SSHKeyAuditCache shares per-listener results between full and targeted scans.
type SSHKeyAuditCache struct {
	entries sync.Map // Stable listener identity to *SSHKeyAuditCacheEntry.
}

// SSHKeyAuditCacheEntry serializes queries for one listener across concurrent
// scans and tracks whether cached results cover auth methods only or a full
// key audit, along with positive TTL expiry and failure backoff deadlines.
type SSHKeyAuditCacheEntry struct {
	mu             sync.Mutex
	result         SSHInfo
	methodsQueried bool
	keysAudited    bool
	expiresAt      time.Time
	retryAfter     time.Time
}

// auditSSH queries advertised SSH authentication methods and, when opt-in key
// auditing is active and the host key has not changed, runs AuditSSHKeys on the
// same connection budget. Results are cached per listener for one hour with a
// five-minute backoff after failed probes.
func (f *Fingerprinter) auditSSH(ctx context.Context, hp *HostProfile) {
	info := hp.SSH
	if info == nil || info.HostKeyFingerprint == "" || f.isInfrastructure(*hp) || ctx.Err() != nil {
		return
	}
	key := sshBaselineKey(*hp, info.Port)
	if prev := f.prevSSHHostKeys[key]; prev != "" && prev != info.HostKeyFingerprint {
		info.HostKeyChanged = true
	}
	auditKeys := !info.HostKeyChanged && f.matchesSSHKeyAuditTarget(*hp)
	if f.DisableSSHAuthProbe && !auditKeys {
		return
	}
	ip, err := netip.ParseAddr(hp.EffectiveProbeIP())
	if err != nil {
		return
	}
	addr := net.JoinHostPort(ip.Unmap().String(), strconv.Itoa(info.Port))
	cacheKey := struct{ host, listener string }{key, addr}
	cached, _ := f.auditedSSHHosts.entries.LoadOrStore(cacheKey, new(SSHKeyAuditCacheEntry))
	entry := cached.(*SSHKeyAuditCacheEntry)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if ctx.Err() != nil {
		return
	}
	now := time.Now()
	// Clear the cached result and query flags when the listener presents a new
	// host key; any prior failure-backoff deadline remains active and can delay
	// the next query.
	if entry.result.HostKeyFingerprint != info.HostKeyFingerprint {
		entry.result = SSHInfo{HostKeyFingerprint: info.HostKeyFingerprint}
		entry.methodsQueried, entry.keysAudited = false, false
	}
	// Re-probe once any failure backoff has elapsed if the entry expired or a
	// newly requested probe tier (key audit or auth-method query) has not yet run.
	if !now.Before(entry.retryAfter) && (!now.Before(entry.expiresAt) || auditKeys && !entry.keysAudited || !f.DisableSSHAuthProbe && !entry.methodsQueried) {
		answer := SSHInfo{HostKeyFingerprint: info.HostKeyFingerprint}
		dropped := false
		if auditKeys {
			AuditSSHKeys(ctx, addr, f.sshAuditKeys, f.sshKeyAudit.Usernames, f.sshKeyAudit.MaxProbesPerHost, f.timeout, &answer)
		} else {
			answer.NoneAuthAccepted, _, dropped = probeSSHKeyBatch(ctx, addr, info.HostKeyFingerprint, "uniblue", nil, f.timeout, &answer.AuthMethods)
		}
		// Keep any authentication evidence received before a key audit was rate-limited.
		learned := answer.NoneAuthAccepted || len(answer.AuthMethods) > 0 || len(answer.AcceptedKeys) > 0
		if ctx.Err() == nil && learned && (!dropped || answer.BruteForceProtected) {
			entry.result = answer
			entry.methodsQueried, entry.keysAudited = true, auditKeys
			entry.expiresAt = now.Add(time.Hour)
			entry.retryAfter = time.Time{}
		} else if ctx.Err() == nil {
			// Keep the previous answer while backing off, even if successive probes fail.
			entry.retryAfter = now.Add(5 * time.Minute)
		}
	}
	result := &entry.result
	if !f.DisableSSHAuthProbe {
		info.AuthMethods = slices.Clone(result.AuthMethods)
	}
	info.NoneAuthAccepted = result.NoneAuthAccepted
	if auditKeys {
		info.AcceptedKeys = slices.Clone(result.AcceptedKeys)
		info.CanaryFalsePositive = result.CanaryFalsePositive
		info.BruteForceProtected = result.BruteForceProtected
	}
}

const (
	// maxSSHKeyConnsHardCap caps auth-attempting SSH connections per audit run.
	maxSSHKeyConnsHardCap = 3
	// maxSSHKeyQueriesHardCap caps total public-key queries per audit run
	// (each attempted username uses one ephemeral canary sharing this 4-query cap).
	maxSSHKeyQueriesHardCap = 4
)

// errPKOKConfirmed aborts ssh.NewClientConn as soon as PK_OK is observed so no
// private-key signature is ever computed or transmitted.
var errPKOKConfirmed = errors.New("ssh pk_ok confirmed without signing")

// LoadSSHPublicKeys reads local OpenSSH .pub files and returns deduplicated
// public keys with SHA-256 fingerprints. Any file containing a private key
// header is strictly refused.
func LoadSSHPublicKeys(paths []string) ([]SSHPublicKey, error) {
	var out []SSHPublicKey
	seen := make(map[string]bool)
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read ssh public key %q: %w", path, err)
		}
		if strings.Contains(strings.ToUpper(string(raw)), "PRIVATE KEY") {
			return nil, fmt.Errorf("refusing private key file %q: only OpenSSH public key (.pub) files are allowed", path)
		}
		label := filepath.Base(path)
		rest := raw
		parsedAny := false
		for len(bytes.TrimSpace(rest)) > 0 {
			pub, _, _, next, err := ssh.ParseAuthorizedKey(rest)
			if err != nil {
				// Skip blank lines and "#" comments between keys, and fail on malformed
				// newline-terminated lines (an unterminated trailing line breaks out of
				// the loop and is ignored if an earlier key was already parsed).
				idx := bytes.IndexByte(rest, '\n')
				if idx < 0 {
					break
				}
				line := bytes.TrimSpace(rest[:idx])
				rest = rest[idx+1:]
				if len(line) == 0 || line[0] == '#' {
					continue
				}
				return nil, fmt.Errorf("parse ssh public key %q: %w", path, err)
			}
			parsedAny = true
			rest = next
			fp := ssh.FingerprintSHA256(pub)
			if !seen[fp] {
				seen[fp] = true
				out = append(out, SSHPublicKey{Key: pub, Fingerprint: fp, Label: label})
			}
		}
		if !parsedAny {
			return nil, fmt.Errorf("no OpenSSH public key found in %q", path)
		}
	}
	return out, nil
}

// pkQuerySigner implements ssh.AlgorithmSigner without holding any private key.
// Go's ssh client performs an RFC 4252 section 7 query (HasSig=false) first and
// only invokes SignWithAlgorithm after the server replies SSH_MSG_USERAUTH_PK_OK,
// at which point we record the negotiated algorithm and abort immediately.
type pkQuerySigner struct {
	pub      ssh.PublicKey
	accepted bool
	algo     string
}

// PublicKey returns the queried public key without holding a private key.
func (s *pkQuerySigner) PublicKey() ssh.PublicKey { return s.pub }

// Sign delegates to SignWithAlgorithm to record PK_OK acceptance and abort.
func (s *pkQuerySigner) Sign(_ io.Reader, _ []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(nil, nil, s.pub.Type())
}

// SignWithAlgorithm records that the server invited this key via PK_OK and
// immediately returns errPKOKConfirmed so no signature is ever sent.
func (s *pkQuerySigner) SignWithAlgorithm(_ io.Reader, _ []byte, algorithm string) (*ssh.Signature, error) {
	s.accepted = true
	s.algo = algorithm
	return nil, errPKOKConfirmed
}

// probeSSHKeyBatch opens one bounded connection, verifies expectedHostKeyFP
// before sending any public key, and queries all signers on that same connection.
// It returns whether "none" authentication succeeded, the signer that received
// PK_OK (if any), and whether the server dropped or refused the connection.
func probeSSHKeyBatch(ctx context.Context, addr, expectedHostKeyFP, user string, signers []*pkQuerySigner, timeout time.Duration, methods *[]string) (noneOK bool, acceptedIdx int, connDropped bool) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, -1, true
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	rawSigners := make([]ssh.Signer, len(signers))
	for i, s := range signers {
		rawSigners[i] = s
	}
	var auth []ssh.AuthMethod
	if len(rawSigners) > 0 {
		auth = []ssh.AuthMethod{ssh.PublicKeys(rawSigners...)}
	}
	cc, _, _, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:          user,
		ClientVersion: sshClientVersion(),
		Auth:          auth,
		AuthCallback: func(ctx *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
			for _, method := range ctx.AllowedMethods {
				if !slices.Contains(*methods, method) {
					*methods = append(*methods, method)
				}
			}
			return nil, nil
		},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if expectedHostKeyFP == "" || ssh.FingerprintSHA256(key) != expectedHostKeyFP {
				return errors.New("ssh host key mismatch")
			}
			return nil
		},
		Timeout: timeout,
	})
	if err == nil {
		// Because pkQuerySigner never signs, a nil error means the server
		// accepted "none" authentication without any key or password.
		_ = cc.Close()
		return true, -1, false
	}
	for i, s := range signers {
		if s.accepted {
			return false, i, false
		}
	}
	lowErr := strings.ToLower(err.Error())
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) ||
		strings.Contains(lowErr, "connection reset") ||
		strings.Contains(lowErr, "too many authentication failures") ||
		strings.Contains(lowErr, "disconnect") {
		return false, -1, true
	}
	return false, -1, false
}

// AuditSSHKeys runs a strictly opt-in SSH "none" and PK_OK audit against one
// host. Per audit run, it caps auth-attempting connections at maxProbes
// (default 3, hard max 3) and total public-key queries at
// min(maxSSHKeyQueriesHardCap, maxProbes+1) (up to 4), with each attempted
// username generating its own ephemeral Ed25519 canary sharing that cap. It
// refuses to run when the host key changed, stops immediately on disconnects,
// and records each match's username, algorithm, key label, method, and caveat
// alongside its SHA-256 fingerprint (never private key material).
func AuditSSHKeys(ctx context.Context, addr string, keys []SSHPublicKey, usernames []string, maxProbes int, timeout time.Duration, info *SSHInfo) {
	if info == nil || info.HostKeyFingerprint == "" || info.HostKeyChanged || len(keys) == 0 || len(usernames) == 0 {
		return
	}
	if maxProbes <= 0 {
		maxProbes = maxSSHKeyConnsHardCap
	}
	if maxProbes > maxSSHKeyConnsHardCap {
		maxProbes = maxSSHKeyConnsHardCap
	}
	maxQueries := min(maxSSHKeyQueriesHardCap, maxProbes+1)

	connsUsed, queriesUsed := 0, 0
	seenUsers := make(map[string]bool)
	for _, rawUser := range usernames {
		user := strings.TrimSpace(rawUser)
		if user == "" || seenUsers[user] || connsUsed >= maxProbes || queriesUsed >= maxQueries {
			continue
		}
		seenUsers[user] = true

		// Generate a fresh ephemeral Ed25519 canary key per username so
		// per-account honeypots or broken sshd configs are always detected.
		canaryPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return
		}
		sshCanary, err := ssh.NewPublicKey(canaryPub)
		if err != nil {
			return
		}

		nextKey := 0
		testedCanary := false
		for nextKey < len(keys) && connsUsed < maxProbes && queriesUsed < maxQueries && ctx.Err() == nil {
			budget := maxQueries - queriesUsed
			var batch []*pkQuerySigner
			var keyIndices []int
			if !testedCanary {
				// Require budget for canary plus at least one configured key.
				if budget < 2 {
					return
				}
				batch = append(batch, &pkQuerySigner{pub: sshCanary})
				keyIndices = append(keyIndices, -1)
				testedCanary = true
				budget--
			}
			for i := nextKey; i < len(keys) && budget > 0; i++ {
				batch = append(batch, &pkQuerySigner{pub: keys[i].Key})
				keyIndices = append(keyIndices, i)
				budget--
			}
			connsUsed++
			noneOK, hit, dropped := probeSSHKeyBatch(ctx, addr, info.HostKeyFingerprint, user, batch, timeout, &info.AuthMethods)
			if hit >= 0 {
				queriesUsed += hit + 1
			} else {
				queriesUsed += len(batch)
			}
			if dropped {
				// A refusal before the first auth response gives no evidence of rate limiting.
				info.BruteForceProtected = len(info.AuthMethods) > 0 || len(info.AcceptedKeys) > 0
				return
			}
			if noneOK {
				info.NoneAuthAccepted = true
				info.AcceptedKeys = append(info.AcceptedKeys, SSHAcceptedKey{
					Username: user,
					Method:   "none",
					Note:     "Server accepted SSH 'none' authentication without any key or password.",
				})
				return
			}
			if hit < 0 {
				// All queried keys for this user were rejected on one connection.
				break
			}
			if keyIndices[hit] < 0 {
				// Random ephemeral canary key got PK_OK -> discard all positives immediately.
				info.CanaryFalsePositive = true
				info.AcceptedKeys = nil
				return
			}
			k := keys[keyIndices[hit]]
			info.AcceptedKeys = append(info.AcceptedKeys, SSHAcceptedKey{
				Username:    user,
				Fingerprint: k.Fingerprint,
				Algorithm:   batch[hit].algo,
				KeyLabel:    k.Label,
				Method:      "publickey-ok",
				Note:        "First factor invited from scanner IP; MFA, ForceCommand, or from= restrictions may still apply.",
			})
			nextKey = keyIndices[hit] + 1
		}
	}
}
