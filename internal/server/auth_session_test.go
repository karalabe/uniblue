// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package server

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPersistedLogoutIgnoresUnknownSessions(t *testing.T) {
	const token = "dashboard-token"
	statePath := filepath.Join(t.TempDir(), "state.json")
	start := func() http.Handler {
		e := NewDemoEngineForTest(t)
		e.cfg.State.Path = statePath
		e.opts.APIToken = token
		return e.Handler()
	}
	handler := start()
	request := func(method, path, cookie string, want int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "http://127.0.0.1"+path, nil)
		if method == http.MethodPost {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s %s returned %d, want %d", method, path, rec.Code, want)
		}
		return rec
	}
	const session = "/api/v1/session"
	const state = "/api/v1/state"
	login := func() string {
		t.Helper()
		for _, ck := range request(http.MethodPost, session, "", http.StatusOK).Result().Cookies() {
			if ck.Name == sessionCookieName {
				return ck.Value
			}
		}
		t.Fatal("missing session cookie")
		return ""
	}
	loggedOut, active := login(), login()
	path := statePath + ".sessions.json"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(active)) || bytes.Contains(raw, []byte(token)) {
		t.Fatal("session file contains a reusable credential")
	}

	handler = start()
	request(http.MethodGet, state, loggedOut, http.StatusOK)
	request(http.MethodDelete, session, loggedOut, http.StatusOK)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode().Perm() != 0o600 {
		t.Fatalf("session file mode = %v, want 0600", before.Mode())
	}
	for i := range 3 * maxActiveSessions {
		request(http.MethodDelete, session, fmt.Sprintf("%064x", i), http.StatusOK)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("unknown logout replaced or modified the session file")
	}
	request(http.MethodGet, state, loggedOut, http.StatusUnauthorized)
	handler = start()
	request(http.MethodGet, state, loggedOut, http.StatusUnauthorized)
	request(http.MethodGet, state, active, http.StatusOK)
}

func TestSessionStoreEvictionAndFailedCommit(t *testing.T) {
	now := time.Now()
	s := sessionStore{nowFn: func() time.Time { return now }}
	const token = "test-token"
	// Keep one session strictly older than the others.
	first, err := s.create(token)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	var last string
	for range maxActiveSessions {
		last, err = s.create(token)
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(s.data.Expires) != maxActiveSessions {
		t.Fatalf("active sessions = %d, want %d", len(s.data.Expires), maxActiveSessions)
	}
	if valid, err := s.lookup(first, token, false); valid || err != nil {
		t.Fatalf("evicted session lookup = %v, %v", valid, err)
	}
	// A directory at the file destination makes atomic replacement fail.
	s.path = t.TempDir()
	if _, err := s.lookup(last, token, true); err == nil {
		t.Fatal("logout succeeded despite a failed commit")
	}
	if valid, err := s.lookup(last, token, false); !valid || err != nil {
		t.Fatalf("session after failed commit = %v, %v", valid, err)
	}
	s.path = filepath.Join(s.path, "sessions.json")
	if valid, err := s.lookup(last, token, true); !valid || err != nil {
		t.Fatalf("retry logout = %v, %v", valid, err)
	}
}
