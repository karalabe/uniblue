// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package cve

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCacheLockHeldUntilOwnerReleasesHandle verifies that Windows kernel
// byte-range locking blocks a second sync caller even when the lock file's
// modification timestamp is older than 30 minutes, until the owner releases it.
func TestCacheLockHeldUntilOwnerReleasesHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".sync.lock")
	release, err := acquireCacheLock(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	old := time.Now().Add(-31 * time.Minute)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	second, err := acquireCacheLock(ctx, path)
	if err == nil {
		defer second()
		t.Fatal("second process acquired lock while first still holds it")
	}
}
