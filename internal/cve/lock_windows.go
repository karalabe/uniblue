// uniblue: blue-team security engine for UniFi networks
// Copyright 2026 Péter Szilágyi. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build windows

package cve

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// acquireCacheLock obtains an exclusive kernel byte-range lock on lockPath via
// LockFileEx so concurrent sync processes wait safely and Windows automatically
// releases the lock when the owning handle closes or the process exits.
func acquireCacheLock(ctx context.Context, lockPath string) (func(), error) {
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	handle := windows.Handle(f.Fd())
	var offset windows.Overlapped
	for {
		if err := ctx.Err(); err != nil {
			f.Close()
			return nil, err
		}
		err = windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &offset)
		if err == nil {
			return func() {
				_ = windows.UnlockFileEx(handle, 0, 1, 0, &offset)
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			f.Close()
			return nil, fmt.Errorf("lock cache: %w", err)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
