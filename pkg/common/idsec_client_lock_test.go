package common

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cookiejar "github.com/juju/persistent-cookiejar"
)

// shortLockTimeout sets cookieFileLockTimeout and cookieFileLockRetry to tiny values for the
// duration of a test, returning a restore function. This prevents each lockCookieFile call from
// blocking for 3 seconds when the advisory flock is unavailable in the test environment.
func shortLockTimeout(t *testing.T) func() {
	t.Helper()
	origTimeout, origRetry := cookieFileLockTimeout, cookieFileLockRetry
	cookieFileLockTimeout = 10 * time.Millisecond
	cookieFileLockRetry = 2 * time.Millisecond
	return func() {
		cookieFileLockTimeout = origTimeout
		cookieFileLockRetry = origRetry
	}
}

// newTestJar creates a persistent cookie jar backed by a temporary file in the workspace. This
// avoids the default ~/.go-cookies path, which is not writable in all environments (e.g.
// sandboxed CI). The caller is responsible for cleanup (handled via t.Cleanup).
func newTestJar(t *testing.T) *cookiejar.Jar {
	t.Helper()
	// Place the cookie file in a temp directory within the workspace so it is always writable.
	dir := filepath.Join(os.Getenv("PWD"), "testdata", "tmp")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("newTestJar: could not create temp dir: %v", err)
	}
	f, err := os.CreateTemp(dir, "cookies-*.json")
	if err != nil {
		t.Fatalf("newTestJar: could not create temp file: %v", err)
	}
	name := f.Name()
	_ = f.Close()
	t.Cleanup(func() {
		_ = os.Remove(name)
		_ = os.Remove(name + ".lock")
	})
	jar, err := cookiejar.New(&cookiejar.Options{Filename: name})
	if err != nil {
		t.Fatalf("newTestJar: cookiejar.New: %v", err)
	}
	return jar
}

// TestLockCookieFile_HoldsAndReleasesMutex verifies that the process-wide mutex is held between
// the lockCookieFile call and the returned release function, and is free afterwards.
func TestLockCookieFile_HoldsAndReleasesMutex(t *testing.T) {
	defer shortLockTimeout(t)()

	release := lockCookieFile()

	// While the region is open the mutex must be taken; TryLock must return false.
	if cookieFileMu.TryLock() {
		cookieFileMu.Unlock()
		release()
		t.Fatal("cookieFileMu was not held by lockCookieFile")
	}

	release()

	// After release the mutex must be free.
	if !cookieFileMu.TryLock() {
		t.Fatal("cookieFileMu was not released by the release function")
	}
	cookieFileMu.Unlock()
}

// TestLockCookieFile_ReleaseDoesNotPanic verifies that a single call to release does not panic.
func TestLockCookieFile_ReleaseDoesNotPanic(t *testing.T) {
	defer shortLockTimeout(t)()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("lockCookieFile release panicked: %v", r)
		}
	}()
	release := lockCookieFile()
	release()
}

// TestLockCookieFile_MutualExclusion verifies that N goroutines calling lockCookieFile
// concurrently are fully serialized — the critical section is never entered simultaneously.
func TestLockCookieFile_MutualExclusion(t *testing.T) {
	defer shortLockTimeout(t)()

	const goroutines = 20
	var (
		concurrent atomic.Int32
		wg         sync.WaitGroup
		violations atomic.Int32
	)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			release := lockCookieFile()
			if count := concurrent.Add(1); count > 1 {
				violations.Add(1)
			}
			// Hold briefly so other goroutines have a chance to enter if exclusion fails.
			time.Sleep(2 * time.Millisecond)
			concurrent.Add(-1)
			release()
		}()
	}
	wg.Wait()
	if n := violations.Load(); n > 0 {
		t.Fatalf("mutual exclusion violated: %d goroutine(s) entered the critical section simultaneously", n)
	}
}

// TestAcquireCookieFileLock_CompletesWithinTimeout verifies that acquireCookieFileLock always
// returns within the declared retry window. When the directory is absent the function returns
// nil immediately; when present it either acquires the lock or gives up after the timeout.
func TestAcquireCookieFileLock_CompletesWithinTimeout(t *testing.T) {
	defer shortLockTimeout(t)()

	maxAllowed := cookieFileLockTimeout + 500*time.Millisecond

	start := time.Now()
	result := acquireCookieFileLock()
	elapsed := time.Since(start)

	if elapsed > maxAllowed {
		t.Fatalf("acquireCookieFileLock blocked for %v, expected < %v", elapsed, maxAllowed)
	}
	if result != nil {
		_ = result.Close()
	}
}

// TestAcquireCookieFileLock_ReturnValueConsistency verifies that when a lock is returned it
// can be closed without panicking.
func TestAcquireCookieFileLock_ReturnValueConsistency(t *testing.T) {
	defer shortLockTimeout(t)()

	result := acquireCookieFileLock()
	if result == nil {
		// Directory absent or lock unavailable — nothing further to verify.
		return
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("acquireCookieFileLock result.Close() panicked: %v", r)
		}
	}()
	_ = result.Close()
}

// TestUnmarshalCookies_ConcurrentSameJar verifies that concurrent UnmarshalCookies calls on
// the same jar do not race. Run with -race to detect any data races.
func TestUnmarshalCookies_ConcurrentSameJar(t *testing.T) {
	defer shortLockTimeout(t)()

	jar := newTestJar(t)

	const goroutines = 30
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			data := fmt.Appendf(nil,
				`[{"name":"cookie%d","value":"val%d","domain":"example.com","path":"/"}]`,
				id, id,
			)
			if err := UnmarshalCookies(data, jar); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("UnmarshalCookies returned error: %v", e)
	}
}

// TestUnmarshalCookies_ConcurrentDistinctJars verifies concurrent UnmarshalCookies calls across
// independent jars do not race with each other or with same-jar calls.
func TestUnmarshalCookies_ConcurrentDistinctJars(t *testing.T) {
	defer shortLockTimeout(t)()

	const goroutines = 30
	// Pre-create all jars on the test goroutine so cleanup is registered correctly.
	jars := make([]*cookiejar.Jar, goroutines)
	for i := range jars {
		jars[i] = newTestJar(t)
	}

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			data := fmt.Appendf(nil,
				`[{"name":"cookie%d","value":"val%d","domain":"example.com","path":"/"}]`,
				id, id,
			)
			if err := UnmarshalCookies(data, jars[id]); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("UnmarshalCookies returned error: %v", e)
	}
}
