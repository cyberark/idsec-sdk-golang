package common

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	cookiejar "github.com/juju/persistent-cookiejar"
)

// hostileCookieFile points GOCOOKIES at a temporary cookie file that is left in
// the worst state the persistent cookie jar can encounter: unparseable content
// plus a lock file naming a live process, which the jar's portable advisory lock
// reports as permanently held. Any code path that still opened the persistent
// jar would fail or stall here.
func hostileCookieFile(t *testing.T) string {
	t.Helper()
	cookieFile := filepath.Join(t.TempDir(), ".go-cookies")
	if err := os.WriteFile(cookieFile, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("could not write cookie file: %v", err)
	}
	lockContents := fmt.Appendf(nil, `{"OwnerPID":%d}`, os.Getpid())
	if err := os.WriteFile(cookieFile+".lock", lockContents, 0o600); err != nil {
		t.Fatalf("could not write cookie lock file: %v", err)
	}
	t.Setenv("GOCOOKIES", cookieFile)
	return cookieFile
}

// TestNewInMemoryCookieJar_NeverTouchesDisk verifies the jar is usable, is not
// backed by a file, and leaves no cookie file behind even when Save is called
// explicitly by a consumer holding the jar.
func TestNewInMemoryCookieJar_NeverTouchesDisk(t *testing.T) {
	cookieFile := hostileCookieFile(t)
	if err := os.Remove(cookieFile); err != nil {
		t.Fatalf("could not remove cookie file: %v", err)
	}

	jar := NewInMemoryCookieJar()
	if jar == nil {
		t.Fatal("NewInMemoryCookieJar returned nil")
	}

	data := []byte(`[{"name":"session","value":"abc","domain":"example.com","path":"/"}]`)
	if err := UnmarshalCookies(data, jar); err != nil {
		t.Fatalf("UnmarshalCookies: %v", err)
	}
	if got := len(jar.AllCookies()); got != 1 {
		t.Fatalf("jar holds %d cookies, want 1", got)
	}
	if err := jar.Save(); err != nil {
		t.Fatalf("Save on a non-persistent jar: %v", err)
	}
	if _, err := os.Stat(cookieFile); !os.IsNotExist(err) {
		t.Fatalf("cookie file %s exists after using an in-memory jar (stat err: %v)", cookieFile, err)
	}
}

// TestNewIdsecClient_NilJarSurvivesHostileCookieFile is the regression test for
// the nil-jar panic: a client constructed without a jar must always end up with
// a usable one, regardless of the state of the cookie file on disk, and must not
// pay the jar's multi-second lock retry window to get there.
func TestNewIdsecClient_NilJarSurvivesHostileCookieFile(t *testing.T) {
	hostileCookieFile(t)

	start := time.Now()
	client := NewIdsecClient("https://example.com", "", "", "Authorization", nil, nil, "test", false)
	elapsed := time.Since(start)

	if client.GetCookieJar() == nil {
		t.Fatal("NewIdsecClient produced a nil cookie jar")
	}
	if client.client.Jar == nil {
		t.Fatal("NewIdsecClient produced an HTTP client with no cookie jar")
	}
	// The persistent jar retries its advisory lock for 3 seconds before giving
	// up. Anything close to that means the persistent path is still in play.
	if elapsed > time.Second {
		t.Fatalf("NewIdsecClient took %v, expected no cookie-file lock retry", elapsed)
	}
	if _, found := client.GetCookies()["session"]; found {
		t.Fatal("client picked up cookies from the on-disk cookie file")
	}
}

// TestNewIdsecClient_ConcurrentNilJars verifies that constructing clients from
// many goroutines at once neither panics nor contends, which is what the shared
// cookie file's cross-process lock used to cause. Run with -race.
func TestNewIdsecClient_ConcurrentNilJars(t *testing.T) {
	hostileCookieFile(t)

	const goroutines = 50
	var wg sync.WaitGroup
	jars := make([]*cookiejar.Jar, goroutines)

	start := time.Now()
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			client := NewIdsecClient("https://example.com", "", "", "Authorization", nil, nil, "test", false)
			jars[id] = client.GetCookieJar()
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	for i, jar := range jars {
		if jar == nil {
			t.Fatalf("goroutine %d produced a nil cookie jar", i)
		}
	}
	if elapsed > 5*time.Second {
		t.Fatalf("%d concurrent constructions took %v, expected no lock contention", goroutines, elapsed)
	}
}

// TestUnmarshalCookies_ConcurrentSameJar verifies that concurrent UnmarshalCookies calls on
// the same jar do not race. Run with -race to detect any data races.
func TestUnmarshalCookies_ConcurrentSameJar(t *testing.T) {
	jar := NewInMemoryCookieJar()

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
	if got := len(jar.AllCookies()); got != goroutines {
		t.Errorf("jar holds %d cookies, want %d", got, goroutines)
	}
}

// TestUnmarshalCookies_ConcurrentDistinctJars verifies concurrent UnmarshalCookies calls across
// independent jars do not race with each other or with same-jar calls.
func TestUnmarshalCookies_ConcurrentDistinctJars(t *testing.T) {
	const goroutines = 30
	jars := make([]*cookiejar.Jar, goroutines)
	for i := range jars {
		jars[i] = NewInMemoryCookieJar()
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

// TestMarshalCookies_ConcurrentWithUnmarshal covers the marshal/unmarshal pairing
// on a shared jar. MarshalCookies sizes its result from a cookie snapshot, so a
// jar mutated mid-marshal previously produced an out-of-range write. Run with -race.
func TestMarshalCookies_ConcurrentWithUnmarshal(t *testing.T) {
	jar := NewInMemoryCookieJar()

	const goroutines = 30
	var wg sync.WaitGroup
	errs := make(chan error, goroutines*2)

	wg.Add(goroutines * 2)
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
		go func() {
			defer wg.Done()
			if _, err := MarshalCookies(jar); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("concurrent marshal/unmarshal returned error: %v", e)
	}
}
