package cover

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	staticSecurityOrdinary  = "ordinary-static-cover-payload\n"
	staticSecurityIndex     = "<html>ordinary static cover index</html>\n"
	staticSecurityHidden    = "DUMMY-STATIC-HIDDEN-CONTENT"
	staticSecurityOutside   = "DUMMY-STATIC-OUTSIDE-CONTENT"
	staticSecurityWellKnown = "ordinary-well-known-fixture"
)

func TestStaticSecurityOrdinaryCompatibility(t *testing.T) {
	fixture := newStaticSecurityFixture(t, true)
	for _, test := range []struct {
		name, method, path, rangeValue, body string
		status                               int
	}{
		{"index_get", http.MethodGet, "/", "", staticSecurityIndex, http.StatusOK},
		{"ordinary_get", http.MethodGet, "/assets/public.txt", "", staticSecurityOrdinary, http.StatusOK},
		{"ordinary_head", http.MethodHead, "/assets/public.txt", "", "", http.StatusOK},
		{"ordinary_range", http.MethodGet, "/assets/public.txt", "bytes=0-7", staticSecurityOrdinary[:8], http.StatusPartialContent},
		{"ordinary_head_range", http.MethodHead, "/assets/public.txt", "bytes=0-7", "", http.StatusPartialContent},
		{"missing", http.MethodGet, "/missing-fixture.txt", "", "404 page not found\n", http.StatusNotFound},
		{"method", http.MethodPost, "/assets/public.txt", "", "Method Not Allowed\n", http.StatusMethodNotAllowed},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := staticSecurityRequest(t, fixture.handler, test.method, test.path, test.rangeValue)
			if response.Code != test.status || response.Body.String() != test.body {
				t.Fatalf("ordinary response = %d/%q, want %d/%q", response.Code, response.Body, test.status, test.body)
			}
			if test.method == http.MethodPost && response.Header().Get("Allow") != "GET, HEAD" {
				t.Errorf("ordinary method Allow = %q", response.Header().Get("Allow"))
			}
			if test.rangeValue != "" {
				want := fmt.Sprintf("bytes 0-7/%d", len(staticSecurityOrdinary))
				if got := response.Header().Get("Content-Range"); got != want {
					t.Errorf("ordinary Content-Range = %q, want %q", got, want)
				}
			}
			assertNoProductMarker(t, response.Result())
		})
	}
}

func TestStaticSecurityWellKnownAndHiddenPaths(t *testing.T) {
	fixture := newStaticSecurityFixture(t, true)
	for _, path := range []string{
		"/.well-known/acme-challenge/public-token",
		"/%2ewell-known/acme-challenge/public-token",
		"/.well-known/acme-challenge/public%2dtoken",
	} {
		t.Run("allowed_"+path, func(t *testing.T) {
			response := staticSecurityRequest(t, fixture.handler, http.MethodGet, path, "")
			if response.Code != http.StatusOK || response.Body.String() != staticSecurityWellKnown {
				t.Fatalf("root .well-known response = %d/%q", response.Code, response.Body)
			}
		})
	}
	for _, path := range []string{
		"/.env",
		"/%2Eenv",
		"/.private/dummy.txt",
		"/%2eprivate/dummy.txt",
		"/assets/.hidden.txt",
		"/assets/%2Ehidden.txt",
		"/assets%2f.hidden.txt",
		"/assets/.well-known/dummy.txt",
		"/.well-known/.private.txt",
		"/.well-known/%2Eprivate.txt",
		"/.well-known%2f.private.txt",
	} {
		t.Run("blocked_"+path, func(t *testing.T) {
			staticSecurityAssertDenied(t, staticSecurityRequest(t, fixture.handler, http.MethodGet, path, ""))
		})
	}
}

func TestStaticSecurityConfinesSymlinks(t *testing.T) {
	fixture := newStaticSecurityFixture(t, true)
	for _, path := range []string{"/inside-relative.txt", "/inside-relative-dir/public.txt"} {
		t.Run("internal_"+path, func(t *testing.T) {
			response := staticSecurityRequest(t, fixture.handler, http.MethodGet, path, "")
			if response.Code != http.StatusOK || response.Body.String() != staticSecurityOrdinary {
				t.Fatalf("internal relative symlink response = %d/%q", response.Code, response.Body)
			}
		})
	}
	for _, path := range []string{
		"/outside-absolute.txt",
		"/outside-relative.txt",
		"/outside-dir/",
		"/outside-dir/index.html",
		"/outside-relative-dir/",
		"/outside-relative-dir/index.html",
	} {
		t.Run("external_"+path, func(t *testing.T) {
			// FileServer may redirect index.html to ./ before opening a file.
			// Follow only bounded local frontend redirects, then inspect the
			// actual terminal response rather than calling a 301 a content leak.
			staticSecurityAssertDenied(t, staticSecurityRequest(t, fixture.handler, http.MethodGet, path, ""))
		})
	}
}

func TestStaticSecurityAbsoluteInternalSymlinkBlocked(t *testing.T) {
	fixture := newStaticSecurityFixture(t, true)
	response := staticSecurityRequest(t, fixture.handler, http.MethodGet, "/inside-absolute.txt", "")
	if response.Code != http.StatusNotFound {
		t.Errorf("absolute internal symlink status/body = %d/%q, want ordinary 404", response.Code, response.Body)
	}
	if strings.Contains(response.Body.String(), staticSecurityOrdinary) {
		t.Error("blocked absolute internal symlink returned actual owned dummy file content")
	}
	staticSecurityAssertNoDummySecrets(t, response)
	assertNoProductMarker(t, response.Result())
}

func TestStaticSecurityAdditionalOrdinaryCompatibility(t *testing.T) {
	fixture := newStaticSecurityFixture(t, true)
	t.Run("invalid_range", func(t *testing.T) {
		response := staticSecurityRequest(t, fixture.handler, http.MethodGet, "/assets/public.txt", "bytes=1000-2000")
		if response.Code != http.StatusRequestedRangeNotSatisfiable || response.Body.String() != "invalid range: failed to overlap\n" {
			t.Fatalf("ordinary invalid Range response = %d/%q, want standard 416", response.Code, response.Body)
		}
		if want, got := fmt.Sprintf("bytes */%d", len(staticSecurityOrdinary)), response.Header().Get("Content-Range"); got != want {
			t.Errorf("invalid Range Content-Range = %q, want %q", got, want)
		}
		assertNoProductMarker(t, response.Result())
	})
	t.Run("directory_redirect", func(t *testing.T) {
		// Do not use the redirect-following helper: the first 301 and its
		// exact relative Location (including the query) are the control.
		request := httptest.NewRequest(http.MethodGet, "https://static.example/assets?q=fixture", nil)
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, request)
		if response.Code != http.StatusMovedPermanently || response.Header().Get("Location") != "assets/?q=fixture" || response.Body.Len() != 0 {
			t.Fatalf("ordinary directory redirect = %d/%q/%q, want 301/assets/?q=fixture/empty", response.Code, response.Header().Get("Location"), response.Body)
		}
		assertNoProductMarker(t, response.Result())
	})
}

func TestStaticSecurityDirectoryListings(t *testing.T) {
	fixture := newStaticSecurityFixture(t, false)
	for _, test := range []struct {
		name, path      string
		present, absent []string
	}{
		{"root", "/", []string{"assets/", ".well-known/"}, []string{".env", ".private/"}},
		{"ordinary_directory", "/listing/", []string{"visible.txt"}, []string{".listing-secret", ".listing-private/"}},
		{"root_well_known", "/.well-known/", []string{"acme-challenge/"}, []string{".private.txt"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := staticSecurityRequest(t, fixture.handler, http.MethodGet, test.path, "")
			if response.Code != http.StatusOK {
				t.Fatalf("directory listing status = %d, want 200", response.Code)
			}
			for _, name := range test.present {
				if !strings.Contains(response.Body.String(), name) {
					t.Errorf("ordinary directory entry %q missing from listing", name)
				}
			}
			for _, name := range test.absent {
				if strings.Contains(response.Body.String(), name) {
					t.Errorf("hidden directory entry %q exposed in listing", name)
				}
			}
			staticSecurityAssertNoDummySecrets(t, response)
		})
	}
}

type staticSecurityFixture struct {
	handler http.Handler
}

func newStaticSecurityFixture(t *testing.T, withIndex bool) staticSecurityFixture {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "public")
	for _, directory := range []string{"public", "outside", "public/assets/.well-known", "public/.private", "public/.well-known/acme-challenge", "public/listing/.listing-private"} {
		if err := os.MkdirAll(filepath.Join(base, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"public/assets/public.txt":                       staticSecurityOrdinary,
		"public/.env":                                    staticSecurityHidden,
		"public/.private/dummy.txt":                      staticSecurityHidden,
		"public/assets/.hidden.txt":                      staticSecurityHidden,
		"public/assets/.well-known/dummy.txt":            staticSecurityHidden,
		"public/.well-known/acme-challenge/public-token": staticSecurityWellKnown,
		"public/.well-known/.private.txt":                staticSecurityHidden,
		"public/listing/visible.txt":                     staticSecurityOrdinary,
		"public/listing/.listing-secret":                 staticSecurityHidden,
		"public/listing/.listing-private/dummy.txt":      staticSecurityHidden,
		"outside/dummy.txt":                              staticSecurityOutside,
		"outside/index.html":                             staticSecurityOutside,
	}
	if withIndex {
		files["public/index.html"] = staticSecurityIndex
	}
	for path, contents := range files {
		if err := os.WriteFile(filepath.Join(base, path), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{
		"inside-relative.txt":  filepath.Join("assets", "public.txt"),
		"inside-relative-dir":  "assets",
		"inside-absolute.txt":  filepath.Join(root, "assets", "public.txt"),
		"outside-absolute.txt": filepath.Join(base, "outside", "dummy.txt"),
		"outside-relative.txt": filepath.Join("..", "outside", "dummy.txt"),
		"outside-dir":          filepath.Join(base, "outside"),
		"outside-relative-dir": filepath.Join("..", "outside"),
	} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatalf("create owned dummy symlink %q: %v", name, err)
		}
	}
	handler, err := NewStaticHandler(root)
	if err != nil {
		t.Fatal(err)
	}
	return staticSecurityFixture{handler: handler}
}

func staticSecurityRequest(t *testing.T, handler http.Handler, method, path, rangeValue string) *httptest.ResponseRecorder {
	t.Helper()
	target, err := url.Parse("https://static.example" + path)
	if err != nil {
		t.Fatal(err)
	}
	for redirects := 0; redirects <= 4; redirects++ {
		request := httptest.NewRequest(method, target.String(), nil)
		if rangeValue != "" {
			request.Header.Set("Range", rangeValue)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		staticSecurityAssertNoDummySecretsOnRedirect(t, response)
		switch response.Code {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
			reference, err := url.Parse(response.Header().Get("Location"))
			if err != nil || response.Header().Get("Location") == "" {
				t.Fatalf("invalid ordinary static redirect Location %q", response.Header().Get("Location"))
			}
			target = target.ResolveReference(reference)
			if target.Scheme != "https" || target.Host != "static.example" || target.User != nil {
				t.Fatalf("static redirect left owned dummy frontend: %q", target)
			}
		default:
			return response
		}
	}
	t.Fatal("static response exceeded four owned local redirects")
	return nil
}

func staticSecurityAssertNoDummySecretsOnRedirect(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code >= 300 && response.Code < 400 {
		staticSecurityAssertNoDummySecrets(t, response)
	}
}

func staticSecurityAssertDenied(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusNotFound {
		t.Errorf("unsafe static terminal status = %d, want ordinary 404", response.Code)
	}
	staticSecurityAssertNoDummySecrets(t, response)
	assertNoProductMarker(t, response.Result())
}

func staticSecurityAssertNoDummySecrets(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	for _, marker := range []string{staticSecurityHidden, staticSecurityOutside} {
		if strings.Contains(response.Body.String(), marker) {
			t.Errorf("owned dummy content outside public policy exposed: %q", marker)
		}
	}
}
