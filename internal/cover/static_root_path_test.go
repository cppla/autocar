package cover

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStaticRootPreservesSymlinkParent(t *testing.T) {
	for _, relative := range []bool{false, true} {
		name := "absolute"
		if relative {
			name = "relative"
		}
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			deploy := filepath.Join(base, "deploy")
			site := filepath.Join(base, "site")
			for _, directory := range []string{deploy, filepath.Join(site, "release")} {
				if err := os.MkdirAll(directory, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for directory, content := range map[string]string{
				deploy: "outside configured site",
				site:   "inside configured site",
			} {
				if err := os.WriteFile(filepath.Join(directory, "marker.txt"), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			link := filepath.Join(deploy, "current")
			staticRootSymlink(t, filepath.Join(site, "release"), link)
			configured := link + string(os.PathSeparator) + ".."
			if relative {
				t.Chdir(base)
				configured = "deploy" + string(os.PathSeparator) + "current" + string(os.PathSeparator) + ".."
			}
			// The native filesystem decides the configured path's meaning;
			// the handler must not substitute its lexically cleaned parent.
			want, err := os.ReadFile(configured + string(os.PathSeparator) + "marker.txt")
			if err != nil {
				t.Fatal(err)
			}
			handler, err := NewStaticHandler(configured)
			if err != nil {
				t.Fatal(err)
			}
			// Relative configuration belongs to the constructor's directory,
			// even if the process changes its working directory afterwards.
			t.Chdir(t.TempDir())
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/marker.txt", nil))
			if response.Code != http.StatusOK || response.Body.String() != string(want) {
				t.Fatalf("configured root contains %q; HTTP returned %d/%q", want, response.Code, response.Body.String())
			}
		})
	}
}

func TestStaticRootFollowsReplacementSiteLink(t *testing.T) {
	base := t.TempDir()
	link := filepath.Join(base, "current")
	for _, name := range []string{"first", "second"} {
		directory := filepath.Join(base, name)
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "marker.txt"), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	staticRootSymlink(t, filepath.Join(base, "first"), link)
	t.Chdir(base)
	handler, err := NewStaticHandler("current")
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	for _, want := range []string{"first", "second"} {
		if want == "second" {
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			staticRootSymlink(t, filepath.Join(base, "second"), link)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/marker.txt", nil))
		if response.Code != http.StatusOK || response.Body.String() != want {
			t.Fatalf("site %s: HTTP returned %d/%q", want, response.Code, response.Body.String())
		}
	}
}

func TestStaticRootPreservesWorkingDirectoryPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix Getwd preserves a matching PWD spelling")
	}
	base := t.TempDir()
	deploy, site := filepath.Join(base, "deploy"), filepath.Join(base, "site")
	for _, directory := range []string{deploy, filepath.Join(site, "release")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for directory, content := range map[string]string{deploy: "outside", site: "inside"} {
		if err := os.WriteFile(filepath.Join(directory, "marker.txt"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(deploy, "current")
	staticRootSymlink(t, filepath.Join(site, "release"), link)
	t.Chdir(site)
	t.Setenv("PWD", link+"/..")
	handler, err := NewStaticHandler(".")
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/marker.txt", nil))
	if response.Code != http.StatusOK || response.Body.String() != "inside" {
		t.Fatalf("HTTP returned %d/%q", response.Code, response.Body.String())
	}
}

func TestStaticRootWindowsRelativePaths(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows drive-relative and rooted path forms")
	}
	if _, err := NewStaticHandler(`\\server\..\site`); err == nil {
		t.Fatal("invalid UNC volume was accepted")
	}
	base := t.TempDir()
	directory := filepath.Join(base, "site")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "marker.txt"), []byte("site"), 0o600); err != nil {
		t.Fatal(err)
	}
	volume := filepath.VolumeName(base)
	paths := []string{"site", directory[len(volume):]}
	if len(volume) == 2 && volume[1] == ':' {
		paths = append(paths, volume+"site")
	}
	for _, configured := range paths {
		t.Run(configured, func(t *testing.T) {
			t.Chdir(base)
			handler, err := NewStaticHandler(configured)
			if err != nil {
				t.Fatal(err)
			}
			t.Chdir(t.TempDir())
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/marker.txt", nil))
			if response.Code != http.StatusOK || response.Body.String() != "site" {
				t.Fatalf("HTTP returned %d/%q", response.Code, response.Body.String())
			}
		})
	}
}

func staticRootSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("directory symlink unavailable: %v", err)
		}
		t.Fatal(err)
	}
}
