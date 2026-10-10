package cover

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// NewStaticHandler returns a handler rooted at directory. Only GET and HEAD
// are accepted; all other methods receive a normal HTTP 405 response.
// Each request opens its own root, so the handler owns no persistent handle.
// Root confinement does not exclude mounts, hard links, or public aliases to
// hidden files inside the root. The configured directory remains operator-owned.
func NewStaticHandler(directory string) (http.Handler, error) {
	if strings.TrimSpace(directory) == "" {
		return nil, errors.New("static directory is required")
	}
	root, err := absoluteStaticDirectory(directory)
	if err != nil {
		return nil, errors.New("resolve static directory")
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, errors.New("open static directory")
	}
	if !info.IsDir() {
		return nil, errors.New("static path is not a directory")
	}
	// Validate actual access without retaining a handle through configuration
	// checks, listener failures, or the shared H2/H3 cover lifecycle.
	validationRoot, err := os.OpenRoot(root)
	if err != nil {
		return nil, errors.New("open static directory")
	}
	if err := validationRoot.Close(); err != nil {
		return nil, errors.New("close static directory")
	}
	return &staticHandler{directory: root}, nil
}

// Anchor a relative directory without cleaning its components: link/.. must
// retain the filesystem's meaning. Do not resolve links here either, because
// replacing a site link must still take effect on the next request.
func absoluteStaticDirectory(directory string) (string, error) {
	if filepath.IsAbs(directory) {
		return directory, nil
	}
	volume := filepath.VolumeName(directory)
	base, err := os.Getwd()
	if volume != "" {
		base, err = filepath.Abs(volume + ".")
	}
	if err != nil {
		return "", err
	}
	relative := directory[len(volume):]
	if len(relative) != 0 && os.IsPathSeparator(relative[0]) {
		if len(relative) > 1 && os.IsPathSeparator(relative[1]) {
			// An unrecognized UNC volume must not become a local drive path.
			return "", errors.New("invalid static directory volume")
		}
		// A Windows rooted path such as \site inherits the current volume.
		return filepath.VolumeName(base) + relative, nil
	}
	// On Windows base also honors the working directory of a drive-relative
	// path such as C:site. Concatenation preserves the supplied components.
	if !os.IsPathSeparator(base[len(base)-1]) {
		base += string(os.PathSeparator)
	}
	return base + relative, nil
}

type staticHandler struct {
	directory string
}

func (h *staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if !staticPathAllowed(r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	root, err := os.OpenRoot(h.directory)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer root.Close()
	// FileServerFS keeps ordinary redirects, index lookup, HEAD, and Range.
	// All files opened for this request use the same root and are closed by
	// FileServer before this request's root handle is released.
	http.FileServerFS(staticFileSystem{base: root.FS()}).ServeHTTP(w, r)
}

// staticPathAllowed uses the decoded, normalized URL path, just as FileServer
// does. The well-known exception belongs only to the root directory. Backslash
// is never a public path separator; Windows alternate streams are also denied.
func staticPathAllowed(name string) bool {
	if strings.ContainsRune(name, '\\') || (runtime.GOOS == "windows" && strings.ContainsRune(name, ':')) {
		return false
	}
	cleaned := strings.TrimPrefix(path.Clean("/"+name), "/")
	if cleaned == "" {
		return true
	}
	for index, component := range strings.Split(cleaned, "/") {
		if !staticComponentAllowed(component, index == 0) {
			return false
		}
	}
	return true
}

func staticComponentAllowed(name string, root bool) bool {
	if strings.ContainsRune(name, '\\') || (runtime.GOOS == "windows" && strings.ContainsRune(name, ':')) {
		return false
	}
	return !strings.HasPrefix(name, ".") || (root && name == ".well-known")
}

type staticFileSystem struct {
	base fs.FS
}

func (s staticFileSystem) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) || !staticPathAllowed(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	file, err := s.base.Open(name)
	if err != nil {
		// Keep denied links, unavailable files, and platform-specific unsafe
		// names indistinguishable, without exposing local paths in errors.
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return &staticFile{File: file, directory: name}, nil
}

type staticFile struct {
	fs.File
	directory string
}

func (f *staticFile) Seek(offset int64, whence int) (int64, error) {
	seeker, ok := f.File.(io.Seeker)
	if !ok {
		return 0, fs.ErrInvalid
	}
	return seeker.Seek(offset, whence)
}

func (f *staticFile) ReadDir(n int) ([]fs.DirEntry, error) {
	directory, ok := f.File.(fs.ReadDirFile)
	if !ok {
		return nil, fs.ErrInvalid
	}
	entries := make([]fs.DirEntry, 0)
	for {
		count := n
		if n > 0 {
			count -= len(entries)
		}
		batch, err := directory.ReadDir(count)
		for _, entry := range batch {
			if staticComponentAllowed(entry.Name(), f.directory == ".") {
				entries = append(entries, entry)
			}
		}
		if err != nil || n <= 0 || len(entries) >= n {
			return entries, err
		}
		if len(batch) == 0 {
			// A positive-count ReadDir must either advance or return an
			// error. Never spin if an implementation violates that contract.
			return entries, io.ErrNoProgress
		}
		// A batch containing only hidden entries is not the end of the
		// directory: continue until the public count or a real error.
	}
}
