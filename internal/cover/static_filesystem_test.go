package cover

import (
	"errors"
	"io"
	"io/fs"
	"reflect"
	"runtime"
	"testing"
	"time"
)

// These controls exercise the candidate-only filesystem wrapper. They are
// deliberately separate from the public API's old-production negative tests.
// No path in this file is opened on a real filesystem or through a symlink.
func TestStaticFileSystemPathPolicy(t *testing.T) {
	for _, test := range []struct {
		name              string
		pathAllowed, open bool
	}{
		{".", true, true},
		{"", true, false},
		{"/", true, false},
		{"public.txt", true, true},
		{"assets/public.txt", true, true},
		{".well-known/acme-challenge/token", true, true},
		{"/.well-known/acme-challenge/token", true, false},
		{".env", false, false},
		{"assets/.env", false, false},
		{".well-known/.env", false, false},
		{"assets/.well-known/token", false, false},
		{".Well-known/token", false, false},
		{".well-known-extra/token", false, false},
		{"assets\\public.txt", false, false},
		{"assets/\\public.txt", false, false},
		{".well-known\\token", false, false},
		{"./public.txt", true, false},
		{"../public.txt", true, false},
		{"assets/../public.txt", true, false},
		{"assets//public.txt", true, false},
		{"assets/public.txt/", true, false},
		// Colon is an ordinary Unix filename byte, but on Windows these
		// spellings can address alternate data streams or drive-relative paths.
		{"public.txt:private", runtime.GOOS != "windows", runtime.GOOS != "windows"},
		{"assets/public.txt:private", runtime.GOOS != "windows", runtime.GOOS != "windows"},
		{"C:private", runtime.GOOS != "windows", runtime.GOOS != "windows"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := staticPathAllowed(test.name); got != test.pathAllowed {
				t.Errorf("decoded path policy on %s = %v, want %v", runtime.GOOS, got, test.pathAllowed)
			}
			file := &staticFileSystemTestFile{}
			backend := &staticFileSystemTestFS{file: file}
			result, err := (staticFileSystem{base: backend}).Open(test.name)
			if test.open {
				if err != nil || result == nil || backend.opens != 1 || backend.name != test.name {
					t.Fatalf("ordinary FS open = %v/%v, calls=%d name=%q", result, err, backend.opens, backend.name)
				}
				if err := result.Close(); err != nil || file.closes != 1 {
					t.Errorf("ordinary wrapper Close = %v / calls %d", err, file.closes)
				}
				return
			}
			var pathError *fs.PathError
			if result != nil || !errors.As(err, &pathError) || pathError.Op != "open" || pathError.Path != test.name || pathError.Err != fs.ErrNotExist {
				t.Errorf("denied FS open must return ordinary requested-path not-exist error: %v/%v", result, err)
			}
			if backend.opens != 0 {
				t.Errorf("unsafe path reached backend Open %d times", backend.opens)
			}
		})
	}
}

func TestStaticFileSystemReadDirContract(t *testing.T) {
	t.Run("positive_count_and_eof", func(t *testing.T) {
		base := staticFileSystemTestDirectory{".hidden", "first", ".env", "second", "third", ".private"}
		file := &staticFileSystemTestDirFile{entries: base}
		wrapper := &staticFile{File: file, directory: "assets"}
		for index, test := range []struct {
			names []string
			err   error
		}{
			{[]string{"first", "second"}, nil},
			{[]string{"third"}, io.EOF},
			{[]string{}, io.EOF},
		} {
			entries, err := wrapper.ReadDir(2)
			if got := staticFileSystemTestNames(entries); !reflect.DeepEqual(got, test.names) || err != test.err {
				t.Errorf("positive ReadDir call %d = %v/%v, want %v/%v", index, got, err, test.names, test.err)
			}
		}
		// The wrapper asks only for the still-needed visible count and does
		// not read ahead after it has filled the caller's requested batch.
		if want := []int{2, 1, 1, 2, 1, 2}; !reflect.DeepEqual(file.counts, want) {
			t.Errorf("underlying positive ReadDir counts = %v, want %v", file.counts, want)
		}
		if file.reads != 0 {
			t.Errorf("directory filtering unexpectedly read file body %d times", file.reads)
		}
	})
	for _, count := range []int{0, -1} {
		for _, directory := range []string{".", "assets"} {
			t.Run("all_"+directory+"_"+map[int]string{0: "zero", -1: "negative"}[count], func(t *testing.T) {
				file := &staticFileSystemTestDirFile{entries: staticFileSystemTestDirectory{".hidden", "first", ".well-known", "last"}}
				wrapper := &staticFile{File: file, directory: directory}
				entries, err := wrapper.ReadDir(count)
				want := []string{"first", "last"}
				if directory == "." {
					want = []string{"first", ".well-known", "last"}
				}
				if got := staticFileSystemTestNames(entries); !reflect.DeepEqual(got, want) || err != nil || !reflect.DeepEqual(file.counts, []int{count}) {
					t.Errorf("all ReadDir = %v/%v counts=%v, want %v/nil/one call", got, err, file.counts, want)
				}
				entries, err = wrapper.ReadDir(count)
				if len(entries) != 0 || err != nil {
					t.Errorf("all ReadDir after end = %v/%v, want empty/nil", entries, err)
				}
			})
		}
	}
	t.Run("original_error_with_partial_batch", func(t *testing.T) {
		failure := errors.New("owned original ReadDir failure")
		file := &staticFileSystemTestDirFile{entries: staticFileSystemTestDirectory{".hidden", "visible"}, finalErr: failure}
		entries, err := (&staticFile{File: file, directory: "."}).ReadDir(3)
		if got := staticFileSystemTestNames(entries); !reflect.DeepEqual(got, []string{"visible"}) || err != failure || !reflect.DeepEqual(file.counts, []int{3}) {
			t.Errorf("partial original ReadDir = %v/%v counts=%v", got, err, file.counts)
		}
	})
	t.Run("empty_nil_does_not_spin", func(t *testing.T) {
		file := &staticFileSystemTestDirFile{emptyNil: true}
		entries, err := (&staticFile{File: file, directory: "."}).ReadDir(1)
		if len(entries) != 0 || err != io.ErrNoProgress || !reflect.DeepEqual(file.counts, []int{1}) {
			t.Errorf("invalid non-advancing backend = %v/%v counts=%v", entries, err, file.counts)
		}
	})
}

func TestStaticFileSystemFileDelegationAndErrors(t *testing.T) {
	t.Run("read_close_stat_seek", func(t *testing.T) {
		readFailure, closeFailure := errors.New("original read failure"), errors.New("original close failure")
		statFailure, seekFailure := errors.New("original stat failure"), errors.New("original seek failure")
		base := &staticFileSystemTestSeekFile{staticFileSystemTestFile: staticFileSystemTestFile{
			readErr: readFailure, closeErr: closeFailure, statErr: statFailure,
		}, seekErr: seekFailure}
		file := &staticFile{File: base, directory: "public.txt"}
		buffer := make([]byte, 4)
		if n, err := file.Read(buffer); n != 3 || err != readFailure || string(buffer[:n]) != "abc" || base.reads != 1 {
			t.Errorf("Read changed original n/payload/error/call count = %d/%q/%v/%d", n, buffer, err, base.reads)
		}
		if err := file.Close(); err != closeFailure || base.closes != 1 {
			t.Errorf("Close changed original error/call count = %v/%d", err, base.closes)
		}
		if info, err := file.Stat(); info == nil || info.Name() != "public.txt" || err != statFailure || base.stats != 1 {
			t.Errorf("Stat changed original info/error/call count = %v/%v/%d", info, err, base.stats)
		}
		if offset, err := file.Seek(7, io.SeekCurrent); offset != 19 || err != seekFailure || base.seeks != 1 || base.offset != 7 || base.whence != io.SeekCurrent {
			t.Errorf("Seek changed original input/output = %d/%v calls=%d offset=%d whence=%d", offset, err, base.seeks, base.offset, base.whence)
		}
	})
	t.Run("unsupported_optional_operations", func(t *testing.T) {
		file := &staticFile{File: &staticFileSystemTestFile{}, directory: "public.txt"}
		if entries, err := file.ReadDir(1); entries != nil || err != fs.ErrInvalid {
			t.Errorf("unsupported ReadDir = %v/%v", entries, err)
		}
		if offset, err := file.Seek(0, io.SeekStart); offset != 0 || err != fs.ErrInvalid {
			t.Errorf("unsupported Seek = %d/%v", offset, err)
		}
	})
	t.Run("backend_open_error_is_generic", func(t *testing.T) {
		failure := errors.New("owned backend private path failure")
		base := &staticFileSystemTestFS{err: failure}
		file, err := (staticFileSystem{base: base}).Open("public.txt")
		var pathError *fs.PathError
		if file != nil || !errors.As(err, &pathError) || pathError.Op != "open" || pathError.Path != "public.txt" || pathError.Err != fs.ErrNotExist || errors.Is(err, failure) || base.opens != 1 {
			t.Errorf("backend Open failure exposed identity or changed call count = %v/%v calls=%d", file, err, base.opens)
		}
	})
}

type staticFileSystemTestFS struct {
	file  fs.File
	err   error
	opens int
	name  string
}

func (f *staticFileSystemTestFS) Open(name string) (fs.File, error) {
	f.opens++
	f.name = name
	return f.file, f.err
}

type staticFileSystemTestFile struct {
	readErr, closeErr, statErr error
	reads, closes, stats       int
}

func (f *staticFileSystemTestFile) Read(p []byte) (int, error) {
	f.reads++
	return copy(p, "abc"), f.readErr
}

func (f *staticFileSystemTestFile) Close() error { f.closes++; return f.closeErr }
func (f *staticFileSystemTestFile) Stat() (fs.FileInfo, error) {
	f.stats++
	return staticFileSystemTestInfo("public.txt"), f.statErr
}

type staticFileSystemTestDirectory []string

type staticFileSystemTestDirFile struct {
	staticFileSystemTestFile
	entries  staticFileSystemTestDirectory
	position int
	counts   []int
	finalErr error
	emptyNil bool
}

func (f *staticFileSystemTestDirFile) ReadDir(n int) ([]fs.DirEntry, error) {
	f.counts = append(f.counts, n)
	if f.emptyNil {
		return nil, nil
	}
	if f.position == len(f.entries) {
		if n > 0 {
			return nil, io.EOF
		}
		return []fs.DirEntry{}, nil
	}
	end := len(f.entries)
	if n > 0 && n < end-f.position {
		end = f.position + n
	}
	entries := make([]fs.DirEntry, 0, end-f.position)
	for _, name := range f.entries[f.position:end] {
		entries = append(entries, fs.FileInfoToDirEntry(staticFileSystemTestInfo(name)))
	}
	f.position = end
	if f.position == len(f.entries) && f.finalErr != nil {
		return entries, f.finalErr
	}
	return entries, nil
}

type staticFileSystemTestSeekFile struct {
	staticFileSystemTestFile
	seekErr error
	seeks   int
	offset  int64
	whence  int
}

func (f *staticFileSystemTestSeekFile) Seek(offset int64, whence int) (int64, error) {
	f.seeks++
	f.offset, f.whence = offset, whence
	return 19, f.seekErr
}

type staticFileSystemTestInfo string

func (f staticFileSystemTestInfo) Name() string     { return string(f) }
func (staticFileSystemTestInfo) Size() int64        { return 3 }
func (staticFileSystemTestInfo) Mode() fs.FileMode  { return 0o600 }
func (staticFileSystemTestInfo) ModTime() time.Time { return time.Time{} }
func (staticFileSystemTestInfo) IsDir() bool        { return false }
func (staticFileSystemTestInfo) Sys() any           { return nil }

func staticFileSystemTestNames(entries []fs.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}
