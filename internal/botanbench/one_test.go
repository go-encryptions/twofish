package botanbench

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// one.cpp times Botan's Twofish with one-block calls, the shape of
// cipher.Block.Encrypt, which `botan speed` (one 64-block call) does not
// measure: see one.cpp for why the two differ.
var (
	oneOnce sync.Once
	oneBin  string
	oneErr  error
)

func buildOne() {
	cache, err := os.UserCacheDir()
	if err != nil {
		oneErr = err
		return
	}
	dir := filepath.Join(cache, "twofish-botanbench")
	if oneErr = os.MkdirAll(dir, 0o755); oneErr != nil {
		return
	}
	oneBin = filepath.Join(dir, "one")
	// The binary may run from any directory (abbench runs it from the repo
	// root), so the source is found from this file, not the working directory.
	_, here, _, _ := runtime.Caller(0)
	src := filepath.Join(filepath.Dir(here), "one", "one.cpp")
	args := []string{"-std=c++20", "-O2", src, "-lbotan-3", "-o", oneBin}
	if inc := os.Getenv("BOTAN_PREFIX"); inc != "" {
		args = append([]string{"-I" + filepath.Join(inc, "include", "botan-3"), "-L" + filepath.Join(inc, "lib"),
			"-Wl,-rpath," + filepath.Join(inc, "lib")}, args...)
	} else {
		args = append([]string{"-I/opt/homebrew/include/botan-3", "-L/opt/homebrew/lib", "-Wl,-rpath,/opt/homebrew/lib"}, args...)
	}
	if out, e := exec.Command("c++", args...).CombinedOutput(); e != nil {
		oneErr = &buildError{e, string(out)}
	}
}

type buildError struct {
	err error
	out string
}

func (b *buildError) Error() string { return b.err.Error() + ": " + b.out }

func oneBlock(b *testing.B, mode, dir string) {
	oneOnce.Do(buildOne)
	if oneErr != nil {
		b.Skip(oneErr)
	}
	out, err := exec.Command(oneBin, mode, dir).Output()
	if err != nil {
		b.Fatal(err)
	}
	us, err := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
	}
	b.ReportMetric(us*1000, "ns/op")
}

// BenchmarkOneBlock* are 64 one-block calls; BenchmarkNBlocks* one 64-block call.
func BenchmarkOneBlockEncrypt(b *testing.B) { oneBlock(b, "one", "encrypt") }
func BenchmarkOneBlockDecrypt(b *testing.B) { oneBlock(b, "one", "decrypt") }
func BenchmarkNBlocksEncrypt(b *testing.B)  { oneBlock(b, "n", "encrypt") }
func BenchmarkNBlocksDecrypt(b *testing.B)  { oneBlock(b, "n", "decrypt") }
