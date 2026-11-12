// Package botanbench makes Botan's `botan speed Twofish` readable as Go
// benchmarks, so abbench can interleave it with this module's own
// BenchmarkEncrypt / BenchmarkDecrypt and benchstat can compare them.
//
// Each benchmark runs `botan speed` once (a Botan figure is a rate over its own
// --msec window, not a per-iteration time) and reports ns/op for one 1024-byte
// buffer, the same unit as this module's benchmarks. Run it with
//
//	go test -c ./internal/botanbench && ./botanbench.test -test.bench .
package botanbench

import (
	"flag"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"testing"
)

var (
	clearCPUID = flag.String("botan.clear-cpuid", "", "value of botan speed --clear-cpuid (to measure Botan's scalar code)")
	msec       = flag.Int("botan.msec", 1000, "botan speed --msec")
)

var rate = regexp.MustCompile(`Twofish(?: \[[^\]]*\])? (encrypt|decrypt) buffer size 1024 bytes: ([0-9.]+) MiB/sec`)

var (
	once sync.Once
	nsOp = map[string]float64{}
	err  error
)

func measure() {
	args := []string{"speed", "--buf-size=1024", "--msec=" + strconv.Itoa(*msec)}
	if *clearCPUID != "" {
		args = append(args, "--clear-cpuid="+*clearCPUID)
	}
	args = append(args, "Twofish")
	out, e := exec.Command("botan", args...).Output()
	if e != nil {
		err = e
		return
	}
	for _, m := range rate.FindAllStringSubmatch(string(out), -1) {
		mib, _ := strconv.ParseFloat(m[2], 64)
		nsOp[m[1]] = 1024 / (mib * 1048576) * 1e9
	}
	if len(nsOp) != 2 {
		err = fmt.Errorf("unexpected botan output: %q", out)
	}
}

func bench(b *testing.B, dir string) {
	once.Do(measure)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
	}
	b.ReportMetric(nsOp[dir], "ns/op")
}

func BenchmarkEncrypt(b *testing.B) { bench(b, "encrypt") }
func BenchmarkDecrypt(b *testing.B) { bench(b, "decrypt") }
