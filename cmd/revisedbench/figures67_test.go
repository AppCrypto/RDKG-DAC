package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

var figures67Out = flag.String("fig67-out", "", "new run directory; empty skips the performance run")
var figures67Rounds = flag.Int("fig67-rounds", 100, "measured rounds per Figure 6/7 configuration")
var figures67Warmup = flag.Int("fig67-warmup", 10, "unrecorded warmup rounds")

// This reuses exactly the lifecycle/selective code used by the full benchmark.
// It deliberately does not rerun primitive calibration or tracing.
func TestRerunFigures67(t *testing.T) {
	if *figures67Out == "" {
		t.Skip("set -fig67-out to run the Figure 6/7 experiment")
	}
	if *figures67Rounds < 1 || *figures67Warmup < 0 {
		t.Fatal("invalid round counts")
	}
	if _, e := os.Stat(*figures67Out); !os.IsNotExist(e) {
		t.Fatal("output directory exists or cannot be inspected")
	}
	// go test normally runs from cmd/revisedbench; benchmark hashes are module-relative.
	originalDir, e := os.Getwd()
	must(e)
	root := filepath.Clean(filepath.Join(originalDir, "../.."))
	must(os.Chdir(root))
	defer os.Chdir(originalDir)
	out := *figures67Out
	if !filepath.IsAbs(out) {
		out = filepath.Join(root, out)
	}
	if _, e := os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("output directory exists or cannot be inspected")
	}
	must(os.MkdirAll(out, 0755))
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	rows = nil
	started := time.Now().UTC()
	hashes := sourceHashes()
	lifecycle(*figures67Rounds, *figures67Warmup)
	selective(*figures67Rounds, *figures67Warmup)
	writeRaw(out)
	meta := map[string]interface{}{"complete": true, "suite": "figures6-7", "started_utc": started.Format(time.RFC3339Nano), "finished_utc": time.Now().UTC().Format(time.RFC3339Nano), "protocol_rounds": *figures67Rounds, "warmup": *figures67Warmup, "primitive_rounds": 0, "source_sha256": hashes, "go_version": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "gomaxprocs": 1, "logical_cpus": runtime.NumCPU(), "threshold": 3, "committee_size": 5, "randomness": "crypto/rand; fresh issuance and presentation randomness", "scope": "Only Figures 6 and 7: unchanged lifecycle/selective benchmark functions, including input validation, NIZK verification and every partial-credential check; setup/network/policy/on-chain work excluded", "unchanged": "No recalibration of primitives, no tracing rerun and no cross-scheme model changes"}
	b, e := json.MarshalIndent(meta, "", "  ")
	must(e)
	must(os.WriteFile(filepath.Join(out, "metadata.json"), append(b, '\n'), 0644))
	fmt.Printf("complete: %d validated Figure 6/7 samples in %s\n", len(rows), out)
}
