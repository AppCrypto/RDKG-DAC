package main

import (
	"EVOLV_DAO/bn256"
	"EVOLV_DAO/crypto/DAC"
	"EVOLV_DAO/internal/benchfixture"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

type sample struct {
	Family, Operation               string
	Q, Public, Users, Round, Member int
	NS                              int64
}

var rows []sample

func add(f, op string, q, p, u, r, m int, d time.Duration) {
	if r >= 0 {
		rows = append(rows, sample{f, op, q, p, u, r, m, d.Nanoseconds()})
	}
}
func must(e error) {
	if e != nil {
		panic(e)
	}
}
func scalar() *big.Int { x, e := rand.Int(rand.Reader, bn256.Order); must(e); return x }
func sourceHashes() map[string]string {
	out := map[string]string{}
	must(filepath.WalkDir(".", func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "results") {
			return filepath.SkipDir
		}
		if !d.IsDir() && (filepath.Ext(p) == ".go" || p == "go.mod" || p == "go.sum") {
			b, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			h := sha256.Sum256(b)
			out[p] = hex.EncodeToString(h[:])
		}
		return nil
	}))
	return out
}
func primitives(n, warm int) {
	_, g1, e := bn256.RandomG1(rand.Reader)
	must(e)
	g2 := new(bn256.G2).ScalarBaseMult(scalar())
	gt := bn256.Pair(g1, g2)
	for r := -warm; r < n; r++ {
		s := scalar()
		start := time.Now()
		new(bn256.G1).ScalarMult(g1, s)
		add("primitives", "E_G1", 0, 0, 0, r, -1, time.Since(start))
		start = time.Now()
		new(bn256.G2).ScalarMult(g2, s)
		add("primitives", "E_G2", 0, 0, 0, r, -1, time.Since(start))
		start = time.Now()
		new(bn256.GT).ScalarMult(gt, s)
		add("primitives", "E_GT", 0, 0, 0, r, -1, time.Since(start))
		start = time.Now()
		bn256.Pair(g1, g2)
		add("primitives", "pairing", 0, 0, 0, r, -1, time.Since(start))
		input := "cred" + string(new(bn256.G1).ScalarMult(g1, s).Marshal())
		start = time.Now()
		_, e := bn256.HashG1(input)
		must(e)
		add("primitives", "H_G", 0, 0, 0, r, -1, time.Since(start))
	}
}
func lifecycle(n, warm int) {
	for q := 1; q <= 7; q++ {
		f, e := benchfixture.New(q)
		must(e)
		for r := -warm; r < n; r++ {
			start := time.Now()
			must(f.Prepare())
			add("lifecycle", "prepare", q, 0, 0, r, -1, time.Since(start))
			f.Blind = make([]*DAC.BlindSignature, 5)
			for _, i := range f.I {
				start = time.Now()
				f.Blind[i], e = DAC.BlindSign_EDAO(f.P, f.SK[i], f.Request, f.ID)
				must(e)
				add("lifecycle", "blind_sign", q, 0, 0, r, i, time.Since(start))
			}
			start = time.Now()
			must(f.Obtain())
			add("lifecycle", "obtain", q, 0, 0, r, -1, time.Since(start))
			start = time.Now()
			th, e := DAC.GenToken(f.P, f.MPK, f.Trace.D, f.Sig, f.Attrs, f.ID, nil)
			must(e)
			add("lifecycle", "generate", q, 0, 0, r, -1, time.Since(start))
			start = time.Now()
			ok, e := DAC.VerifyTok(f.P, f.MPK, f.Trace.D, th, nil)
			must(e)
			if !ok {
				panic("invalid measured token")
			}
			add("lifecycle", "verify", q, 0, 0, r, -1, time.Since(start))
		}
		fmt.Printf("completed lifecycle q=%d (%d rounds)\n", q, n)
	}
}
func selective(n, warm int) {
	f, e := benchfixture.New(7)
	must(e)
	for public := 1; public <= 6; public++ {
		ds := make([]int, public)
		for j := range ds {
			ds[j] = j + 1
		}
		for r := -warm; r < n; r++ {
			start := time.Now()
			th, e := DAC.GenToken(f.P, f.MPK, f.Trace.D, f.Sig, f.Attrs, f.ID, ds)
			must(e)
			add("selective", "generate", 7, public, 0, r, -1, time.Since(start))
			start = time.Now()
			ok, e := DAC.VerifyTok(f.P, f.MPK, f.Trace.D, th, th.Disclosed)
			must(e)
			if !ok {
				panic("invalid selective token")
			}
			add("selective", "verify", 7, public, 0, r, -1, time.Since(start))
		}
		fmt.Printf("completed selective public=%d (%d rounds)\n", public, n)
	}
}
func tracing(n, warm int) {
	f, e := benchfixture.New(1)
	must(e)
	want := new(bn256.G1).ScalarMult(f.P.G1, f.ID).Marshal()
	for users := 20; users <= 100; users += 20 {
		registry := map[string]string{string(want): "synthetic-user"}
		for j := 1; j < users; j++ {
			key := new(bn256.G1).ScalarMult(f.P.G1, big.NewInt(int64(j))).Marshal()
			registry[string(key)] = fmt.Sprintf("synthetic-%d", j)
		}
		for r := -warm; r < n; r++ {
			th, e := DAC.GenToken(f.P, f.MPK, f.Trace.D, f.Sig, f.Attrs, f.ID, nil)
			must(e)
			total := time.Now()
			start := time.Now()
			shares := make([]*DAC.DecryptionShare, 0, 3)
			for _, i := range f.I {
				s, e := DAC.ComputeDecryptionShare(f.P, f.Trace, th.ElGamalCipher, i)
				must(e)
				shares = append(shares, s)
			}
			shareTime := time.Since(start)
			start = time.Now()
			for _, s := range shares {
				must(DAC.ProveDecryptionShare(f.P, f.Trace, th.ElGamalCipher, s))
			}
			proveTime := time.Since(start)
			start = time.Now()
			for _, s := range shares {
				if !DAC.VerifyDecryptionShare(f.P, f.Trace, th.ElGamalCipher, s) {
					panic("invalid trace proof")
				}
			}
			verifyTime := time.Since(start)
			start = time.Now()
			u, e := DAC.CombineVerifiedDecryption(f.Trace, th.ElGamalCipher, shares)
			must(e)
			combineTime := time.Since(start)
			start = time.Now()
			id, ok := registry[string(u.Marshal())]
			lookupTime := time.Since(start)
			totalTime := time.Since(total)
			if !ok || id != "synthetic-user" || !bytes.Equal(want, u.Marshal()) {
				panic("incorrect threshold trace")
			}
			for op, d := range map[string]time.Duration{"share": shareTime, "prove": proveTime, "verify": verifyTime, "combine": combineTime, "lookup": lookupTime, "total": totalTime} {
				add("tracing", op, 1, 0, users, r, -1, d)
			}
		}
		fmt.Printf("completed tracing users=%d (%d rounds)\n", users, n)
	}
}
func writeRaw(dir string) {
	f, e := os.Create(filepath.Join(dir, "samples.csv"))
	must(e)
	w := csv.NewWriter(f)
	must(w.Write([]string{"family", "operation", "q", "public", "users", "round", "member", "n", "t", "duration_ns"}))
	for _, s := range rows {
		must(w.Write([]string{s.Family, s.Operation, strconv.Itoa(s.Q), strconv.Itoa(s.Public), strconv.Itoa(s.Users), strconv.Itoa(s.Round), strconv.Itoa(s.Member), "5", "3", strconv.FormatInt(s.NS, 10)}))
	}
	w.Flush()
	must(w.Error())
	must(f.Close())
}
func main() {
	n := flag.Int("rounds", 100, "protocol samples per configuration")
	pn := flag.Int("primitive-rounds", 500, "primitive samples")
	warm := flag.Int("warmup", 5, "unrecorded warmup rounds")
	out := flag.String("out", "results/revised", "new run directory; must not exist")
	flag.Parse()
	if *n < 1 || *pn < 1 || *warm < 0 {
		panic("invalid sample counts")
	}
	if _, e := os.Stat(*out); e == nil {
		panic("output directory exists")
	}
	must(os.MkdirAll(*out, 0755))
	runtime.GOMAXPROCS(1)
	started := time.Now().UTC()
	hashes := sourceHashes()
	primitives(*pn, *warm)
	lifecycle(*n, *warm)
	selective(*n, *warm)
	tracing(*n, *warm)
	writeRaw(*out)
	metadata := map[string]interface{}{"started_utc": started.Format(time.RFC3339Nano), "finished_utc": time.Now().UTC().Format(time.RFC3339Nano), "go_version": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "logical_cpus": runtime.NumCPU(), "gomaxprocs": runtime.GOMAXPROCS(0), "protocol_rounds": *n, "primitive_rounds": *pn, "warmup": *warm, "source_sha256": hashes, "curve": "upstream bn256, unchanged", "threshold": 3, "committee_size": 5, "randomness": "crypto/rand; fresh issuance and presentation randomness", "scope": "local off-chain cryptographic operations; input validation and proof checks included; setup, authenticated registration, policy review, governance, network and blockchain gas excluded", "validation": "all measured presentations and traces must pass; obtaining a credential verifies every partial signature", "tracing": "total wall time includes all verified partial decryptions, interpolation and indexed registry lookup; subphases also recorded", "comparisons": "other schemes use operation-count estimates calibrated on this run, not new end-to-end implementations", "complete": true}
	b, e := json.MarshalIndent(metadata, "", "  ")
	must(e)
	must(os.WriteFile(filepath.Join(*out, "metadata.json"), append(b, '\n'), 0644))
	fmt.Printf("complete: %d validated samples in %s\n", len(rows), *out)
}
