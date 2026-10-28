# RDKG-DAC

Experimental implementation for **Anonymous Credentials with Dynamic Threshold
Issuance and Traceability Using Evolving DAO**.

This repository contains the source files from the paper's `experiments`
directory, placed at the repository root. It includes the revised off-chain DAC
protocol, RDKG/VSS and resharing, benchmark runners, and the original Solidity
contract and Go demo. Raw experiment results and local configuration are not
included in this source release.

## Requirements

- Go 1.23.3 or later (measurements used Go 1.25.4).
- For the optional blockchain demo: a compatible Ethereum JSON-RPC endpoint,
  funded test accounts, and local `.env` configuration.
- To regenerate the contract artifacts: Solidity compiler and `abigen`.

## Test

```sh
go test ./crypto/DAC ./crypto/RDKG/... ./cmd/revisedbench
```

To test the original blockchain demo and the `bn256` dependency tests as well,
fetch the full dependency set and run `go test -mod=mod ./...`.

## Run the revised off-chain benchmarks

```sh
go run ./cmd/revisedbench -rounds 100 -primitive-rounds 500 -warmup 10 -out results/new-run
```

The runner needs no blockchain connection. It refuses an existing output
directory and records individual samples, runtime metadata, and source hashes.
Every measured presentation, partial-credential check, and threshold opening
must validate before the run is marked complete. Secrets remain in memory and
are not written to result files.

To rerun only the lifecycle and selective-disclosure measurements:

```sh
go test ./cmd/revisedbench -run '^TestRerunFigures67$' -count=1 -v -args -fig67-out results/new-fig67-run -fig67-rounds 100 -fig67-warmup 10
```

## Source layout

- `crypto/DAC/`: fresh commitment-derived issuance bases, joint issuance proofs,
  independent presentation/encryption/signature masks, selective disclosure,
  checked partial credentials, and verified threshold ElGamal opening.
- `crypto/RDKG/`: distributed key generation, VSS, and verified resharing.
- `bn256/`: the original elliptic-curve implementation and its license.
- `internal/benchfixture/` and `cmd/revisedbench/`: synthetic fixtures and benchmarks.
- `scripts/`: paper-data update utilities; these require the corresponding paper
  and benchmark result directory supplied separately.
- `compile/`: Solidity source, generation script, and contract artifacts used by
  the original Go demo. Regenerate with `cd compile && bash compile.sh`.
- `main.go` and `utils/`: the original blockchain demo, which requires local
  configuration and is separate from the offline benchmark runner.

Authentication, policy review, network transport, and blockchain execution are
outside the revised off-chain timings. DAC attribute changes use authenticated
reissuance; the implementation does not provide credential revocation.

## Provenance

The original source was copied from `AppCrypto/RDKG-DAC-SSO` at commit
`70b8ecc31a6ca5231712ce96df7e76acb575f9eb`. `upstream.json` records the original
file hashes, and `UPSTREAM_README.md` preserves its historical instructions.
The original `bn256` implementation is unchanged. No deployment keys or `.env`
files are included.
