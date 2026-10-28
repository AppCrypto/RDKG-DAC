# RDKG-DAC

Implementation of **Anonymous Credentials with Dynamic Threshold Issuance and
Traceability Using Evolving DAO**, using Go and Solidity.

## Requirements

Go 1.23.3 or later. The blockchain demo additionally requires an Ethereum RPC
endpoint and account configuration in a local `.env` file.

## Tests

```sh
go test ./crypto/DAC ./crypto/RDKG/... ./cmd/revisedbench
```

## Benchmarks

```sh
go run ./cmd/revisedbench -rounds 100 -primitive-rounds 500 -warmup 10 -out results/new-run
```

Benchmarks run locally without a blockchain connection. Use a new output
directory for each run; samples and runtime metadata are saved there.

## Code

- `crypto/`: DAC, RDKG, VSS, and resharing protocols.
- `bn256/`: elliptic-curve operations.
- `cmd/revisedbench/`: benchmark runner.
- `compile/`: Solidity contract and generated bindings.
- `main.go`: protocol and blockchain demos.
- `scripts/`: paper-data update utilities.
