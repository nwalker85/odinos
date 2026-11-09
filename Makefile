# Odin OS Phase B.3.2 Canonical Release Makefile
.PHONY: all build test qemu authority-tests verifier-tests smt paper verify-release clean

SOURCE_DATE_EPOCH ?= 1700000000

all: verify-release

build:
	cargo build --release --target riscv64gc-unknown-none-elf

test:
	cargo test --lib --target aarch64-apple-darwin

qemu:
	cargo run --release

authority-tests:
	python3 -m unittest tests/test_authority_isolation.py

verifier-tests:
	python3 -m unittest tests/test_evidence_verifier_adversarial.py

smt:
	for f in formal/*.smt2; do echo -n "$$f: "; z3 "$$f"; done

paper:
	SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) typst compile zenodo/odin-os-whitepaper.typ zenodo/odin-os-whitepaper.pdf

verify-release:
	python3 tools/verify_release.py

clean:
	cargo clean
	rm -f tools/release_verification_report.json
