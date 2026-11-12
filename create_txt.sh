#!/usr/bin/env bash

EV=~/workspace/lab-notes/evidencia/2026-11-12
mkdir -p "$EV"

for BIN in fixtures/hello32.exe fixtures/hello64.exe fixtures/hello-net.exe; do
  BASE=$(basename "$BIN")
  ./target/debug/pe-inspect --sections "$BIN" > "$EV/pe-inspect-$BASE.txt"
  llvm-readobj --sections "$BIN" > "$EV/llvm-readobj-$BASE.txt"
  objdump -h "$BIN" > "$EV/objdump-$BASE.txt"
  file "$BIN" > "$EV/file-$BASE.txt"
  sha256sum "$BIN" > "$EV/sha256-$BASE.txt"
  python3 tools/entropy.py "$BIN" > "$EV/entropy-$BASE.txt"
done
