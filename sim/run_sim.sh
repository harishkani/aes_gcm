#!/usr/bin/env bash
# run_sim.sh – Compile and simulate AES-128-GCM with iverilog
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$SCRIPT_DIR/.."

echo "Compiling..."
iverilog -g2005 -o "$SCRIPT_DIR/aes_gcm_sim" \
    "$ROOT/rtl/aes_encrypt.v"  \
    "$ROOT/rtl/gf128_mult.v"   \
    "$ROOT/rtl/aes_gcm.v"      \
    "$ROOT/tb/aes_gcm_tb.v"

echo "Simulating..."
vvp "$SCRIPT_DIR/aes_gcm_sim"
