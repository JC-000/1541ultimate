#!/bin/sh
# set-barry-peer.sh <barry-tree> <peer-ip>
# The peer-address change on top of barryw/1541ultimate 74f0112e4 (branch bench/nios-tls-2026-10-24): his
# software/api/tls_bench.cc connects to a fixed address in two places (the plain leg in run_plain(), the TLS leg in
# run_benchmark()). Both inet_addr("...") literals become <peer-ip>. Nothing else changes. Refuses to run unless
# exactly those two lines are found, and prints the resulting diff.
set -eu
[ $# -eq 2 ] || { echo "usage: $0 <barry-tree> <peer-ip>" >&2; exit 2; }
tree=$1 peer=$2
f=$tree/software/api/tls_bench.cc
case $peer in *[!0-9.]*|"") echo "peer-ip must be a dotted IPv4 address" >&2; exit 2;; esac
[ -f "$f" ] || { echo "no $f" >&2; exit 2; }
n=$(grep -c 'address.sin_addr.s_addr = inet_addr("[0-9.]*");' "$f")
[ "$n" = 2 ] || { echo "expected exactly 2 inet_addr literals in $f, found $n (is the tree at 74f0112e4?)" >&2; exit 1; }
# in-place edit that keeps the file's line endings (the sed script never touches the line terminator)
sed -i.orig "s/address.sin_addr.s_addr = inet_addr(\"[0-9.]*\");/address.sin_addr.s_addr = inet_addr(\"$peer\");/" "$f"
rm -f "$f.orig"
git -C "$tree" diff --stat -- software/api/tls_bench.cc
git -C "$tree" diff -U0 -- software/api/tls_bench.cc
