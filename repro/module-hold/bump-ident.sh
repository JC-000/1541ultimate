#!/bin/sh
# BENCH ONLY. Raises IDENT_MINOR by 100 (and the version in IDENT_STRING with it) in the three WiFi modules, so that the
# updater installs the hold module: it reflashes a module only when the image's version differs (U64, U64E) or is higher
# (C64 Ultimate, Ultimate 64 Elite II, U2+L) than the module's. Run it from the repository root after the cherry-pick, on
# the same base for every build you flash. It reads the current value, so it works on master and on a PR head.
set -e
for h in software/wifi/raw_u64/main/rpc_dispatch.h software/wifi/raw_c3/main/rpc_dispatch.h software/u64ctrl/main/rpc_dispatch.h; do
    awk '
    /^#define IDENT_MINOR[ \t]/ { new = $3 + 100; sub(/[0-9]+[ \t]*$/, new); }
    /^#define IDENT_STRING[ \t]/ { if (match($0, /V[0-9]+\.[0-9]+/)) { v = substr($0, RSTART + 1, RLENGTH - 1); split(v, p, "."); line = $0; sub(/V[0-9]+\.[0-9]+/, "V" p[1] "." (p[2] + 100), line); $0 = line } }
    { print }' "$h" > "$h.new"
    cat "$h.new" > "$h" && rm "$h.new"   # keeps the file mode and line endings
    grep -E '^#define IDENT_(MINOR|STRING)' "$h"
done
