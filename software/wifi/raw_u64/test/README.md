# Engine host test (M3-SPEC v1 section 5)

`engine_test.c` plays the Ultimate against the real `rpc_dispatch.c` and `tls_engine.c`, built on the host
with mbedTLS 4.1.1 in the ESP32's configuration (ASan and UBSan on). It builds every request byte by byte at
the offsets the spec freezes, never from `rpc_calls.h`, so a layout slip on the ESP32 side fails here.
The server is `m3srv.c` (mbedTLS 3.6.0, default configuration), which can also answer a ClientHello by hand
(version refusals, the downgrade sentinel) and log what the client offered.

    ./build.sh head          # this tree; also base (the M2 engine at a846369f) and mut-NAME
    ./run.sh head [CASE...]  # each case runs in its own process; server logs in build/head/logs
    ./mutrun.sh              # every mutant in mutants/ must be killed by at least one case

`mutants/make.py` rewrites the mutant patches from the current `main/`. `build.sh` names the libraries it
links (mbedTLS 4.1.1 built by engine4's `build_mb4.sh` with this bridge's sdkconfig, and mbedTLS 3.6.0);
set their paths in MB4, S4, IDF, SRV and S36. The PKI (`mkpki.sh`) is generated, throwaway, and
trusted nowhere else.
