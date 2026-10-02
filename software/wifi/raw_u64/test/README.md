# Engine host test

`engine_test.c` plays the Ultimate against the real `rpc_dispatch.c` and `tls_engine.c`, built on the host
with mbedTLS 4.1.1 in the ESP32's configuration (ASan and UBSan on). It builds every request byte by byte at
the protocol spec's offsets, never from `rpc_calls.h`, so a layout slip on the ESP32 side fails here.
The server is `m3srv.c` (mbedTLS 3.6.0, default configuration), which can also answer a ClientHello by hand
(version refusals, the downgrade sentinel) and log what the client offered.

    ./build.sh head          # this tree; also base (the previous engine at a846369f) and mut-NAME
    ./run.sh head [CASE...]  # each case runs in its own process; server logs in build/head/logs
    ./mutrun.sh              # every mutant in mutants/ must be killed by at least one case

`mutants/make.py` rewrites the mutant patches from the current `main/`. `build.sh` names the libraries it
links (mbedTLS 4.1.1 built for the host with this bridge's sdkconfig, and mbedTLS 3.6.0);
set their paths in MB4, S4, IDF, SRV and S36. The PKI (`mkpki.sh`) is generated, throwaway, and
trusted nowhere else.

## Reference

`build.sh [VARIANT...]` (default `head`):

    head           this tree
    base           the previous engine at a846369f (built with -DBASE_ENGINE, where the TLS task and
                   CLOSE_ALL/SET_CA do not exist), for RED runs
    mut-NAME       this tree with mutants/NAME.patch applied
    at-SHA[+NAME]  the engine at commit SHA, optionally with mutant NAME applied

Inputs, all read-only and required in the environment:

    MB4   mbedTLS 4.1.1 (espressif ce3f3485) built for the host with this bridge's sdkconfig, ASan+UBSan
    S4    its source tree
    IDF   ESP-IDF v6.0.3 (76f5dedd), for esp_crt_bundle.c and gen_crt_bundle.py
    SRV   mbedTLS 3.6.0 with its default configuration (the server side), and S36 its source

Output: `build/<variant>/engine_test`, `build/m3srv`, `build/pki` (`mkpki.sh`).

`engine_test [CASE...]` runs every case (or the named ones), each in its own process. Environment:
M3SRV (server binary), PKI (`mkpki.sh` output), LOGDIR, PORTBASE; `run.sh` sets them.

`m3srv PORT tls OPTIONS...` is a TLS server (mbedTLS 3.6.0, default configuration); `m3srv PORT raw:WHAT`
uses no TLS library: it reads the ClientHello, logs it, and answers WHAT by hand. Everything it sees goes to
stdout, one "KEY value" line each, for the test to check.

    tls OPTIONS (key=value):
      ver=13|12|1213     versions offered (min and max)
      groups=a:b         key-exchange groups, IANA hex (e.g. 0017 or 001d:0017)
      crt=FILE key=FILE  server certificate chain and key (PEM)
      ems=0              TLS 1.2 without the extended master secret extension
      ownusage=0         skip the server's check of its own certificate's (extended) key usage, to serve one that
                         the client must refuse (the DER sent is unchanged)
      run=TOKENS         what to do after the handshake, comma separated, in order:
        app:N        one application data record of N bytes of the test pattern
        wa:D / fa:D  a warning / fatal alert with description D (encrypted as the session is)
        cn           close_notify
        rd:N         read N bytes of plaintext and check them against the client pattern
        echo         echo plaintext until close_notify or EOF, then log which one it was
        drain        read until close_notify or EOF, log which one it was
        sleep:MS     sleep
        rst          close with SO_LINGER 0
    raw WHAT:
      ch         nothing (the ClientHello audit only)
      sh12       a TLS 1.2 ServerHello (legacy_version 0x0303, no supported_versions)
      sh12s      the same with the RFC 8446 4.1.3 downgrade sentinel in its random
      sh11       a ServerHello for TLS 1.1 (0x0302)
      sh12suite  a TLS 1.2 ServerHello choosing a suite the client never offered (a CBC one mbedTLS still has)
      sh13comp   a TLS 1.3 ServerHello (supported_versions 0x0304, key_share x25519, the session id echoed, no sentinel)
                 with legacy_compression_method 1
      sh13suite  the same with compression 0 and a suite the client never offered (TLS_AES_128_CCM_8_SHA256)
      sh13s      the same with an offered suite and the downgrade sentinel in its random (a 1.3 ServerHello: no downgrade)
      alert70    a plaintext fatal protocol_version alert
      cn         a plaintext close_notify warning alert
      hrrcookie  a TLS 1.3 HelloRetryRequest for secp256r1 carrying a cookie, then the second ClientHello logged as CH2

The test pattern: byte i of a direction's plaintext stream is (i * 31 + seed) & 0xFF, seed 7 from the server and 11 from the client.
