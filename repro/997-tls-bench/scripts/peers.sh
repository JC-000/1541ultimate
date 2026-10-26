#!/bin/sh
# peers.sh start|stop <outdir>
# Barry's two peers (benchmarks/nios-tls/peer/server.py :18443 TLS, plain_server.py :18444 plain) for one series,
# their logs in <outdir>/peer-tls.jsonl and peer-plain.jsonl, and optionally a packet capture of the device's traffic.
#
# Environment:
#   PEER_DIR       directory with server.py, plain_server.py, server.pem, server.key (Barry's tree at 74f0112e4:
#                  benchmarks/nios-tls/peer). Required.
#   DEVICE_IP      the Ultimate's address, for the capture filter. Required only with CAPTURE_IFACE.
#   CAPTURE_IFACE  wired interface that faces the device (e.g. eth0, en5). Unset = no capture.
# Only the PIDs this script recorded in <outdir> are stopped (never pkill).
set -u
cmd=${1:-} out=${2:-}
[ -n "$cmd" ] && [ -n "$out" ] || { echo "usage: peers.sh start|stop <outdir>" >&2; exit 2; }
: "${PEER_DIR:?set PEER_DIR to the benchmarks/nios-tls/peer directory}"
mkdir -p "$out" && cd "$out" || exit 2
case $cmd in
start)
  python3 -I "$PEER_DIR/server.py" > peer-tls.jsonl 2>&1 & echo $! > tls.pid
  python3 -I "$PEER_DIR/plain_server.py" > peer-plain.jsonl 2>&1 & echo $! > plain.pid
  names="tls plain"
  if [ -n "${CAPTURE_IFACE:-}" ]; then
    : "${DEVICE_IP:?set DEVICE_IP for the capture filter}"
    dumpcap -i "$CAPTURE_IFACE" -f "host $DEVICE_IP and (tcp port 18443 or tcp port 18444)" -w capture.pcapng > dumpcap.log 2>&1 & echo $! > cap.pid
    names="tls plain cap"
  fi
  sleep 3
  for f in $names; do kill -0 "$(cat $f.pid)" 2>/dev/null || { echo "FAIL: $f not running"; exit 1; }; done
  echo "peers${CAPTURE_IFACE:+ + capture} up in $out" ;;
stop)
  for f in cap tls plain; do [ -f $f.pid ] && kill "$(cat $f.pid)" 2>/dev/null; done
  sleep 1
  files="$PEER_DIR/server.py $PEER_DIR/plain_server.py"; [ -f capture.pcapng ] && files="capture.pcapng $files"
  shasum -a 256 $files > sha256.txt 2>/dev/null || sha256sum $files > sha256.txt
  python3 -I -c "import ssl,sys;print(sys.version.split()[0],ssl.OPENSSL_VERSION)" > python.txt
  echo "stopped; sha256.txt, python.txt written in $out" ;;
*) echo "usage: peers.sh start|stop <outdir>" >&2; exit 2 ;;
esac
