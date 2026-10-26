#!/usr/bin/env python3
"""Minimal TCP sender for the probe: for every connection, wait for the one byte the C64 writes, then stream SIZE bytes
(byte i = i & 0xFF) and close. Standard library only.

  sender.py --port 18444 --size 262144
"""
import argparse
import socket
import socketserver
import sys


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        s, size = self.request, self.server.size
        s.settimeout(30)
        try:
            if not s.recv(1):
                return
            sent = 0
            while sent < size:
                n = min(65536, size - sent)
                s.sendall(bytes((sent + i) & 0xFF for i in range(n)))
                sent += n
            s.shutdown(socket.SHUT_WR)
            while s.recv(4096):          # wait for the C64's close
                pass
            print("%s:%d  sent %d" % (self.client_address + (sent,)), flush=True)
        except OSError as e:
            print("%s:%d  %s" % (self.client_address + (e,)), flush=True)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=18444)
    ap.add_argument("--size", type=int, default=262144, help="bytes per connection; same as mkcfg.py --size")
    a = ap.parse_args()
    srv = Server((a.bind, a.port), Handler)
    srv.size = a.size
    print("sending %d bytes per connection on %s:%d" % (a.size, a.bind, a.port), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
