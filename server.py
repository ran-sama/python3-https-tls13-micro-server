#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""HTTPS server with A+ rating"""

import os
import ssl
import re
import sys
from http.server import ThreadingHTTPServer
from http.server import SimpleHTTPRequestHandler

MYSERV_WORKDIR = "/media/kingdian/server_pub"
# MYSERV_CLIENTCRT = "/home/ran/keys/client.pem"
MYSERV_FULLCHAIN = "/home/ran/.acme.sh/example.com_ecc/fullchain.cer"
MYSERV_PRIVKEY = "/home/ran/.acme.sh/example.com_ecc/example.com.key"


def create_ctx():
    """Create default context"""
    sslcontext = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    sslcontext.options |= ssl.OP_NO_TICKET
    sslcontext.options |= ssl.OP_NO_COMPRESSION
    sslcontext.options |= ssl.OP_SINGLE_ECDH_USE
    sslcontext.options |= ssl.OP_IGNORE_UNEXPECTED_EOF
    sslcontext.options |= ssl.PROTOCOL_TLS_SERVER
    # sslcontext.verify_mode = ssl.CERT_REQUIRED
    sslcontext.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305")
    sslcontext.set_ecdh_curve("secp384r1")
    # sslcontext.set_ecdh_curve("secp521r1")  # limited support
    # sslcontext.load_verify_locations(MYSERV_CLIENTCRT)
    # sslcontext.verify_flags &= ~ssl.VERIFY_X509_STRICT
    # sslcontext.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    sslcontext.load_cert_chain(MYSERV_FULLCHAIN, MYSERV_PRIVKEY)
    # diagnostic data 2186428625 2 557056 for Python-3.13.2
    # print(sslcontext.options, sslcontext.verify_mode, sslcontext.verify_flags)
    return sslcontext


class HSTSHandler(SimpleHTTPRequestHandler):
    """Serve request types"""
    def end_headers(self):
        """Upgrade headers to state of the art"""
        self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        # self.send_header("Content-Security-Policy", "default-src 'none'; img-src 'self'; script-src 'self'; font-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        # self.send_header("X-Robots-Tag", "none")
        self.send_header("Permissions-Policy", "camera=(), microphone=()")
        self.send_header("Cross-Origin-Embedder-Policy", "unsafe-none")
        self.send_header("Cross-Origin-Opener-Policy", "unsafe-none")
        self.send_header("Cross-Origin-Resource-Policy", "cross-origin")
        self.send_header("Referrer-Policy", "no-referrer")
        SimpleHTTPRequestHandler.end_headers(self)


HSTSHandler.extensions_map['.avif'] = 'image/avif'
HSTSHandler.extensions_map['.webp'] = 'image/webp'


def main():
    """Initialize"""
    try:
        sys.tracebacklimit = 0  # 1-line errorlog in production
        os.chdir(MYSERV_WORKDIR)  # auto-change working directory
        SimpleHTTPRequestHandler.sys_version = ""  # empty version string
        SimpleHTTPRequestHandler.server_version = "nginx"  # pretend to be nginx
        my_server = ThreadingHTTPServer(('0.0.0.0', 443), HSTSHandler)
        tlscontext = create_ctx()
        my_server.socket = tlscontext.wrap_socket(my_server.socket, do_handshake_on_connect=False, server_side=True, suppress_ragged_eofs=True)
        print('Starting server, use <Ctrl-C> to stop')
        my_server.serve_forever()
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, TimeoutError):
        print("caught")
        # pass
    except KeyboardInterrupt:
        print(' received, shutting down server')
        my_server.shutdown()


if __name__ == '__main__':
    main()
