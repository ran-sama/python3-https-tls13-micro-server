#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, ssl
from socketserver import ThreadingMixIn
from http.server import SimpleHTTPRequestHandler, HTTPServer

MYSERV_WORKDIR = "/media/kingdian/server_pub"
#MYSERV_CLIENTCRT = "/home/ran/keys/client.pem"
MYSERV_FULLCHAIN = "/home/ran/.acme.sh/example.com_ecc/fullchain.cer"
MYSERV_PRIVKEY = "/home/ran/.acme.sh/example.com_ecc/example.com.key"

global sslcontext
sslcontext = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
sslcontext.options |= ssl.OP_NO_TICKET
sslcontext.options |= ssl.OP_NO_COMPRESSION
sslcontext.options |= ssl.OP_SINGLE_ECDH_USE
sslcontext.options |= ssl.OP_IGNORE_UNEXPECTED_EOF
#sslcontext.protocol = ssl.PROTOCOL_TLS
#sslcontext.verify_mode = ssl.CERT_REQUIRED
sslcontext.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305")
sslcontext.set_ecdh_curve("secp384r1")#works well with everything
#sslcontext.set_ecdh_curve("secp521r1")#works well on firefox but you can also use secp384r1
#sslcontext.load_verify_locations(MYSERV_CLIENTCRT)
#sslcontext.verify_flags &= ~ssl.VERIFY_X509_PARTIAL_CHAIN
sslcontext.load_cert_chain(MYSERV_FULLCHAIN, MYSERV_PRIVKEY)

class HSTSHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        #self.send_header("Content-Security-Policy", "default-src 'none'; img-src 'self'; script-src 'self'; font-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        #self.send_header("X-Robots-Tag", "none")
        self.send_header("Permissions-Policy", "camera=(), microphone=()")
        self.send_header("Cross-Origin-Embedder-Policy", "unsafe-none")
        self.send_header("Cross-Origin-Opener-Policy", "unsafe-none")
        self.send_header("Cross-Origin-Resource-Policy", "cross-origin")
        self.send_header("Referrer-Policy", "no-referrer")
        SimpleHTTPRequestHandler.end_headers(self)

HSTSHandler.extensions_map['.avif'] = 'image/avif'
HSTSHandler.extensions_map['.webp'] = 'image/webp'

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

def main():
    try:
        os.chdir(MYSERV_WORKDIR)#auto-change working directory
        SimpleHTTPRequestHandler.sys_version = ""#empty version string
        SimpleHTTPRequestHandler.server_version = "nginx"#pretend to be nginx
        my_server = ThreadedHTTPServer(('0.0.0.0', 443), HSTSHandler)
        my_server.socket = sslcontext.wrap_socket(my_server.socket, do_handshake_on_connect=False, server_side=True)
        print('Starting server, use <Ctrl-C> to stop')
        my_server.serve_forever()
    except Exception as e:#except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, TimeoutError, ssl.SSLError):
        print(type(e))
        pass
    except KeyboardInterrupt:
        print(' received, shutting down server')
        my_server.shutdown()

if __name__ == '__main__':
    main()
