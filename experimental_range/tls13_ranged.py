#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""HTTPS range request server with custom indexer"""

import os
import ssl
import urllib.parse
import html
import sys
import io
import shutil
from http import HTTPStatus
from ranged_server import ThreadingHTTPServer  # from http.server import ThreadingHTTPServer
from ranged_server import SimpleHTTPRequestHandler  # from http.server import SimpleHTTPRequestHandler

MYSERV_WORKDIR = "/media/kingdian/server_priv"
# MYSERV_CLIENTCRT = "/home/ran/keys/client.pem"
MYSERV_FULLCHAIN = "/home/ran/keys/fullchain.pem"
MYSERV_PRIVKEY = "/home/ran/keys/privkey.pem"

DOMAIN_PREFIX = "https://example.com/somedir/"


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
    """Replace function definitions with improved versions"""
    def end_headers(self):
        """Send state of the art headers"""
        self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        # self.send_header("Content-Security-Policy", "default-src 'none'; img-src 'self'; script-src 'self'; font-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Robots-Tag", "none")
        self.send_header("Permissions-Policy", "camera=(), microphone=()")
        self.send_header("Cross-Origin-Embedder-Policy", "unsafe-none")
        self.send_header("Cross-Origin-Opener-Policy", "unsafe-none")
        self.send_header("Cross-Origin-Resource-Policy", "cross-origin")
        self.send_header("Referrer-Policy", "no-referrer")
        SimpleHTTPRequestHandler.end_headers(self)

    def list_directory(self, path):
        """Overwrite list_directory with custom indexing"""
        try:
            dirlist = os.listdir(path)
        except OSError:
            self.send_error(
                HTTPStatus.NOT_FOUND,
                "No permission to list directory")
            return None
        # dirlist.sort(key=lambda a: a.lower())
        dirlist.sort(key=lambda a: os.path.splitext(a)[::-1])
        r = []
        try:
            displaypath = urllib.parse.unquote(self.path,
                                               errors='surrogatepass')
        except UnicodeDecodeError:
            displaypath = urllib.parse.unquote(self.path)
        displaypath = html.escape(displaypath, quote=False)
        enc = sys.getfilesystemencoding()
        title = f'Directory listing for {displaypath}'
        r.append('<!DOCTYPE HTML>')
        r.append('<html lang="en">')
        r.append('<head>')
        r.append(f'<meta charset="{enc}">')
        r.append('<style type="text/css">\n:root {\ncolor-scheme: light dark;\n}\n</style>')
        r.append(f'<title>{title}</title>\n</head>')
        r.append(f'<body>\n<h1>{title}</h1>')
        r.append('<hr>\n<ul>')
        for name in dirlist:
            fullname = os.path.join(path, name)
            if os.path.isdir(fullname) is False:
                customname = DOMAIN_PREFIX + urllib.parse.quote(name, errors='surrogatepass')
                r.append(f'<a href="{customname}">{customname}</a><br>')
        r.append('<br><br><textarea rows="40" cols="200">')
        for name in dirlist:
            fullname = os.path.join(path, name)
            if os.path.isdir(fullname) is False:
                customname = DOMAIN_PREFIX + urllib.parse.quote(name, errors='surrogatepass')
                r.append(f'{customname}')
        r.append('</textarea>')
        r.append('</ul>\n<hr>\n</body>\n</html>\n')
        encoded = '\n'.join(r).encode(enc, 'surrogateescape')
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", "text/html; charset={enc}")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        return f

    def copyfile(self, source, outputfile, *, range=None):
        """Overwrite copyfile with error handling"""
        try:
            if range is None:
                shutil.copyfileobj(source, outputfile)
            else:
                start, end = range
                length = end - start + 1
                source.seek(start)
                while length > 0:
                    buf = source.read(min(length, shutil.COPY_BUFSIZE))
                    if not buf:
                        raise EOFError('File shrank after size was checked')
                    length -= len(buf)
                    outputfile.write(buf)
        except (BrokenPipeError, ConnectionResetError):
            pass  # clients disconnecting is normal


HSTSHandler.extensions_map['.avif'] = 'image/avif'
HSTSHandler.extensions_map['.webp'] = 'image/webp'


def main():
    """Init"""
    try:
        # sys.tracebacklimit = 0  # 1-line errorlog in production
        os.chdir(MYSERV_WORKDIR)  # auto-change working directory
        SimpleHTTPRequestHandler.sys_version = ""  # empty version string
        SimpleHTTPRequestHandler.server_version = "nginx"  # pretend to be nginx
        my_server = ThreadingHTTPServer(('127.0.0.1', 2443), HSTSHandler)
        tlscontext = create_ctx()
        my_server.socket = tlscontext.wrap_socket(my_server.socket, do_handshake_on_connect=False, server_side=True, suppress_ragged_eofs=True)
        print('Starting server, use <Ctrl-C> to stop')
        my_server.serve_forever()
    except KeyboardInterrupt:
        print(' received, shutting down server')
        my_server.shutdown()


if __name__ == '__main__':
    main()
