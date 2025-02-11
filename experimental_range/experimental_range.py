#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""HTTPS range request server with custom indexer"""

import os
import ssl
import urllib.parse
import html
import sys
import io
from http import HTTPStatus
from ranged_server import ThreadingHTTPServer  # from http.server import ThreadingHTTPServer
from ranged_server import SimpleHTTPRequestHandler  # from http.server import SimpleHTTPRequestHandler

MYSERV_WORKDIR = "/media/kingdian/server_priv"
MYSERV_CLIENTCRT = "/home/ran/keys/client.pem"
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
    sslcontext.verify_mode = ssl.CERT_REQUIRED
    sslcontext.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305")
    # sslcontext.set_ecdh_curve("secp384r1")#works well with everything
    # sslcontext.set_ecdh_curve("secp521r1")#works well on firefox and wget but not aria2
    sslcontext.load_verify_locations(MYSERV_CLIENTCRT)
    sslcontext.verify_flags &= ~ssl.VERIFY_X509_STRICT
    sslcontext.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    sslcontext.load_cert_chain(MYSERV_FULLCHAIN, MYSERV_PRIVKEY)
    # diagnostic data 2186428625 2 557056 for Python-3.13.2
    # print(sslcontext.options, sslcontext.verify_mode, sslcontext.verify_flags)
    return sslcontext


class HSTSHandler(SimpleHTTPRequestHandler):
    """Serve request types"""
    def send_head(self):
        """Common code for HEAD command"""
        path = self.translate_path(self.path)
        f = None
        self._range = self.parse_range()
        if os.path.isdir(path):
            parts = urllib.parse.urlsplit(self.path)
            if not parts.path.endswith('/'):
                self.send_response(HTTPStatus.MOVED_PERMANENTLY)
                new_parts = (parts[0], parts[1], parts[2] + '/',
                             parts[3], parts[4])
                new_url = urllib.parse.urlunsplit(new_parts)
                self.send_header("Location", new_url)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None
            for index in self.index_pages:
                index = os.path.join(path, index)
                if os.path.isfile(index):
                    path = index
                    break
            else:
                return CustomIndexer.list_directory(self, path)
        ctype = self.guess_type(path)
        if path.endswith("/"):
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None
        try:
            f = open(path, 'rb')
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return None
        try:
            fs = os.fstat(f.fileno())
            if ("If-Modified-Since" in self.headers
                    and "If-None-Match" not in self.headers):
                try:
                    ims = email.utils.parsedate_to_datetime(
                        self.headers["If-Modified-Since"])
                except (TypeError, IndexError, OverflowError, ValueError):
                    pass
                else:
                    if ims.tzinfo is None:
                        ims = ims.replace(tzinfo=datetime.timezone.utc)
                    if ims.tzinfo is datetime.timezone.utc:
                        last_modif = datetime.datetime.fromtimestamp(
                            fs.st_mtime, datetime.timezone.utc)
                        last_modif = last_modif.replace(microsecond=0)

                        if last_modif <= ims:
                            self.send_response(HTTPStatus.NOT_MODIFIED)
                            self.end_headers()
                            f.close()
                            return None
            if self._range:
                start, end = self._range
                if start is None:
                    assert end is not None
                    start = max(0, fs.st_size - end)
                    end = fs.st_size - 1
                elif end is None or end >= fs.st_size:
                    end = fs.st_size - 1

                if start == 0 and end >= fs.st_size - 1:
                    self._range = None
                elif start >= fs.st_size:
                    f.close()
                    headers = [('Content-Range', f'bytes */{fs.st_size}')]
                    self.send_error(HTTPStatus.REQUESTED_RANGE_NOT_SATISFIABLE,
                                    extra_headers=headers)
                    return None
            if self._range:
                self.send_response(HTTPStatus.PARTIAL_CONTENT)
                self.send_header("Content-Range",
                    f"bytes {start}-{end}/{fs.st_size}")
                self.send_header("Content-Length", str(end - start + 1))
                self._range = (start, end)
            else:
                self.send_response(HTTPStatus.OK)
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Content-Length", str(fs.st_size))
            self.send_header("Content-type", ctype)
            self.send_header("Last-Modified",
                self.date_time_string(fs.st_mtime))
            self.end_headers()
            return f
        except:
            f.close()
            raise

    def end_headers(self):
        """Send state of the art headers"""
        self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        # self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("Content-Security-Policy", "default-src 'none'; img-src 'self'; script-src 'self'; font-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Robots-Tag", "none")
        self.send_header("Permissions-Policy", "camera=(), microphone=()")
        self.send_header("Cross-Origin-Embedder-Policy", "unsafe-none")
        self.send_header("Cross-Origin-Opener-Policy", "unsafe-none")
        self.send_header("Cross-Origin-Resource-Policy", "cross-origin")
        self.send_header("Referrer-Policy", "no-referrer")
        SimpleHTTPRequestHandler.end_headers(self)


HSTSHandler.extensions_map['.avif'] = 'image/avif'
HSTSHandler.extensions_map['.webp'] = 'image/webp'


class CustomIndexer(SimpleHTTPRequestHandler):
    """Overwrite indexer"""
    def list_directory(self, path):
        """Create custom escaped index"""
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
                r.append('<a href="%s">%s</a><br>'
                        % (customname, customname))
        r.append('</ul>\n<hr>\n</body>\n</html>\n')
        encoded = '\n'.join(r).encode(enc, 'surrogateescape')
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", "text/html; charset=%s" % enc)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        return f


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
