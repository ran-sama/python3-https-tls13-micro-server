#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Upgrade unsafe HTTP to HTTPS with HTTP 301 reply"""

import os
import sys
from http.server import ThreadingHTTPServer
from http.server import SimpleHTTPRequestHandler

MYSERV_ACMEWEBDIR = "/home/ran/.acmeweb"  # must exist to run the script


class RedirectHandler(SimpleHTTPRequestHandler):
    """Handler for request types"""
    def do_HEAD(self):
        """Serve a HEAD request"""
        if self.path.startswith("/.well-known"):  # only serve acme challenges
            SimpleHTTPRequestHandler.do_HEAD(self)
        else:
            my_host = "localhost"
            my_path = "/"
            if 'Host' in self.headers:
                my_host = self.headers.get('Host').split(':')[0]
                my_path = self.path
            self.send_response(301)  # redirect all other requests
            self.send_header("Location", "https://" + my_host + my_path)
            self.send_header("Content-Length", "0")
            SimpleHTTPRequestHandler.end_headers(self)

    def do_GET(self):
        """Serve a GET request"""
        if self.path.startswith("/.well-known"):  # only serve acme challenges
            SimpleHTTPRequestHandler.do_GET(self)
        else:
            my_host = "localhost"
            my_path = "/"
            if 'Host' in self.headers:
                my_host = self.headers.get('Host').split(':')[0]
                my_path = self.path
            self.send_response(301)  # redirect all other requests
            self.send_header("Location", "https://" + my_host + my_path)
            self.send_header("Content-Length", "0")
            SimpleHTTPRequestHandler.end_headers(self)


def main():
    """Start server"""
    try:
        sys.tracebacklimit = 0  # 1-line errorlog in production
        os.chdir(MYSERV_ACMEWEBDIR)  # auto-change working directory
        SimpleHTTPRequestHandler.server_version = "nginx"  # pretend to be nginx
        SimpleHTTPRequestHandler.sys_version = ""  # empty version string
        server = ThreadingHTTPServer(('0.0.0.0', 80), RedirectHandler)
        print("Starting server, use <Ctrl-C> to stop")
        server.serve_forever()
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, TimeoutError) as e:
        print("caught: ", e)
        # pass
    except KeyboardInterrupt:
        print(" received, shutting down server")
        server.shutdown()


if __name__ == '__main__':
    main()
