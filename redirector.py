#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
from socketserver import ThreadingMixIn
from http.server import SimpleHTTPRequestHandler, HTTPServer

MYSERV_ACMEWEBDIR = "/home/ran/.acmeweb"
allowed_hosts = ['example.com', 'www.example.com', 'ran.example.com', 'chen.example.com']

def bot_redirector(received_host):
    if received_host in allowed_hosts: 
        return True, received_host
    else:
        return False, ''

class RedirectHandler(SimpleHTTPRequestHandler):
    def do_HEAD(self):
        if self.path.startswith("/.well-known"):#only serve acme challenges
            SimpleHTTPRequestHandler.do_HEAD(self)
        else:
            my_host = "localhost"
            my_path = "/"
            if 'Host' in self.headers:
                my_host = self.headers.get('Host').split(':')[0]
                my_path = self.path
            not_a_bot, received_host = bot_redirector(my_host)
            if not_a_bot == True:
                self.send_response(301)#redirect all other requests
                self.send_header("Location", "https://" + received_host + my_path)
                self.send_header("Content-Length", "0")
                SimpleHTTPRequestHandler.end_headers(self)
            if not_a_bot == False:
                self.send_response(400)#disconnect on requests without hostname
                self.send_header('Connection', 'close')
                self.send_header("Content-Length", "0")
                SimpleHTTPRequestHandler.end_headers(self)

    def do_GET(self):
        if self.path.startswith("/.well-known"):#only serve acme challenges
            SimpleHTTPRequestHandler.do_GET(self)
        else:
            my_host = "localhost"
            my_path = "/"
            if 'Host' in self.headers:
                my_host = self.headers.get('Host').split(':')[0]
                my_path = self.path
            not_a_bot, received_host = bot_redirector(my_host)
            if not_a_bot == True:
                self.send_response(301)#redirect all other requests
                self.send_header("Location", "https://" + received_host + my_path)
                self.send_header("Content-Length", "0")
                SimpleHTTPRequestHandler.end_headers(self)
            if not_a_bot == False:
                self.send_response(400)#disconnect on requests without hostname
                self.send_header('Connection', 'close')
                self.send_header("Content-Length", "0")
                SimpleHTTPRequestHandler.end_headers(self)

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

def main():
    try:
        os.chdir(MYSERV_ACMEWEBDIR)#auto-change working directory
        SimpleHTTPRequestHandler.server_version = "nginx"#pretend to be nginx
        SimpleHTTPRequestHandler.sys_version = ""#empty version string
        server = ThreadedHTTPServer(('0.0.0.0', 80), RedirectHandler)
        print("Starting server, use <Ctrl-C> to stop")
        server.serve_forever()
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, TimeoutError):
        pass
    except KeyboardInterrupt:
        print(" received, shutting down server")
        server.shutdown()

if __name__ == '__main__':
    main()
