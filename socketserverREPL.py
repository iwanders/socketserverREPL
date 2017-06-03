#!/usr/bin/env python

from __future__ import print_function

import code
import threading
import sys
import time
try:
    import __builtin__
    import SocketServer as ss
except ImportError:
    import builtins as __builtin__
    import socketserver as ss

# Create a function that is available from the shell to gracefully exit server
# after disconnect.
should_exit = False
def halt():
    global should_exit
    sys.displayhook("Shutting down after all connections close.")
    should_exit = True

# Update the displayhook such that it redirects data to the appropriate stream
# if the print is called from a stream.
thread_scope = threading.local()
def new_displayhook(data):
    if (data is None):
        return

    if hasattr(thread_scope, "displayhook"):
        thread_scope.displayhook(data)
    else:
        print(data)
sys.displayhook = new_displayhook

# https://docs.python.org/2/library/code.html
# https://github.com/python/cpython/blob/2.7/Lib/code.py

class InteractiveSocket(code.InteractiveConsole):
    def __init__(self, rfile, wfile, locals=None):
        code.InteractiveConsole.__init__(self, locals)
        self.rfile = rfile
        self.wfile = wfile


    def write(self, data):
        if not self.wfile.closed:
            self.wfile.write(data.encode('ascii'))
            self.wfile.flush()

    def raw_input(self, prompt=""):
        if (self.wfile.closed):
            raise EOFError("Socket closed")

        self.write(prompt);
        raw_value = self.rfile.readline()
        r = raw_value.rstrip()

        # self.wfile.write("\033[31m" + repr(raw_value) + "\033[0m\n" + "\n")
        try:
            r = r.decode('ascii')
        except:
            pass

        if (len(raw_value) == 0):
            raise EOFError("Empty line, ^D?")

        return r

class RequestPythonREPL(ss.StreamRequestHandler):
    def handle(self):
        repl_scope=dict(globals(), **locals())

        def display(f):
            f = str(f)
            try:
                f = bytes(f, 'ascii')
            except:
                pass

            self.wfile.write(f)
            self.wfile.write(b"\n")
            self.wfile.flush()

        thread_scope.displayhook = display
        thread_scope.rfile = self.rfile
        thread_scope.wfile = self.wfile

        self.console = InteractiveSocket(self.rfile, self.wfile, locals=repl_scope)
        try:
            self.console.interact()
        except SystemExit:
            print("SystemExit reached")
            self.finish()


class ThreadedTCPServer(ss.ThreadingMixIn, ss.TCPServer):
    pass

if __name__ == "__main__":
    server = ThreadedTCPServer(("192.168.0.86", 1337), RequestPythonREPL)
    server_thread = threading.Thread(target=server.serve_forever)
    # Exit the server thread when the main thread terminates
    server_thread.daemon = True
    server_thread.start()
    while not should_exit:
        time.sleep(1)
    print("Shutting down.")
    server.shutdown()
    server.server_close()