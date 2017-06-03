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
    sys.displayhook("Shutting down after all clients disconnect.")
    should_exit = True

# Update the displayhook such that it redirects data to the appropriate stream
# if the errors and such are printed by code.interact. This does not capture
# print() itself.
thread_scope = threading.local()
def new_displayhook(data):
    if (data is None):
        return

    if hasattr(thread_scope, "displayhook"):
        thread_scope.displayhook(data)
    else:
        print(data)
sys.displayhook = new_displayhook

# Relevant links:
# https://docs.python.org/2/library/code.html
# https://github.com/python/cpython/blob/2.7/Lib/code.py
class InteractiveSocket(code.InteractiveConsole):
    def __init__(self, rfile, wfile, locals=None):
        code.InteractiveConsole.__init__(self, locals)
        self.rfile = rfile
        self.wfile = wfile

        # This is called before the banner, we can use it to print this note:
        thread_scope.displayhook("Use Print() to ensure printing to stream.")
        # print() always outputs to the stdout of the interpreter.


    def write(self, data):
        # Write data to the stream.
        if not self.wfile.closed:
            self.wfile.write(data.encode('ascii'))
            self.wfile.flush()

    def raw_input(self, prompt=""):
        # Try to read data from the stream.
        if (self.wfile.closed):
            raise EOFError("Socket closed.")

        # print the prompt.
        self.write(prompt)

        # Process the input.
        raw_value = self.rfile.readline()
        r = raw_value.rstrip()

        try:
            r = r.decode('ascii')
        except:
            pass

        # The default repl quits on control+d, control+d causes the line that
        # has been typed so far to be sent by netcat. That means that pressing
        # control+D without anything having been typed in results in a ''
        # to be read into raw_value (even though it's not a line, not sure why)
        # but when '' is read we know control+d has been sent, we raise
        # EOFError to gracefully close the connection.
        if (len(raw_value) == 0):
            raise EOFError("Empty line, disconnect requested with ^D.")

        return r

# The entry point for connections.
class RequestPythonREPL(ss.StreamRequestHandler):
    def handle(self):
        # Actually handle the request from socketserver, every connection is
        # handled in a different thread.

        # Create a new Print() function that outputs to the stream.
        def Print(f):
            f = str(f)
            try:
                f = bytes(f, 'ascii')
            except:
                pass

            self.wfile.write(f)
            self.wfile.write(b"\n")
            self.wfile.flush()

        # Add that function to the thread's scope.
        thread_scope.displayhook = Print
        thread_scope.rfile = self.rfile
        thread_scope.wfile = self.wfile

        # Set up the environment for the repl, this makes halt() and Print()
        # available.
        repl_scope=dict(globals(), **locals())

        # Create the console object and pass the stream's rfile and wfile.
        self.console = InteractiveSocket(self.rfile, self.wfile,
                                         locals=repl_scope)

        # All errors except SystemExit are caught inside interact(), only
        # sys.exit() is escalated, in this situation we want to close the
        # connection, not kill the server ungracefully. We have halt()
        # to do that gracefully.
        try:
            self.console.interact()
        except SystemExit:
            Print("SystemExit reached, closing the connection.")
            self.finish()

# TCPServer with new thread for each connection:
class ThreadedTCPServer(ss.ThreadingMixIn, ss.TCPServer):
    pass


if __name__ == "__main__":
    # Create the server object and a thread to serve.
    server = ThreadedTCPServer(("192.168.0.86", 1337), RequestPythonREPL)
    server_thread = threading.Thread(target=server.serve_forever)

    # Exit the server thread when the main thread terminates
    server_thread.daemon = True

    # Start the server thread, which serves the RequestPythonREPL.
    server_thread.start()

    # Ensure main thread does not quit unless we want it to.
    while not should_exit:
        time.sleep(1)

    # If we reach this point we are really shutting down the server.
    print("Shutting down.")
    server.shutdown()
    server.server_close()