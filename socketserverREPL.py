#!/usr/bin/env python

# The MIT License (MIT)
#
# Copyright (c) 2017 Ivor Wanders
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import code
import threading
import sys
import time
import socket
import argparse
import os

# load following in python2 and python3 compatible way.
if sys.version_info.major == 2:
    import SocketServer as ss
else:
    import socketserver as ss

# Create a function that is available from the shell to gracefully exit server
# after disconnect.
should_exit = False

def halt():
    global should_exit
    print("Shutting down after all clients disconnect.")
    should_exit = True

thread_scope = threading.local()
original_stdout = sys.stdout

class ThreadAwareStdout(object):
    """
        This class acts as a file object and based on the thread it is used
        from it uses to the appropriate stream. If it is called from the main
        thread "wfile" will not be present and it will write to the original
        stdou, which is the stdout of the server process.
    """
    def write(self, data):
        if hasattr(thread_scope, "wfile"):
            thread_scope.wfile.write(data.encode('ascii'))
        else:
            original_stdout.write(data.encode('ascii'))

    def flush(self):
        if hasattr(thread_scope, "wfile"):
            thread_scope.wfile.flush()
        else:
            original_stdout.flush()

sys.stdout = ThreadAwareStdout()
sys.stderr = ThreadAwareStdout()

# Relevant links:
# https://docs.python.org/2/library/code.html
# https://github.com/python/cpython/blob/2.7/Lib/code.py


class InteractiveSocket(code.InteractiveConsole):
    def __init__(self, rfile, wfile, locals=None):
        """
            This class actually creates the interactive session and ties it
            to the socket by reading input from the socket and writing output.

            This class is always located in the thread that is created per
            connection.
        """
        code.InteractiveConsole.__init__(self, locals)
        self.rfile = rfile
        self.wfile = wfile

        print("Use Print() to print on the server thread, use halt() to close"
              " the server after the last session terminates.")

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
            # Python 2 / 3 difference.
            r = r.decode('ascii')
        except:
            pass

        # The default repl quits on control+d, control+d causes the line that
        # has been typed so far to be sent by netcat. That means that pressing
        # control+D without anything having been typed in results in a ''
        # to be read into raw_value.
        # But when '' is read we know control+d has been sent, we raise
        # EOFError to gracefully close the connection.
        if (len(raw_value) == 0):
            raise EOFError("Empty line, disconnect requested with control-D.")

        return r


class RequestPythonREPL(ss.StreamRequestHandler):
    """
        THis is the entry point for connections from the socketserver.
    """
    def handle(self):
        # Actually handle the request from socketserver, every connection is
        # handled in a different thread.

        # Create a new Print() function that outputs to the original stdout.
        def Print(f):
            f = str(f)
            try:
                f = bytes(f, 'ascii')
            except:
                pass
            original_stdout.write(f.decode('ascii'))
            original_stdout.write("\n")
            original_stdout.flush()

        # Add that function to the thread's scope.
        thread_scope.rfile = self.rfile
        thread_scope.wfile = self.wfile

        # Set up the environment for the repl, this makes halt() and Print()
        # available.
        repl_scope = dict(globals(), **locals())

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


class ThreadedTCPServer(ss.ThreadingMixIn, ss.TCPServer):
    # from https://stackoverflow.com/a/18858817
    # Ensures that the socket is available for rebind immediately.
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Expose a Python REPL loop"
                                     " over a tcp socket.")
    parser.add_argument('-i', '--hostname', default=None,
                        help="Ip to bind to defaults to 127.0.0.1, will use "
                             "environment value of REPL_HOST if set.")
    parser.add_argument('-p', '--port', default=None, type=int,
                        help="Port to bind to. Defaults"
                        " to 1337, will use environment value of REPL_PORT if"
                        " set.")
    parser.add_argument('-k', '--kill-active', default=False,
                        action="store_true", help="Kill active connections on"
                        " interrupt signal.")

    args = parser.parse_args()

    if ("REPL_HOST" in os.environ) and args.hostname is None:
        args.hostname = os.environ["REPL_HOST"]

    if args.hostname is None:  # still None, go for fallback.
        args.hostname = "127.0.0.1"

    if "REPL_PORT" in os.environ and args.port is None:
        args.port = int(os.environ["REPL_PORT"])

    if (args.port is None):  # Still None, go for fallback.
        args.port = 1337


    # Create the server object and a thread to serve.
    server = ThreadedTCPServer((args.hostname, args.port), RequestPythonREPL)

    # set whether sending ctrl+c to the server will close it even if there are active connections.
    server.daemon_threads = args.kill_active

    # start the server thread
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
    server.server_close()
    server.shutdown()
    server_thread.join()
    # This does not always correctly release the socket, hence SO_REUSEADDR.
