#!/usr/bin/env python

# The MIT License (MIT)
#
# Copyright (c) 2016 Ivor Wanders
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

import argparse
import sys
import socket
import time
import base64
import hashlib
import os

# Ensure we have raw input if running in python3
if sys.version_info.major == 3:
    raw_input = input


class socketREPL(object):
    def __init__(self, ip, port, echo=True):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((ip, port))
        self.echo = echo

    def write(self, z):
        self.sock.sendall(z.encode('ascii') + b"\n")

        if (self.echo):
            sys.stdout.write("\033[1m" + z + "\033[0m" + "\n")

    def read(self, print_function=None):
        try:
            b = b""
            while True:
                # Inefficient, but no one is transferring large amounts of data
                # with this system...
                d = self.sock.recv(1)

                if (len(d) == 0):
                    # no more data to be read, socket closed?
                    return b.decode('ascii')

                if d and print_function:
                    # call the print function if it is set for local echo.
                    print_function(d.decode('ascii'))

                b += d

                if (b.endswith(b">>> ")):
                    # We've detected a prompt, return
                    return b.decode('ascii')

                if (b.endswith(b"... ")):
                    # We've detected a prompt, return
                    return b.decode('ascii')

        except KeyboardInterrupt:
            pass

    def close(self):
        try:
            self.sock.shutdown(1)
            self.sock.close()
        except socket.error as e:
            sys.stderr.write("Closing connection failed: {}\n".format(str(e)))
            pass


def run_eval(args):
    statement = args.statement.replace("\\n", "\n")

    c = socketREPL(args.dest, args.port)
    c.read(print_function=lambda x: sys.stdout.write(x))

    for line in statement.split("\n"):
        c.write(line)
        c.read(print_function=lambda x: sys.stdout.write(x))

    c.close()


def run_exec(args):
    # Put all statements on one line, this is convenient as it requires
    # only one read statement afterwards.
    p = 'exec_name = "{}";'.format(args.filename)
    p += 'execfile(exec_name);'

    # check if we are verbose.
    if (args.verbose):
        echo_flag = True
        print_function = lambda x: sys.stdout.write(x)
    else:
        echo_flag = False
        print_function = lambda x: None

    c = socketREPL(args.dest, args.port, echo=echo_flag)
    c.read(print_function=print_function)
    c.write(p)
    c.read(print_function=print_function)
    c.close()


def run_upload(args):
    # Grab the file's data, do this first because if this fails we don't need
    # to open the connection.
    with open(args.source, 'r') as f:
        data = f.read()

    # Yay, data acquired, encode it such that it contains no quotes etc.
    datab64 = base64.b64encode(data)

    # craft the payload
    p = 'import base64;'
    if args.destination:
        destination = args.destination
        p += 'import os;'
        p += 'dir = os.path.dirname("{}"); '.format(destination)
        # Create the dirs if required, if statement on one line to avoid
        # multiple prompts to be read.
        p += "_ = os.makedirs(dir) if not os.path.isdir(dir) else True;"
    else:
        destination = args.source

    p += 'f = open("{}", "w");'.format(destination)
    p += 'fdata = base64.b64decode("{}");'.format(datab64)
    p += 'f.write(fdata);'
    p += ' f.close();'

    # check if we are verbose.
    if (args.verbose):
        echo_flag = True
        print_function = lambda x: sys.stdout.write(x)
    else:
        echo_flag = False
        print_function = lambda x: None

    # create the connection
    c = socketREPL(args.dest, args.port, echo=echo_flag)

    # Read the banner
    c.read(print_function=print_function)

    # Drop the payload.
    c.write(p)

    # Read the prompt after.
    c.read(print_function=print_function)

    if (args.check):
        # Calculate the hash of the file at the remote end.
        p = b"import hashlib;"
        p += "x = hashlib.md5(); x.update(fdata);print(x.hexdigest());"
        c.write(p)
        hash = c.read(print_function=print_function).split("\n")[0]

        # Calcualte the hash of the file as we have sent it.
        x = hashlib.md5()
        x.update(data)

        # Compare them.
        if (hash == x.hexdigest()):
            sys.stdout.write("md5 {} of received data"
                             " matches source data.\n".format(hash))
        else:
            sys.stderr.write("md5 {} of received data"
                             " does not match source data.\n".format(hash))

    c.close()


def run_download(args):
    # Payload to read data and print the base64 string.
    p = 'import base64;'
    p += 'f = open("{}", "r");'.format(args.source)
    p += 'data = f.read(); fdata = base64.b64encode(data);'
    p += ' f.close();'
    p += "print(fdata);"  # drop the data!

    # check if we are verbose.
    if (args.verbose):
        echo_flag = True
        print_function = lambda x: sys.stdout.write(x)
    else:
        echo_flag = False
        print_function = lambda x: None

    # Create connection.
    c = socketREPL(args.dest, args.port, echo=echo_flag)

    # read banner and prompt
    c.read(print_function=print_function)
    # drop the payload
    c.write(p)
    # Read the base64 string and split the prompt from it.
    blob = c.read(print_function=print_function).split("\n")[0]

    # decode the data
    data = base64.b64decode(blob)

    if (args.check):
        # calculate the md5 of the sent data
        p = b"import hashlib;"
        p += "x = hashlib.md5(); x.update(data);print(x.hexdigest());"
        c.write(p)
        hash = c.read(print_function=print_function).split("\n")[0]

        # calculate local md5 of the received data
        x = hashlib.md5()
        x.update(data)
        if (hash == x.hexdigest()):
            sys.stdout.write("md5 {} of received data"
                             " matches source data.\n".format(hash))
        else:
            sys.stderr.write("md5 {} of received data"
                             " does not match source data.\n".format(hash))

    c.close()

    # ensure destination folder exists, if no destination use basename to local
    # folder.
    if (args.destination):
        destination = args.destination
        dest_dir = os.path.dirname(destination)
        if (dest_dir) and (not os.path.isdir(dest_dir)):
            os.makedirs(dest_dir)
    else:
        destination = os.path.basename(args.source)

    # Finally, write the data to the destination file.
    with open(destination, "w") as f:
        f.write(data)


def run_repl(args):
    # print some info..
    sys.stdout.write("KeyboardInterrupt is treated locally, two consecutive"
                     " KeyboardInterrupt \ncloses connection from this side),"
                     " control+D sends exit() to remote.\n")
    # import convenience readline (history) and rlcompleter for tab completion
    # of python functions.
    import readline
    # import rlcompleter
    # readline.parse_and_bind("tab: complete")

    # create the connection.
    c = socketREPL(args.dest, args.port, echo=False)

    def read_split():
        z = c.read(print_function = lambda x: sys.stdout.write(x))
        if (z.endswith(">>> ") or z.endswith("... ")):
            # output is already echod as it comes in, but we have to remove
            # the prompt as that is handled by raw_input.
            sys.stdout.write(chr(8) * 4)
            return z[:-4], z[-4:]
        else:
            return z, ""

    interrupt_counter = 0
    repling = True

    # Read the prompt and banner
    output, prompt = read_split()
    while repling:
        try:  # outer loop for keyboard interrupt (control+C)
            try:  # try raw_input to catch control+D
                line = raw_input(prompt)
            except EOFError as e:
                # got control+D, close everything gracefully.
                repling = False
                line = "exit()"  # interpret as if exit() was typed.
                sys.stdout.write("exit()\n")  # ensure it shows in stdout.

            # Reset the consecutive control+C counter.
            interrupt_counter = 0

            # Finally, drop the typed instruction into the socket.
            c.write(line)
            # read any output, and the prompt.
            output, prompt = read_split()

        except KeyboardInterrupt as e:
            # increase consecutive control+C counter.
            interrupt_counter += 1
            sys.stdout.write("\n")
            if (interrupt_counter > 1):
                sys.stdout.write("Local KeyboardInterrupt,"
                                 " closing connection.\n")
                break
    c.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dest', default=None,
                        help="Hostname or ip of target running REPL. Defaults"
                        " to 127.0.0.1, will use environment value of "
                        "REPL_HOST if set.")
    parser.add_argument('-p', '--port', default=None, type=int,
                        help="Port of target turnning REPL. Defaults"
                        " to 1337, will use environment value of REPL_PORT if"
                        " set.")
    subparsers = parser.add_subparsers(dest="command")

    eval_description = ("This evaluates the one statement that is provided to"
                        " it. Any \\n occurances are replace by non escaped "
                        "newlines and the statement is executed line by line. "
                        "Output is read between each line. The statement may "
                        "span multiple lines, basically it's the same as "
                        "pasting this statement into a open REPL session.")
    eval_parser = subparsers.add_parser('evaluate',
                                        help="Evaluate a statement",
                                        description=eval_description)
    eval_parser.add_argument('statement', help="The string to evaluate, '\n'"
                             " is replaced by newline and the statement is "
                             "executed & read line by line")
    eval_parser.set_defaults(func=run_eval)

    upload_description = ("This allows uploading a file to the remote REPL "
                          " from the local computer. It overwrites the "
                          " destination without prompt.")
    upload_parser = subparsers.add_parser('upload', help="Upload a file",
                                          description=upload_description)
    upload_parser.add_argument('source')
    upload_parser.add_argument('-v', default=False, action="store_true",
                               dest="verbose", help="print all interaction")
    upload_parser.add_argument('--no-check', default=True,
                               action="store_false", dest="check",
                               help="do not perform md5 transfer check")
    upload_parser.add_argument('destination', type=str, default=None,
                               help="defaults to source path", nargs="?")
    upload_parser.set_defaults(func=run_upload)

    execute_description = ("This allows remote execution of a script.")
    execute_parser = subparsers.add_parser('execute', help="Execute a file",
                                           description=execute_description)
    execute_parser.add_argument('filename')
    execute_parser.add_argument('-q', default=True, action="store_false",
                                dest="verbose",
                                help="Inhibit printing all interaction")
    execute_parser.set_defaults(func=run_exec)

    download_description = ("This allows downloading a file from the remote "
                            " REPL to the local computer. It overwrites the "
                            " destination without prompt.")
    download_parser = subparsers.add_parser('download', help="Download a file",
                                            description=download_description)
    download_parser.add_argument('source')
    download_parser.add_argument('-v', default=False, action="store_true",
                                 dest="verbose", help="print all interaction")
    download_parser.add_argument('--no-check', default=True,
                                 action="store_false", dest="check",
                                 help="do not perform md5 transfer check")
    download_parser.add_argument('destination', type=str, default=None,
                                 help="defaults to source basename", nargs="?")
    download_parser.set_defaults(func=run_download)

    repl_description = ("This REPL command is slightly more convenient than "
                        "connecting to the socketserverREPL with netcat. "
                        " A command history is made available by using the"
                        " readline module.")
    repl_parser = subparsers.add_parser('repl', help="Drop into a repl",
                                        description=repl_description)
    repl_parser.set_defaults(func=run_repl)

    args = parser.parse_args()

    if ("REPL_HOST" in os.environ) and args.dest is None:
        args.dest = os.environ["REPL_HOST"]

    if args.dest is None:  # still None, go for fallback.
        args.dest = "127.0.0.1"

    if "REPL_PORT" in os.environ and args.port is None:
        args.port = int(os.environ["REPL_PORT"])

    if (args.port is None):  # Still None, go for fallback.
        args.port = 1337

    # no command
    if (args.command is None):
        parser.print_help()
        parser.exit()
        sys.exit(1)

    args.func(args)
    sys.exit()
