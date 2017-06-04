#!/usr/bin/env python

import argparse
import sys
import socket
import time
import base64


class socketREPL(object):
    def __init__(self, ip, port, echo=True):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((ip, port))
        self.echo = echo

    def write(self, z):
        self.sock.sendall(z.encode('ascii') + b"\n")

        if (self.echo):
            sys.stdout.write("\033[1m" + z + "\033[0m\n" + "\n")
 
    def read(self, print_function=None):
        try:
            b = b""
            while True:
                # extremely innefficient, but who cares...
                d = self.sock.recv(1)

                if (len(d) == 0):
                    return b

                if print_function:
                    print_function(d)
                b += d
                if (b.endswith(b">>> ")):
                    return b.decode('ascii')
        except KeyboardInterrupt:
            pass
        

    def close(self):
        self.sock.shutdown(1)
        self.sock.close()
        


def run_eval(args):
    c = socketREPL(args.dest, args.port)
    c.read(print_function=lambda x: sys.stdout.write(x))
    c.write(args.statement)
    c.read(print_function=lambda x: sys.stdout.write(x))
    c.close()

def run_exec(args):
    p = 'exec_name = "{}";'.format(args.filename)
    if (args.fix_print):
        p += 'import tempfile;'
        p += 'f = open("{}", "r");'.format(args.filename)
        p += 'd = f.read(); f.close();'
        p += 'd = d.replace("print(", "Print(");' # replace print( with Print(
        p += 'f = tempfile.NamedTemporaryFile("w"); f.write(d);f.flush();'
        p += "exec_name = f.name;"
    p += 'execfile(exec_name, {"Print": sys.displayhook});'
    if (args.fix_print):
        p += 'f.close();'
    c = socketREPL(args.dest, args.port)
    c.read(print_function=lambda x: sys.stdout.write(x))
    c.write(p)
    c.read(print_function=lambda x: sys.stdout.write(x))
    c.close()

def run_upload(args):
    # first grab file:
    with open(args.source, 'r') as f:
        data = f.read()

    # yay, data acquired, encode it such that it contains no quotes etc.
    datab64 = base64.b64encode(data)


    p = 'import base64;'
    # craft the payload
    if args.destination:
        destination = args.destination
        p += 'import os;'
        p += 'dir = os.path.dirname("{}"); '.format(destination)
        p += "make_dir_without_newlines = os.makedirs(dir) if not os.path.isdir(dir) else True;"
    else:
        destination = args.source
    p += 'f = open("{}", "w");'.format(destination)
    p += 'f.write(base64.b64decode("{}"));'.format(datab64)
    p += ' f.close();'

    c = socketREPL(args.dest, args.port)
    c.read(print_function=lambda x: sys.stdout.write(x))
    c.write(p)
    c.read(print_function=lambda x: sys.stdout.write(x))

    c.close()

    

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dest', default="192.168.0.86")
    parser.add_argument('-p', '--port', default=1337, type=int)
    subparsers = parser.add_subparsers(dest="command")

    eval_parser = subparsers.add_parser('eval')
    eval_parser.add_argument('statement')
    eval_parser.set_defaults(func=run_eval)

    upload_parser = subparsers.add_parser('upload')
    upload_parser.add_argument('source')
    upload_parser.add_argument('destination', type=str, default=None, help="Defaults to source path.", nargs="?")
    upload_parser.set_defaults(func=run_upload)

    execute_file_parser = subparsers.add_parser('exec')
    execute_file_parser.add_argument('filename')
    execute_file_parser.add_argument('--no-fix-print', default=True, dest="fix_print", action="store_false")
    execute_file_parser.set_defaults(func=run_exec)


        
    args = parser.parse_args()

    # no command
    if (args.command is None):
        parser.print_help()
        parser.exit()
        sys.exit(1)


    args.func(args)
    sys.exit()
