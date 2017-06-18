# socketserverREPL
This project exposes the interactive Python interpreter over a TCP socket. It
does so in a manner that allows multiple connections at the same time, each 
connection runs in a separate thread and has its own scope. It is a pure Python
implementation relying on the [code](module_code) and
[socketserver](module_socketserver) modules.
Tested on Python 2.7 and Python 3.4.

## What is the use case?
I created this to facilitate development for [Pythonista](pythonista), a Python
interpreter that runs on iOS. At first I had a script that allowed updating
other scripts, but I missed the functionality to quickly test something in an
interactive interpreter. Getting the interpreter with `code.interact()` from a
script in Pythonista works but that requires typing on the device itself,
obviously not the preffered solution.

This socketserverREPL exposes the interpreter on a TCP socket, this allows
connecting to it with netcat and thus typing into the interactive Python
interpreter of Pythonista through a normal keyboard. Additionally it allows
uploading scripts and executing them while observing the output on a normal
screen.

Although developed with this use-case in mind, it works for any scenario where
you have access to Python but can't use standard tools to access it. Be careful
to which ip address you bind the server to; expose the REPL only on trusted
networks.

## repl_tool.py
This is a simple helper script to facilitate file upload, download and
execution. It also provides a convenience wrapper around the TCP socket to
provide command history.

## License

MIT License, see [LICENSE](LICENSE).

Copyright (c) 2017 Ivor Wanders

[module_code]: https://docs.python.org/2/library/code.html
[module_socketserver]: https://docs.python.org/2/library/socketserver.html
[pythonista]: http://omz-software.com/pythonista/