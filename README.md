# nc

A rudimentary implementation of netcat that allows piping between
internet or Unix domain sockets.

## Usage

Netcat can be used
 * in client (sender) or server (receiver/listener) mode.
   The `-l` flag can be passed to run `netcat` in the latter mode.

 * between Internet (Ipv4 or Ipv6) sockets or Unix domain sockets.
   Both sender and receiver must be consistent i.e. use the same
   socket family.

### Internet Sockets

By default (`-u` is not specified), netcat will try to use internet
sockets. The command line is expected to look like this:
```sh
# sender
nc [-f FILE] <IP> <PORT>

# receiver
nc -l [-f FILE] <IP> <PORT>
```

The client, by default, tries to read from standard input. If a file
is otherwise specified using the `-f` flag, it will read from the specified
file. The contents read are written to the socket.
```sh
	echo "some random text" | nc 127.0.0.1 4444
	nc -f mysrcfile.txt 127.0.0.1 4444
```

The server, by default, reads from the socket and dumps the contents
to `stdout`. If a file is otherwise specified using the `-f` flag, it
will write the output to the specified file instead.
```
	nc -l 127.0.0.1 4444
	nc -l -f output.txt 127.0.0.1 4444
```

#### Ipv6

Netcat attempts to figure out automatically whether ipv4 or ipv6 is to
be used. This is inferred from the arguments passed by the user,
specifically whether `<IP>` is an `ipv4` address (i.e. _dotted decimal
notation_) or an `ipv6` address (i.e. ipv6 _hex-string notation_).

The user can therefore supply either e.g. `127.0.0.1` or `::1` as the
`<IP>` positional argument to netcat.

### Unix Domain Sockets

To make `netcat` use `Unix` domain sockets instead of sockets in the
`internet` domain, pass the `-u` flag. This also changes the command
line structure. While when using internet sockets 2 positional
parameters are expected - ip address and port -, only one - a file
system path to the unix domain socket - is expected when using unix
domain socket. Consequently, the cli looks like this:
```sh
# sender
nc -u [-f FILE] <PATH>

# receiver
nc -u -l [-f FILE] <PATH>
```
for example
```
echo "test 1 2 3" | nc -u "/tmp/nctest.sock"
```
