# nc

Basic implementation of netcat that allows creation of a client-server
pipe using internet or Unix domain sockets. Internet domain sockets
support TLS encryption.

## Building

Run `make` to compile the program. By default, TLS support is _not_
added in. To compile with TLS support (currently expects `Openssl3`),
run `make USE_TLS=y`.

## Usage

### CLI options

Once compiled, call `nc` with the `-h` or `--help` flag to get it to
show its cli. TLS support adds a few options that will not otherwise
appear:

 * with TLS support:
```sh
└─$ ./out/nc -h
 ./out/nc
SYNOPSYS:
  IPv4/IPv6:           [-hdel][-f FILE][[-c CERT][-k KEY][--noverify]|[-p PSK][--psk-from-file]] <ADDRESS> <PORT>
  Unix Domain Sockets: -u [-hdl][-f FILE] <UDS PATH>

OPTIONS:
 -h|--help             show help usage and exit
 -d|--debug            enable debug prints and verbosity
 -f|--file FILE        read contents from file instead of stdin (client) or write contents to file instead of stdout (server)
 -l|--listen           run in listening/server/receiver mode.
 -u|--unix             use Unix Domain Sockets instead of Internet (Ipv4/Ipv6) sockets
 -e|--encrypt          TLS-encrypt communication using the openssl library
 -c|--cert CERT_PATH   use specified TRUSTED certificate for TLS authentication.
 -k|--key KEY_PATH     indicate private key associated with the certificate specified
 -p|--psk PSK          use specified PSK for TLS authentication
    --psk-from-file    the PSK argument to -p is not the psk itself but a file containing the psk
    --noverify         skip verification of the certificate presented by the server; client need not present a certificate
```

 * without TLS support:
```sh
└─$ ./out/nc -h
 ./out/nc
SYNOPSYS:
  IPv4/IPv6:           [-hdl][-f FILE] <ADDRESS> <PORT>
  Unix Domain Sockets: -u [-hdl][-f FILE] <UDS PATH>

OPTIONS:
 -h|--help             show help usage and exit
 -d|--debug            enable debug prints and verbosity
 -f|--file FILE        read contents from file instead of stdin (client) or write contents to file instead of stdout (server)
 -l|--listen           run in listening/server/receiver mode.
 -u|--unix             use Unix Domain Sockets instead of Internet (Ipv4/Ipv6) sockets
```

## Basic Concepts

### Client-server / sender-receiver mode

The program can be run either in server/receiver/listener mode (all
meaning the same thing) if the `-l` or `--listen` flag is specified,
or in client/sender mode otherwise.

If in server mode, the program will read from the socket whatever is
sent by the client and print it out to `stdout`. A file to write to
can be specified instead via the `-f` or `--file` option.

If in client mode, the program will read from `stdin` and write to the
socket, sending to the server whatever has been read from `stdin`. A
file to read from can instead be specified via the `-f` or `--file`
option. This will sent the contents of the specied file to the server.

`nc` is **silent** by default -- nothing gets printed to `stdout` or
`stderr` unless there is an error. This is necessary since otherwise
verbose prints would be mixed up with the actual data if the data is
printed to one of the standard streams. This is obviously problematic
if e.g. a tarball is piped over the network. However, diagnostic
messages might be useful, particularly if the data is instead _written
to a file_ using the `-f` option. To enable debug/verbose prints, the
`-d` or `--debug` flag can be used.

### Internet Domain or Unix Domain

The client and server can communicate either via Internet (Ipv4 or
Ipv6) Domain sockets or over a Unix Domain socket. Both sender and
receiver must be consistent i.e. use the same socket family.

-----------------------------------------------------------------------

## Unix Domain Sockets

When using `unix domain socket` the server and client both reside on
the same host in the same ipc namespace (that is, not containerized
and isolated as regards ipc namespacing). Only one positional argument
is expected to end the command line call: the path to unix domain
socket.

If called in server mode, the path is implicitly created when the
program starts and removed if it already exists (and also removed when
the program shuts down after the pipe transfer is complete).
If called in client mode, the path refers to a socket the server
is listening on, so it must therefore already exist.

TLS encryption, needless to say, does **not** work with Unix Domain
Sockets.

### Examples

 * send 'some random string' from client (read from stdin)
   to server (printed to stdout)
```sh
# server
nc -lu "/tmp/nctest.sock"

# client
echo "some random string" | nc -u "/tmp/nctest.sock"
```

 * send `test.tgz` from client to server
```sh
# server
nc -lu -f received.tgz /tmp/nctest.sock

# client
nc -u -f test.tgz "/tmp/nctest.sock"
```

## Internet Domain Sockets

By default (`-u` is not specified), netcat will try to use internet
sockets. The options must be followed by two positional arguments - an
IP (v4 or v6) address and a port. See the `synopsys` section in the
help output.

Netcat attempts to figure out automatically whether ipv4 or ipv6 is to
be used. This is inferred from the arguments passed by the user,
specifically whether `<IP>` is an `ipv4` address (i.e. _dotted decimal
notation_) or an `ipv6` address (i.e. ipv6 _hex-string notation_).

The user can therefore supply either e.g. `127.0.0.1` or `::1` as the
`<IP>` positional argument to netcat.

### Examples

 * send the contents of mynotes.txt to the server (printed to stdout),
   listening on local host, port 4444
```sh
# server
nc -l 127.0.0.1 4444

# client
nc -f mynotes.txt 127.0.0.1 4444
```

 * pipe some random text into the client to be sent to the server
   (written to logs.txt), over Ipv6
```sh
# server
nc -l -f logs.txt ::1 4444

#client
echo "nothing of significance" | nc ::1 4444
```

## TLS/SSL Support

The client sends the data to the server in plaintext, completely
unencrypted. `TLS` encryption can optionally be used instead.

_As explained above, this is not built into the application by default.
To compile `nc` with `TLS` support, build with `make USE_TLS=y`._

The `-e` or `--encrypt` flag must be passed to enable `TLS` encryption.
The command line needs to then be further complemented with other suitable
options dependening on the mode of authentication: `PSK` or public
certificate.

#### PSK authentication

PSK or `pre-shared key` authentication, as the name implies, entails
the client and server both using the a key that is shared in advance.
The key is verified/validated simply by the fact that it is what the
peer expects (if indeed it is). Both client and server use the same
exact `PSK`.

To use `PSK`, the `-p` or `--psk` flag must be specified. The argument is
either the psk key to use or, if `--psk-from-file` is passed, the name
of a file to read the psk _from_. The length of the PSK must be a
multiple of 2 and is expected to be a hexadecimal string.

PSK is inherently less secure than certificate-based authentication,
but it can be _much_ more convenient (read _easy_/inexpensive), as seen next.

#### Certificate-based Authentication

If the `-c` or `--cert` flag is passed instead, the specified
certificate will be used for authentication with the peer. _Both_
client and server authenticate each other in `nc` when TLS is used
and therefore each must specify a certificate. For simple setups the
certificates can be oneand the same -- or they may be different, for
more security.

This is more secure but can be much lots less straightforward than
PSK. Specifically, `self-signed` certificates are considered insecure
and are not trusted. This is not to do with `nc` but with `openssl`
and security practices.

For the certificate presented by the peer to be found 'valid' and
trustworthy in light of the verification process the `CA` that signed
the certificate must be a trusted `CA`. In practical terms, this means
that the `trust anchor` i.e. the certificate authority that issued the
certificate is in the trust store of the sytem. Note this does _not_ mean
the `CA` is one of the standard authorities issuing such certificates
(at a cost) but that it is known and trusted by the system. The user
can create their _own_ certificate authority, create a self-signed
certificate for it, place it in the system trust store, then use it to
sign their own end-entity certificates. How this is done is beyond the
scope of this `README`.

Of course, certificates of standard well-known CAs come preinstalled
on most systems, so the user in that case need not do anything.

#### Skip certificate verification

Finally the insecure method: if certificate authentication just can't
seem to be set up, passing the `--noverify` flag will make it so
certificate verification is skipped. What this means exactly is:
 * the certificate presented by the server is verified but if
   verification fails the TLS handshake still proceeds
 * the server does NOT expect the client to authenticate itself with a
   certificate so the client never presents one.

Note the following points:
 * a certificate and key must still be passed at the command line for both
   client and server
 * the certificate and key must still be valid format-wise. I.e. the
   certificate must still be a valid, parsable `PEM` certificate, for
   example. It's just that if the verification fails e.g. because it
   is not signed by a trusted authority, this will not terminate the
   handshake.

### nc TLS examples

 * send data from client to string with certificate authentication
   _disabled_, over ipv6, in debug mode
```sh
# server
└─$ nc -del --cert ~/tls_certs/test_srv.crt -k ~/tls_certs/test_srv.key --noverify ::1 4444
 ~ Setting up TLS encryption
 ~ using certificate-based authentication
 ~ certificate verification will be skipped (insecure!)
 ~ Looking to accept() incoming TLS connection request
 ~ Transferring data over TLS
some random string

# client
└─$ echo "some random string" | ./out/nc -de -c ~/tls_certs/test_client.crt -k ~/tls_certs/test_client.key --noverify ::1 4444
 ~ Setting up TLS encryption
 ~ using certificate-based authentication
 ~ certificate verification will be skipped (insecure!)
 ~ Looking to connect(): initiating connection request with TLS server
 ~ Transferring data over TLS
```

 * send contents of secret.txt over Ipv4 TLS, with certificate verification _enabled_
```sh
# server
└─$ nc -el --cert ~/tls_certs/test_srv.crt -k ~/tls_certs/test_srv.key --noverify 127.0.0.1 4444

# client
└─$ nc -e -c ~/tls_certs/test_client.crt -k ~/tls_certs/test_client.key -f secret.txt 127.0.0.1 4444
```

 * send contents of secret.txt over IPv4 TLS, using command-line specified PSK key, in debug mode
```sh
# server
└─$ nc -del -p 123456 127.0.0.1 4444
 ~ Setting up TLS encryption
 ~ using PSK authentication
 ~ Looking to accept() incoming TLS connection request
 ~ running psk_server_cb()
 ~ PSK identity received from the client with length 12: 'static_ident'
 ~ PSK client identity successfully validated.
 ~ Returning PSK length=3
 ~ Transferring data over TLS

# client
└─$ nc -de -p 123456 -f secret.txt 127.0.0.1 4444
 ~ Setting up TLS encryption
 ~ using PSK authentication
 ~ Looking to connect(): initiating connection request with TLS server
 ~ running psk_client_cb()
 ~ no PSK identity hint provided by the server (none expected)
 ~ successfully set PSK identity: 'static_ident' of length 12
 ~ Returning PSK length=3
 ~ Transferring data over TLS
```

 * send contents of secret.key over IPv4 TLS, using PSK key read from file
```sh
# generate longer, more secure PSK key (512 hex digits = 256 bytes)
openssl rand -out psk.txt -hex 512

# server
nc -el -p psk.txt --psk-from-file 127.0.0.1 4444

# client
nc -e -p psk.txt --psk-from-file -f secret.txt 127.0.0.1 4444
```

## TODOs
 - make project compilable with different openssl versions; use
   `OPENSSL_VERSION_NUMBER` to distinguish between openssl versions
 - set reuseaddr sock option to allow immediate binding

