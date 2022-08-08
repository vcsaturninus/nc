# nc
Very basic netcat

## Purpose

`netcat` - or its successor - `ncat` are very common on linux
platforms. These are often modularized such that it's possible to
compile only a subet of the availble features. On resource-constrained
systems `nc` is yet another extremely minimal version of `netcat`
often seen. `nc` typically only takes a single option `-l` and two
positional parameters `address` and `port`. It will then act as either
sender or receiver depending on whether `-l` was specified.

Some platforms provide `nc` _without_ the `-l` option with the result
that `nc` can only be run in sender mode. This is virtually useless.

This repo implements the rudimentary `nc` so that it can be quickly
cross-compiled for platforms lacking other essential file-sharing
features such as `ssh`.


## Usage overview

