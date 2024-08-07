# go-exploit: External C2 Experiments

Public C2 servers and examples for the [go-exploit](https://github.com/vulncheck/go-exploit) framework. These repositories hold various examples of how to use `go-exploit` in non-trivial and programmatic ways.

If you are here looking for how to develop an external C2 channel for communicating with your exploits, start by looking at the following components:

- [example](./example/README.md) - A very trivial minimal implementation of the external C2 component that gives an idea of what the bare minimum set up will be.
- [ssh](./ssh/README.md) - A full server and payload client for reverse shell controlled by the server.

Each of these C2 components will additionally need an accompanying payload. Each public external C2 should have a baseline payload that is an example of the basic use case and should at least be functional (for example `./ssh/payload/reverse_shell` is a functional client ssh reverse shell payload). Do not assume that any evasion techniques or any advanced EDR analysis is done with these payloads, they are *baseline* only unless stated otherwise.

> [!WARNING]  
> The C2 components in this repository may not have the same level of support or testing as the core modules. The repo says "experimental" for a reason.

## Experiment List

| Name        | Description  | Link |
| ----------- | ------------ | ---- |
| `SSHServer` | An SSH server runs from the exploitation hosts and handles incoming SSH client connections. Includes a payload reverse shell client | [ssh](./ssh/README.md) |
