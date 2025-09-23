# NomadNet JS

This is a simple Javascript library for interacting with [nomadnet](https://github.com/markqvist/NomadNet) that works on web or in node.

It can do basic [LXMF](https://github.com/markqvist/LXMF) over [Reticulum](https://github.com/markqvist/Reticulum).

The goal is to be able to inter-operate with [nomadnet](https://github.com/markqvist/NomadNet), [reticulum-meshchat](https://github.com/liamcottle/reticulum-meshchat), or [Sideband](https://github.com/markqvist/Sideband), in terms of messages (I will not implement mu display, or interface-transports, just basic communication.)

I am doing all my testing over a websocket, so it will work on web & native in a similar way, but this library is really about identity-management and LXMF packet-handling, and should work over nay transport.

## examples

I have some examples in [examples/](examples/)

If you want to test multiple clients on a network with the examples, you can do this:

```sh
nomadnet --config demo/a/nomad --rnsconfig demo/a/rns
nomadnet --config demo/b/nomad --rnsconfig demo/b/rns
```

These clients (and the examples) are configured to log & interact with a remote websocket (see [here](https://github.com/konsumer/signal-worker)), which you can host yourself, if you like.

> [!NOTE]
> The main thing is to copy [WebsocketClientInterface.py](demo/interfaces/WebsocketClientInterface.py) into your reticulum interfaces/ folder, and use that. This will allow nomadnet/etc to connect to a websocket.

Now, add this to your config:

```toml
[[Konsumer Websocket]]
type = WebsocketClientInterface
interface_enabled = True
target_url = "wss://signal.konsumer.workers.dev/ws/reticulum"
```

## license

MIT
