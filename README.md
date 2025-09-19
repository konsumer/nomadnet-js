# NomadNet JS

This is a simple Javascript library for interacting with [nomadnet](https://github.com/markqvist/NomadNet) that works on web or in node.

It can do basic [LXMF](https://github.com/markqvist/LXMF) over [Reticulum](https://github.com/markqvist/Reticulum).

The goal is to be able to interop with [nomadnet](https://github.com/markqvist/NomadNet), [reticulum-meshchat](https://github.com/liamcottle/reticulum-meshchat), in terms of transport (I will not implement mu display, or transports, just communication.)

I have some examples in [exmaples/](examples/)

If you want to test multiple clients on a network with the examples, you can do this:

```sh
nomadnet --config test/a/nomad --rnsconfig test/a/rns
nomadnet --config test/b/nomad --rnsconfig test/b/rns
```

These clients (and the examples) are configured to log & interact with a remote websocket (see [here](https://github.com/konsumer/signal-worker)), which you can host yourself, if you like.


## previous work

It's based on [rns.js](https://github.com/liamcottle/rns.js/), but everything has been ported to APIs that work better on web & other JS runtimes (not just node.)

## license

MIT