# NomadNet JS

This is a simple Javascript library for interacting with [nomadnet](https://github.com/markqvist/NomadNet) that works on web or in node.

It can do basic [LXMF](https://github.com/markqvist/LXMF) over [Reticulum](https://github.com/markqvist/Reticulum).

Not complete, but it can currently push announcement messages (as a peer or node) over web-sockets. See [examples](examples/).

### Goals

- [x] Generate an identity. This might need a little work to make sure everything is in order
- [x] Send announcements that show up in nomadnet client
- [ ] Parse announcements (and pull out peer-pubkeys)
- [ ] Receive messages, detect if it's for me
- [ ] Send message using announcement peer-pubkeys
- [ ] Serve files over node address
- [ ] Decrypt messages for me
