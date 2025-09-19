## Reticulum

This is the wire-format that is used for messages on the network:

- Header: 2 bytes.
- Addresses: 16 or 32 bytes.
- Context: 1 byte.
- Data Payload: 0–477 bytes of data, which is always encrypted for unicast communication. 

### Header (2 bytes):

- Byte 1: Packet type and flags (flags: BROADCAST, TRANSPORT, DATA, ANNOUNCE, LINK_REQUEST, PROOF, etc.)
- Byte 2: Additional flags (hop count for certain packet types)


### Context (1 byte)

The context byte indicates what type of data is in the payload. For LXMF messages, this would typically be set to indicate that the payload contains an LXMF message. Different applications can use different context values to distinguish their data types.


## LXMF

This runs on top of Reticulum.

- Destination
- Source
- Ed25519 Signature
- Payload
    - Timestamp
    - Content
    - Title
    - Fields

### And these rules:

1. A LXMF message is identified by its __message-id__, which is a SHA-256 hash of the __Destination__, __Source__ and __Payload__. The message-id is never included directly in the message, since it can always be inferred from the message itself.

   In some cases the actual message-id cannot be inferred, for example when a Propagation Node is storing an encrypted message for an offline user. In these cases a _transient-id_ is used to identify the message while in storage or transit.

2. __Destination__, __Source__, __Signature__ and __Payload__ parts are mandatory, as is the __Timestamp__ part of the payload.
    - The __Destination__ and __Source__ fields are 16-byte Reticulum destination hashes
    - The __Signature__ field is a 64-byte Ed25519 signature of the __Destination__, __Source__, __Payload__ and __message-id__
    - The __Payload__ part is a [msgpacked](https://msgpack.org) list containing four items:
        1. The __Timestamp__ is a double-precision floating point number representing the number of seconds since the UNIX epoch.
        2. The __Content__ is the optional content or body of the message
        3. The __Title__  is an optional title for the message
        4. The __Fields__ is an optional dictionary

3. The __Content__, __Title__ and __Fields__ parts must be included in the message structure, but can be left empty.

4. The __Fields__ part can be left empty, or contain a dictionary of any structure or depth.

## Wire Format

Assuming the default Reticulum configuration, the binary wire-format is as follows:

- 16 bytes destination hash
- 16 bytes source hash
- 64 bytes Ed25519 signature
- Remaining bytes of [msgpack](https://msgpack.org) payload data, in accordance with the structure defined above





