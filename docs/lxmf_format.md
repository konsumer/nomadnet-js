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

1. A LXMF message is identified by its **message-id**, which is a SHA-256 hash of the **Destination**, **Source** and **Payload**. The message-id is never included directly in the message, since it can always be inferred from the message itself.

   In some cases the actual message-id cannot be inferred, for example when a Propagation Node is storing an encrypted message for an offline user. In these cases a _transient-id_ is used to identify the message while in storage or transit.

2. **Destination**, **Source**, **Signature** and **Payload** parts are mandatory, as is the **Timestamp** part of the payload.

   - The **Destination** and **Source** fields are 16-byte Reticulum destination hashes
   - The **Signature** field is a 64-byte Ed25519 signature of the **Destination**, **Source**, **Payload** and **message-id**
   - The **Payload** part is a [msgpacked](https://msgpack.org) list containing four items:
     1. The **Timestamp** is a double-precision floating point number representing the number of seconds since the UNIX epoch.
     2. The **Content** is the optional content or body of the message
     3. The **Title** is an optional title for the message
     4. The **Fields** is an optional dictionary

3. The **Content**, **Title** and **Fields** parts must be included in the message structure, but can be left empty.

4. The **Fields** part can be left empty, or contain a dictionary of any structure or depth.

## Encryption

The encryption applied to LXMF messages depends on the Reticulum destination type used for transport.

#### For Reticulum "Links" (default)

This is the most common and secure method for LXMF messages, offering end-to-end encryption with Perfect Forward Secrecy.

- **Ephemeral keys:** When a link (an encrypted channel) is established between two endpoints, it is secured with ephemeral (short-lived) keys.
- **Key exchange:** These temporary keys are derived using an Elliptic Curve Diffie-Hellman (ECDH) key exchange on Curve25519. This process ensures that the keys are not reusable and that past communications cannot be decrypted even if a long-term key is compromised.
- **Symmetric encryption:** The actual data is then encrypted using AES-256 in CBC mode. For authentication, a SHA-256-based Hash-based Message Authentication Code (HMAC) is used.

#### For single Reticulum packets

For opportunistic delivery, an LXMF message can be sent in a single Reticulum packet.

- **Ephemeral keys:** In this case, a new ephemeral AES-256 key is derived for each individual packet.
- **Key exchange:** Similar to links, the key is derived using an ECDH key exchange on Curve25519.
- **Sender anonymity:** This method offers initiator anonymity, meaning it is very difficult to determine the sender's origin.

#### For Reticulum "Group" destinations

To send messages to a group of participants, a symmetric key is used.

- **Shared key:** All members of the group share a symmetric AES-256 key for encryption.
- **No forward secrecy:** Because the same key is used for all communications, this method does not offer forward secrecy. If the shared key is compromised, all past and future group messages can be decrypted.

### Digital signatures for authentication

In addition to encryption, Reticulum uses digital signatures for message authentication.

- **Ed25519:** Messages are signed using Ed25519 elliptic-curve signatures, ensuring that the data and exposed metadata are authentic.
- **Receipts:** The system can also provide unforgeable delivery confirmations, where the recipient signs a hash of the received packet to prove it was received.

### Traffic-hiding features

Reticulum is designed to reveal as little information as possible to external observers.

- **Minimal headers:** Only minimal metadata, such as the destination address and hop count, is exposed in unrouted packets.
- **No source addresses:** Reticulum does not include source addresses in packets, making it difficult to trace the origin of a message.
- **Transport node privacy:** Transport nodes, which route messages through the network, only know the next-best hop for a packet. They do not know the complete path, and the payload is always encrypted, so they cannot read the contents.
