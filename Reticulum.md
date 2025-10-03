See [here](https://reticulum.network/manual/understanding.html) for an overview of packets. Here, I want to roecord the basic structure of different real-world packets, keys, etc, in high-level code, so you more easily write your own parser. I will focus on LXMF, and format stuff that is common to popular clients (nomadnet, meshchat, sideband, etc.)

This library will do all this stuff for you, so don;t need to understand all this, to get it working.

## packet

The basic unit of Reticulum is packets. They look like this, in terms of bytes:

```
[HEADER 2 bytes] [ADDRESSES 16/32 bytes] [CONTEXT 1 byte] [DATA 0-465 bytes]
```

- The HEADER field is 2 bytes long.
  - Byte 1: `IFAC Flag`, `Header Type`, `Context Flag`, `Propagation Type`, `Destination Type` and `Packet Type`
  - Byte 2: Number of hops
- Interface Access Code field if the IFAC flag was set.
  - The length of the Interface Access Code can vary from 1 to 64 bytes according to physical interface capabilities and configuration.
- The `ADDRESSES` field contains either 1 or 2 addresses.
  - Each address is 16 bytes long.
  - The Header Type flag in the `HEADER` field determines whether the `ADDRESSES` field contains 1 or 2 addresses.
  - Addresses are SHA-256 hashes truncated to 16 bytes.
- The `CONTEXT` field is 1 byte.
  - It is used by Reticulum to determine packet context.
- The `DATA` field is between 0 and 465 bytes.
  - It contains the packets data payload.

So to get all your fields, it looks like this:

```js
packet = { flags: bytes[0], hops: bytes[1] }

packet.ifac = (packet.flags & 0b10000000) >> 7
packet.headerType = (packet.flags & 0b01000000) >> 6
packet.contextFlag = (packet.flags & 0b00100000) >> 5
packet.propogationType = (packet.flags & 0b00010000) >> 4
packet.destinationType = (packet.flags & 0b00001100) >> 2
packet.packetType = packet.flags & 0b00000011

// 1 or 2 addresses?
if (packet.headerType === 1) {
  packet.transportId = packet.raw.slice(2, 18)
  packet.destinationHash = packet.raw.slice(18, 34)
  packet.context = bytes[34]
  packet.data = packet.raw.slice(35)
} else {
  packet.destinationHash = packet.raw.slice(2, 18)
  packet.context = bytes[18]
  packet.data = packet.raw.slice(19)
}
```

`hops` is the maximum number of hops (over interfaces) this packet can travel. 0 means "stay on the interface it was sent on".

### flags

Now, you can look at the flags to determine various things:

```js
// packetType

PACKET_DATA = 0x0
PACKET_ANNOUNCE = 0x1
PACKET_LINKREQUEST = 0x2
PACKET_PROOF = 0x3

// desitnationType

DESTINATION_SINGLE = 0x0 // Single (encrypted)
DESTINATION_GROUP = 0x1 // Group (shared key)
DESTINATION_PLAIN = 0x2 // Plaintext
DESTINATION_LINK = 0x3 // Link (uses link_id in header)

// contextFlag

CONTEXT_NONE = 0x00 // Generic data packet
CONTEXT_RESOURCE = 0x01 // Packet is part of a resource
CONTEXT_RESOURCE_ADV = 0x02 // Packet is a resource advertisement
CONTEXT_RESOURCE_REQ = 0x03 // Packet is a resource part request
CONTEXT_RESOURCE_HMU = 0x04 // Packet is a resource hashmap update
CONTEXT_RESOURCE_PRF = 0x05 // Packet is a resource proof
CONTEXT_RESOURCE_ICL = 0x06 // Packet is a resource initiator cancel message
CONTEXT_RESOURCE_RCL = 0x07 // Packet is a resource receiver cancel message
CONTEXT_CACHE_REQUEST = 0x08 // Packet is a cache request
CONTEXT_REQUEST = 0x09 // Packet is a request
CONTEXT_RESPONSE = 0x0a // Packet is a response to a request
CONTEXT_PATH_RESPONSE = 0x0b // Packet is a response to a path request
CONTEXT_COMMAND = 0x0c // Packet is a command
CONTEXT_COMMAND_STATUS = 0x0d // Packet is a status of an executed command
CONTEXT_CHANNEL = 0x0e // Packet contains link channel data
CONTEXT_KEEPALIVE = 0xfa // Packet is a keepalive packet
CONTEXT_LINKIDENTIFY = 0xfb // Packet is a link peer identification proof
CONTEXT_LINKCLOSE = 0xfc // Packet is a link close message
CONTEXT_LINKPROOF = 0xfd // Packet is a link packet proof
CONTEXT_LRRTT = 0xfe // Packet is a link request round-trip time measurement
CONTEXT_LRPROOF = 0xff // Packet is a link request proof

// propagationType

PROPOGATION_BROADCAST = 0x00
PROPOGATION_TRANSPORT = 0x01
PROPOGATION_RELAY = 0x02
PROPOGATION_TUNNEL = 0x03
```

### ANNOUNCE

This is how a peer tells other peers about itself. It contains the public-keys for encryption & signing (2 seperate keys, called ratchet.)

```js
const out = { ...packet }
const keysize = 64
const ratchetsize = 32
const name_hash_len = 10
const sig_len = 64

out.pubKeyEncrypt = packet.data.slice(0, keysize / 2)
out.pubKeySignature = packet.data.slice(keysize / 2, keysize)

out.nameHash = packet.data.slice(keysize, keysize + name_hash_len)
out.randomHash = packet.data.slice(keysize + name_hash_len, keysize + name_hash_len + 10)

// does this packet have a ratchet pubkey?
if (packet.contextFlag === 1) {
  out.ratchet = packet.data.slice(keysize + name_hash_len + 10, keysize + name_hash_len + 10 + ratchetsize)
  out.signature = packet.data.slice(keysize + name_hash_len + 10 + ratchetsize, keysize + name_hash_len + 10 + ratchetsize + sig_len)
  if (packet.data.length > keysize + name_hash_len + 10 + sig_len + ratchetsize) {
    out.appData = packet.data.slice(keysize + name_hash_len + 10 + sig_len + ratchetsize)
  }
} else {
  out.signature = packet.data.slice(keysize + name_hash_len + 10, keysize + name_hash_len + 10 + sig_len)
  if (packet.data.length > keysize + name_hash_len + 10 + sig_len) {
    out.appData = packet.data.slice(keysize + name_hash_len + 10 + sig_len)
  }
}
```

On LXMF, `appData` is a [msgpack](https://msgpack.org/) array, and the first-field is a byte-array of the peer-name.

Here is how you verify a signature (from above):

```js
const signedData = new Uint8Array([...out.destinationHash, ...out.pubKeyEncrypt, ...out.pubKeySignature, ...out.nameHash, ...out.randomHash, ...(out.ratchet || []), ...(out.appData || [])])
out.verified = ed25519.verify(out.signature, signedData, out.pubKeySignature)
```

### DATA

If a message is small (less than 465 bytes) "opportunistic delivery" will be used, which means use the last ratchet that the peer ANNOUNCEd with. It means no LINK (key-exchange) is needed.

### LINKREQUEST

This indicates a "link" request, which is a key exchange between 2 peers. Messages sent in this link will sent with same keys (not ratchets, which are generally 1-time-only, but for established cconnection, or a transfer that spans over many packets.)

### PROOF

This is how your client tells the peer that it got the message. The destination-address is message-id, not the peer.

### Examples

Here is a concrete example:

```
ANNOUNCE (072ec44973a8dee8e28d230fb4af8fe4):  2100072ec44973a8dee8e28d230fb4af8fe400a2b9b02fb4749fcf8458762d1be0ae67ff1caa47fb0a52f4c2bd6dd07860a738da50a87f884e6e64aaa70b44d20868144e3e26ffa001c60a7c797dbae5078ece6ec60bc318e2c0f0d90873408275530068de1039e2bb21108b2cbc900b476290ab7867441446db366a70fb8ed1448ca0e889bd65bad6d8654e72661ddc089b06495ab91a57afc5700e095f021aa8cec04f22ba55438efc3ab1e2a91b8d17bd259313f175dff040827fdf1111c88bef501676380b92c40e416e6f6e796d6f75732050656572c0

ANNOUNCE (76a93cda889a8c0a88451e02d53fd8b9):  210076a93cda889a8c0a88451e02d53fd8b90071f199f04d3589ca083c66ff91baed628ee19517ef68eb209827df3a6785cf5b0af43fb0e168176370828fcdc199e5ae2b208b57cf65179ffa8f25733d9d40bc6ec60bc318e2c0f0d908149ad525040068de103b0df6d220011ce9da7559fbd620380501d9e19afce87a6d0c661412f3831cc915dbecabe89ef5a11a359d3757a85280c3ae68a8b6366ed4110be24a408dbe946b2815e0e89f8e49848978122b30e442af83b36cef11d3df69c34189156858560292c40e416e6f6e796d6f75732050656572c0

DATA (76a93cda889a8c0a88451e02d53fd8b9):  000076a93cda889a8c0a88451e02d53fd8b900f549cccf8d574cb520c8f12ea6ea67c4f4ce34f301de611cd942acbfb6933f3f7a025d5b6d6184d04dd0279b8037f1c9c1c1c25defbdd5e62aa8fb04502101014a501b9235e62f823bbdfd4d85e7656d765802f115a01b57b823ae02cc94899ae3a0f94bf7c32f1a73c027e5c95e0dd94c72c833ea75951af517da665eff26bca45e90e2eaa18775e65799ea0b3a977645107850dbfe62bb1f3228b50ac6e775006c4f18d6f3a1474233dc9b13cd95f6a6f581ad0b85de7196ea606d393d35f1

PROOF (2831d76f1a8035638505c132fe5818c1):  03002831d76f1a8035638505c132fe5818c100b90b83a04be319463f930b123b667eaaf64a85e827c34831a032cf72834a1dc58836e1fe4c49e30decab52747da2811db83a4b0b8464aa31e02f2eebbf1dae03

DATA (072ec44973a8dee8e28d230fb4af8fe4):  0000072ec44973a8dee8e28d230fb4af8fe400b2191b23b7506a3325fe288d75a7ab06700f92c710c16a7f55769afb014d753b8cf3187730116905843fb0de9dcec976b121a6425b995f80442819ebe883dab5aa72fb8a9d96849969b073b8e76e4463dc8c0eceba936665c4b62af1c31de32ba3433b6d5bf9ceaf4e08355126af0ef6dd111bdeeefa49434c69aba42160ec3e3698c2a88d96ef940b636dff89f2dbde337ae0fc7cd802de72793458dc3a1966fb0ed28e513dfc77138d53f87875a97a22e11e58191d5ae863de24ff68a3e961

PROOF (d7c0e833f0cbde9f9133cd9e7d508b1a):  0300d7c0e833f0cbde9f9133cd9e7d508b1a00cd00ce237471609d6ef64e427151fed46d9eb71fe6337f6fc530a9f3a55c730f1fd09f82f7d12d1caadbc185b7703f0d9f5db6c792c2dfcdf1eed3111088860c
```

- `072ec444` announces themselves, everyone else records their ratchet (pubkey), address, and maybe some info (like their peer-name)
- `76a93cda` announces themselves, everyone else records their ratchet (pubkey), address, and maybe some info (like their peer-name)
- `072ec444` sends a message to `76a93cda`. It's small, so they use ratchets and "opportunistic delivery", meaning they created a shared private key for `072ec444`+`76a93cda` using the pubkey `76a93cda` sent in their ANNOUNCE
- `76a93cda` gets the message, they also create a shared private key for `072ec444`+`76a93cda` using the pubkey `072ec444` sent in their ANNOUNCE
- Using that ratchet-key, `76a93cda` reads the messgae, gets the message-id, and sends a PROOF to tell `072ec444` (indirectly, so no one else knows) they got it
- `76a93cda` sends a message to `072ec444`. It's small, so they use ratchets and "opportunistic delivery", meaning they created a shared private key for `072ec444`+`76a93cda` using the pubkey `072ec444` sent in their ANNOUNCE
- `072ec444` gets the message, they also create a shared private key for `072ec444`+`76a93cda` using the pubkey `76a93cda` sent in their ANNOUNCE
- Using that ratchet-key, `072ec444` reads the messgae, gets the message-id, and sends a PROOF to tell `76a93cda` (indirectly, so no one else knows) they got it

Let's break down the first one, even further:

```
    HEADER(1)               ADDRESS(16)              CONTEXT(1)   DATA
b00100001 0x00 | 0x072ec44973a8dee8e28d230fb4af8fe4 |  0x00   |  ...
 || | | |    |
 || | | |    +-- Hops                = 0
 || | | +------- Packet Type         = ANNOUNCE
 || | +--------- Destination Type    = SINGLE
 || +----------- Propagation Type    = BROADCAST
 |+------------- Header Type         = 0 (one address field, not 2)
 +-------------- Access Codes (IFAC) = DISABLED
```

In ANNOUNCE packets, it's got this in DATA field:

```
If contextFlag is 1:
  RATCHET(32) | SIGNATURE(64) | APP_DATA
else:
  SIGNATURE(64) | APP_DATA
```

So here, that first packet, DATA looks like this:

```
    RATCHET(32)                 SIGNATURE(64)              APP_DATA
0xe2bb21108b2cbc900.... | bad6d8654e72661ddc089b0649.... | ...

```

With RATCHET, it's an ID (random number) you can create a shared private key, using the announce-packet's public key, your private key, that ID, and send DATA messages to it, using that.

Commonly, APP_DATA is a msgpack array, here it is:

```js
;[[65, 110, 111, 110, 121, 109, 111, 117, 115, 32, 80, 101, 101, 114], null]
```

The first element is UTF8 encoded bytes (not msgepack string): `Anonymous Peer`, which is the name. Other clients put additional stuff in here, like meshchat includes icons (emojis).
