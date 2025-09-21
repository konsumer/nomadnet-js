## Reticulum Wire Format

A Reticulum packet is composed of the following fields:

```
[HEADER 2 bytes] [ADDRESSES 16/32 bytes] [CONTEXT 1 byte] [DATA 0-465 bytes]
```

- The HEADER field is 2 bytes long.

  - Byte 1: `[IFAC Flag], [Header Type], [Propagation Type], [Destination Type] and [Packet Type]`
  - Byte 2: Number of hops

- Interface Access Code field if the IFAC flag was set.

  - The length of the Interface Access Code can vary from
    1 to 64 bytes according to physical interface
    capabilities and configuration.

- The ADDRESSES field contains either 1 or 2 addresses.

  - Each address is 16 bytes long.
  - The Header Type flag in the HEADER field determines
    whether the ADDRESSES field contains 1 or 2 addresses.
  - Addresses are SHA-256 hashes truncated to 16 bytes.

- The CONTEXT field is 1 byte.

  - It is used by Reticulum to determine packet context.

- The DATA field is between 0 and 465 bytes.
  - It contains the packets data payload.

## IFAC Flag

open 0 Packet for publically accessible interface
authenticated 1 Interface authentication is included in packet

## Header Types

type 1 0 Two byte header, one 16 byte address field
type 2 1 Two byte header, two 16 byte address fields

## Propagation Types

broadcast 00
transport 01
reserved 10
reserved 11

## Destination Types

single 00
group 01
plain 10
link 11

## Packet Types

data 00
announce 01
link request 10
proof 11

### Packet Example

```
   HEADER FIELD           DESTINATION FIELDS            CONTEXT FIELD  DATA FIELD
 _______|_______   ________________|________________   ________|______   __|_
|               | |                                 | |               | |    |
01010000 00000100 [HASH1, 16 bytes] [HASH2, 16 bytes] [CONTEXT, 1 byte] [DATA]
|| | | |    |
|| | | |    +-- Hops             = 4
|| | | +------- Packet Type      = DATA
|| | +--------- Destination Type = SINGLE
|| +----------- Propagation Type = TRANSPORT
|+------------- Header Type      = HEADER_2 (two byte header, two address fields)
+-------------- Access Codes     = DISABLED
```

### Packet Example

```

   HEADER FIELD   DESTINATION FIELD   CONTEXT FIELD  DATA FIELD
 _______|_______   _______|_______   ________|______   __|_
|               | |               | |               | |    |
00000000 00000111 [HASH1, 16 bytes] [CONTEXT, 1 byte] [DATA]
|| | | |    |
|| | | |    +-- Hops             = 7
|| | | +------- Packet Type      = DATA
|| | +--------- Destination Type = SINGLE
|| +----------- Propagation Type = BROADCAST
|+------------- Header Type      = HEADER_1 (two byte header, one address field)
+-------------- Access Codes     = DISABLED
```

### Packet Example

```

   HEADER FIELD     IFAC FIELD    DESTINATION FIELD   CONTEXT FIELD  DATA FIELD
 _______|_______   ______|______   _______|_______   ________|______   __|_
|               | |             | |               | |               | |    |
10000000 00000111 [IFAC, N bytes] [HASH1, 16 bytes] [CONTEXT, 1 byte] [DATA]
|| | | |    |
|| | | |    +-- Hops             = 7
|| | | +------- Packet Type      = DATA
|| | +--------- Destination Type = SINGLE
|| +----------- Propagation Type = BROADCAST
|+------------- Header Type      = HEADER_1 (two byte header, one address field)
+-------------- Access Codes     = ENABLED
```

### Size examples of different packet types

The following table lists example sizes of various
packet types. The size listed are the complete on-
wire size counting all fields including headers,
but excluding any interface access codes.

- Path Request : 51 bytes
- Announce : 167 bytes
- Link Request : 83 bytes
- Link Proof : 115 bytes
- Link RTT packet : 99 bytes
- Link keepalive : 20 bytes
