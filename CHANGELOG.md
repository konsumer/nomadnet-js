# Changelog

All notable changes to this project will be documented in this file.

## [Unrealized] - 2024-01-XX

### Fixed

- **Fixed "Invalid Signature" error with official Nomadnet client**
  - Root cause: Double PKCS7 padding in AES-CBC encryption
  - We were manually adding PKCS7 padding, but `@noble/ciphers` CBC mode also adds its own padding automatically
  - This resulted in encrypted data with two layers of padding
  - When Nomadnet decrypted messages, it only removed one layer, leaving padding bytes in the LXMF message
  - Signatures failed validation because they were calculated over data that included padding bytes
  - Solution: Removed manual `pkcs7_pad`/`pkcs7_unpad` calls and let `@noble/ciphers` handle padding automatically

- **Fixed msgpack encoding compatibility with Python**
  - Configured msgpackr with `{ useRecords: false, variableMapSize: true, mapsAsObjects: true }`
  - This ensures empty objects are encoded as fixmap (`80`) instead of map16 (`de0000`)
  - Matches Python msgpack library encoding for better interoperability

- **Fixed timestamp handling in lxmf_build**
  - Null timestamps now properly default to `Date.now() / 1000`
  - JavaScript default parameters don't work with explicit `null`, added explicit check

- **Fixed get_message_id for packets with header_type=1**
  - Packets with transport_id (header_type=1) have different structure
  - Now correctly skips 18 bytes (header + hops + 16-byte transport_id) instead of 2 bytes
  - Ensures correct packet hash calculation for all packet types

### Changed

- Replaced async Web Crypto API with synchronous `@noble/ciphers` for AES-CBC
- All crypto operations are now synchronous (removed async/await throughout)
- Simplified LXMF message handling - removed unnecessary Map/Object conversions
- Reduced debug logging in echobot example

### Dependencies

- Added `@noble/ciphers` for synchronous AES-CBC encryption
