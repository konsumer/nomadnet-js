/**
 * Lightweight Reticulum library for JavaScript
 */

import { cbc } from '@noble/ciphers/aes.js'
import { randomBytes } from '@noble/ciphers/utils.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { hmac } from '@noble/hashes/hmac.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { x25519 } from '@noble/curves/ed25519.js'
import { pack, unpack } from 'msgpackr'

// Packet types
export const PACKET_DATA = 0x00
export const PACKET_ANNOUNCE = 0x01
export const PACKET_LINKREQUEST = 0x02
export const PACKET_PROOF = 0x03

// Context types
export const CONTEXT_NONE = 0x00
export const CONTEXT_RESOURCE = 0x01
export const CONTEXT_RESOURCE_ADV = 0x02
export const CONTEXT_RESOURCE_REQ = 0x03
export const CONTEXT_RESOURCE_HMU = 0x04
export const CONTEXT_RESOURCE_PRF = 0x05
export const CONTEXT_RESOURCE_ICL = 0x06
export const CONTEXT_RESOURCE_RCL = 0x07
export const CONTEXT_CACHE_REQUEST = 0x08
export const CONTEXT_REQUEST = 0x09
export const CONTEXT_RESPONSE = 0x0a
export const CONTEXT_PATH_RESPONSE = 0x0b
export const CONTEXT_COMMAND = 0x0c
export const CONTEXT_COMMAND_STATUS = 0x0d
export const CONTEXT_CHANNEL = 0x0e
export const CONTEXT_KEEPALIVE = 0xfa
export const CONTEXT_LINKIDENTIFY = 0xfb
export const CONTEXT_LINKCLOSE = 0xfc
export const CONTEXT_LINKPROOF = 0xfd
export const CONTEXT_LRRTT = 0xfe
export const CONTEXT_LRPROOF = 0xff

// Destination types
export const DEST_SINGLE = 0x00
export const DEST_GROUP = 0x01
export const DEST_PLAIN = 0x02
export const DEST_LINK = 0x03

// Transport types
export const TRANSPORT_BROADCAST = 0
export const TRANSPORT_TRANSPORT = 1

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function concatArrays(arrays) {
  const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0)
  const result = new Uint8Array(totalLength)
  let offset = 0
  for (const arr of arrays) {
    result.set(arr, offset)
    offset += arr.length
  }
  return result
}

function arraysEqual(a, b) {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

// Crypto helper functions
function _hmacSha256(key, data) {
  return hmac(sha256, key, data)
}

function _sha256(data) {
  return sha256(data)
}

function _hkdf(length, deriveFrom, salt, context = null) {
  const hashLen = 32

  if (!length || length < 1) {
    throw new Error('Invalid output key length')
  }

  if (!deriveFrom || deriveFrom.length === 0) {
    throw new Error('Cannot derive key from empty input material')
  }

  if (!salt || salt.length === 0) {
    salt = new Uint8Array(hashLen)
  }

  if (context === null) {
    context = new Uint8Array(0)
  }

  return hkdf(sha256, deriveFrom, salt, context, length)
}

// PKCS7 padding - only needed for encryption (Noble auto-unpads on decrypt)
function _pkcs7Pad(data, bs = 16) {
  const l = data.length
  const n = bs - (l % bs)
  const padding = new Uint8Array(n).fill(n)
  const result = new Uint8Array(l + n)
  result.set(data)
  result.set(padding, l)
  return result
}

function _aesCbcEncrypt(key, iv, plaintext) {
  const cipher = cbc(key, iv)
  return cipher.encrypt(plaintext)
}

function _aesCbcDecrypt(key, iv, ciphertext) {
  const cipher = cbc(key, iv)
  // Noble's CBC automatically removes PKCS7 padding on decrypt
  return cipher.decrypt(ciphertext)
}

function _ed25519Sign(data, privateKey) {
  return ed25519.sign(data, privateKey)
}

function _ed25519Validate(publicKey, signature, message) {
  try {
    return ed25519.verify(signature, message, publicKey)
  } catch (e) {
    return false
  }
}

function _x25519Exchange(privateKey, publicKey) {
  return x25519.getSharedSecret(privateKey, publicKey)
}

// Identity functions
export function identityCreate() {
  const encryptPrivate = randomBytes(32)
  const encryptPublic = x25519.getPublicKey(encryptPrivate)
  const signPrivate = randomBytes(32)
  const signPublic = ed25519.getPublicKey(signPrivate)
  return {
    public: { encrypt: encryptPublic, sign: signPublic },
    private: { encrypt: encryptPrivate, sign: signPrivate }
  }
}

export function getIdentityFromBytes(privateIdentityBytes) {
  if (privateIdentityBytes.length !== 64) {
    throw new Error('Private identity must be 64 bytes')
  }

  const encryptPrivate = privateIdentityBytes.slice(0, 32)
  const signPrivate = privateIdentityBytes.slice(32, 64)

  const encryptPublic = x25519.getPublicKey(encryptPrivate)
  const signPublic = ed25519.getPublicKey(signPrivate)

  return {
    public: {
      encrypt: encryptPublic,
      sign: signPublic
    },
    private: {
      encrypt: encryptPrivate,
      sign: signPrivate
    }
  }
}

// Ratchet functions
export function ratchetCreateNew() {
  return randomBytes(32)
}

export function ratchetGetPublic(privateRatchet) {
  return x25519.getPublicKey(privateRatchet)
}

// Destination hash
export function getDestinationHash(identity, appName, ...aspects) {
  const identityData = new Uint8Array(64)
  identityData.set(identity.public.encrypt)
  identityData.set(identity.public.sign, 32)
  const identityHash = _sha256(identityData).slice(0, 16)

  let fullName = appName
  for (const aspect of aspects) {
    fullName += '.' + aspect
  }

  const nameHash = _sha256(new TextEncoder().encode(fullName)).slice(0, 10)

  const addrHashMaterial = new Uint8Array(26)
  addrHashMaterial.set(nameHash)
  addrHashMaterial.set(identityHash, 10)

  return _sha256(addrHashMaterial).slice(0, 16)
}

// Message functions
export function getMessageId(packet) {
  const headerType = (packet.raw[0] >> 6) & 0b11
  const hashablePart = new Uint8Array(packet.raw.length - (headerType === 1 ? 18 : 2) + 1)
  hashablePart[0] = packet.raw[0] & 0b00001111

  if (headerType === 1) {
    hashablePart.set(packet.raw.slice(18), 1)
  } else {
    hashablePart.set(packet.raw.slice(2), 1)
  }

  return _sha256(hashablePart)
}

// ============================================================================
// PACKET ENCODING/DECODING
// ============================================================================

export function encodePacket(packet) {
  let headerByte = 0

  // Build header byte
  if (packet.ifacFlag) headerByte |= 0b10000000
  if (packet.headerType) headerByte |= 0b01000000
  if (packet.contextFlag) headerByte |= 0b00100000
  if (packet.propagationType) headerByte |= 0b00010000
  headerByte |= (packet.destinationType || 0) & 0b00001100
  headerByte |= (packet.packetType || 0) & 0b00000011

  const parts = [new Uint8Array([headerByte]), new Uint8Array([packet.hops || 0])]

  // Add addresses based on header type
  if (packet.headerType) {
    // Double header: transport_id (source) first, then destination
    parts.push(packet.sourceHash)
    parts.push(packet.destinationHash)
  } else {
    // Single header: just destination
    parts.push(packet.destinationHash)
  }

  // Always add context byte
  parts.push(new Uint8Array([packet.context || 0]))

  // Add data
  if (packet.data) parts.push(packet.data)

  // Concatenate all parts
  const totalLength = parts.reduce((sum, p) => sum + p.length, 0)
  const result = new Uint8Array(totalLength)
  let offset = 0
  for (const part of parts) {
    result.set(part, offset)
    offset += part.length
  }

  return result
}

export function decodePacket(packetBytes) {
  const packet = {
    raw: packetBytes,
    ifacFlag: Boolean(packetBytes[0] & 0b10000000),
    headerType: Boolean(packetBytes[0] & 0b01000000),
    contextFlag: Boolean(packetBytes[0] & 0b00100000),
    propagationType: Boolean(packetBytes[0] & 0b00010000),
    destinationType: (packetBytes[0] & 0b00001100) >> 2,
    packetType: packetBytes[0] & 0b00000011,
    hops: packetBytes[1]
  }

  let offset = 2

  if (packet.headerType) {
    // Double header: first is source, second is destination
    packet.sourceHash = packetBytes.slice(offset, offset + 16)
    offset += 16
    packet.destinationHash = packetBytes.slice(offset, offset + 16)
    offset += 16
  } else {
    // Single header: just destination
    packet.destinationHash = packetBytes.slice(offset, offset + 16)
    offset += 16
    packet.sourceHash = null
  }

  // Always read context byte
  packet.context = packetBytes[offset]
  offset += 1

  packet.data = packetBytes.slice(offset)

  return packet
}

// ============================================================================
// ANNOUNCE
// ============================================================================

export function buildAnnounce(identity, destination, fullName = 'lxmf.delivery', ratchetPub = null, appData = null) {
  const nameHash = _sha256(new TextEncoder().encode(fullName)).slice(0, 10)
  const randomHash = randomBytes(10)

  // Determine effective ratchet and context
  let ratchetForSigning, contextVal, hasExplicitRatchet
  if (ratchetPub === null || arraysEqual(ratchetPub, identity.public.encrypt)) {
    // No explicit ratchet - use empty bytes for signing
    ratchetForSigning = new Uint8Array(0)
    contextVal = 0
    hasExplicitRatchet = false
  } else {
    // Explicit ratchet - include in signing
    ratchetForSigning = ratchetPub
    contextVal = 1
    hasExplicitRatchet = true
  }

  // Prepare app data
  let appDataBytes = new Uint8Array(0)
  if (appData) {
    appDataBytes = typeof appData === 'string' ? new TextEncoder().encode(appData) : appData
  }

  // Build signed data
  const publicKeys = concatArrays([identity.public.encrypt, identity.public.sign])
  const signedData = concatArrays([
    destination,
    publicKeys,
    nameHash,
    randomHash,
    ratchetForSigning, // Empty or explicit ratchet
    appDataBytes
  ])

  const signature = _ed25519Sign(signedData, identity.private.sign)

  // Build payload (data part of packet)
  let payload
  if (hasExplicitRatchet) {
    // Include explicit ratchet in payload
    payload = concatArrays([publicKeys, nameHash, randomHash, ratchetPub, signature, appDataBytes])
  } else {
    // No explicit ratchet in payload
    payload = concatArrays([publicKeys, nameHash, randomHash, signature, appDataBytes])
  }

  return encodePacket({
    destinationHash: destination,
    packetType: PACKET_ANNOUNCE,
    destinationType: 0,
    hops: 0,
    context: contextVal,
    contextFlag: hasExplicitRatchet, // Only set flag if explicit ratchet
    data: payload
  })
}

export function announceParse(packet) {
  const data = packet.data
  const announce = { valid: false }

  // Extract keys (64 bytes total)
  const publicKey = data.slice(0, 64)
  announce.keyPubEncrypt = data.slice(0, 32)
  announce.keyPubSignature = data.slice(32, 64)

  // Extract name and random hashes
  announce.nameHash = data.slice(64, 74)
  announce.randomHash = data.slice(74, 84)

  let offset = 84
  let ratchetForSigning

  // Check if explicit ratchet is present (based on contextFlag)
  if (packet.contextFlag) {
    // Explicit ratchet present
    announce.ratchetPub = data.slice(offset, offset + 32)
    ratchetForSigning = announce.ratchetPub
    offset += 32
  } else {
    // No explicit ratchet - it's implicit (empty for signing)
    announce.ratchetPub = announce.keyPubEncrypt
    ratchetForSigning = new Uint8Array(0)
  }

  // Extract signature
  announce.signature = data.slice(offset, offset + 64)
  offset += 64

  // Extract app data
  announce.appData = data.length > offset ? data.slice(offset) : new Uint8Array(0)

  // Build signed data for verification
  const signedData = concatArrays([packet.destinationHash, publicKey, announce.nameHash, announce.randomHash, ratchetForSigning, announce.appData])

  // Verify signature
  announce.valid = _ed25519Validate(announce.keyPubSignature, announce.signature, signedData)
  announce.destinationHash = packet.destinationHash

  return announce
}

// ============================================================================
// PROOF
// ============================================================================

export function buildProof(identity, packet, messageId = null) {
  if (!messageId) {
    messageId = getMessageId(packet)
  }

  // Sign the full message ID
  const signature = _ed25519Sign(messageId, identity.private.sign)

  // Proof packet data: version byte + signature
  const proofData = concatArrays([new Uint8Array([0x00]), signature])

  return encodePacket({
    destinationHash: messageId.slice(0, 16),
    packetType: PACKET_PROOF,
    destinationType: 0,
    hops: 0,
    context: 0,
    contextFlag: false,
    data: proofData
  })
}

export function proofValidate(packet, identity, fullPacketHash) {
  if (packet.data.length < 65) return false

  // Skip version byte, signature is bytes 1-65
  const signature = packet.data.slice(1, 65)
  return _ed25519Validate(identity.public.sign, signature, fullPacketHash)
}

// ============================================================================
// DATA (Encryption/Decryption)
// ============================================================================

export function buildData(identity, recipientAnnounce, plaintext) {
  // Calculate recipient identity hash for HKDF
  const recipientIdentityData = concatArrays([recipientAnnounce.keyPubEncrypt, recipientAnnounce.keyPubSignature])
  const recipientIdentityHash = _sha256(recipientIdentityData).slice(0, 16)

  // Generate ephemeral keypair
  const ephemeralKey = randomBytes(32)
  const ephemeralPub = x25519.getPublicKey(ephemeralKey)

  // Perform X25519 key exchange with recipient's ratchet
  const sharedKey = _x25519Exchange(ephemeralKey, recipientAnnounce.ratchetPub)

  // Derive encryption and signing keys
  const derivedKey = _hkdf(64, sharedKey, recipientIdentityHash, new Uint8Array(0))
  const signingKey = derivedKey.slice(0, 32)
  const encryptionKey = derivedKey.slice(32, 64)

  // Encrypt the plaintext
  const paddedPlaintext = _pkcs7Pad(plaintext)
  const iv = randomBytes(16)
  const ciphertext = _aesCbcEncrypt(encryptionKey, iv, paddedPlaintext)

  // Create HMAC over IV + ciphertext
  const signedData = concatArrays([iv, ciphertext])
  const hmac = _hmacSha256(signingKey, signedData)

  // Build token: ephemeralPub + IV + ciphertext + HMAC
  const token = concatArrays([ephemeralPub, iv, ciphertext, hmac])

  return encodePacket({
    destinationHash: recipientAnnounce.destinationHash,
    packetType: PACKET_DATA,
    destinationType: 0,
    hops: 0,
    context: 0,
    contextFlag: false,
    data: token
  })
}

function tryDecrypt(ephemeralPub, ciphertext, privateKey, identityHash) {
  try {
    console.log('  trying with key:', Buffer.from(privateKey).toString('hex').slice(0, 16))

    const sharedKey = _x25519Exchange(privateKey, ephemeralPub)
    console.log('  shared:', Buffer.from(sharedKey).toString('hex').slice(0, 16))

    const derivedKey = _hkdf(64, sharedKey, identityHash, new Uint8Array(0))
    const signingKey = derivedKey.slice(0, 32)
    const encryptionKey = derivedKey.slice(32, 64)
    console.log('  encKey:', Buffer.from(encryptionKey).toString('hex').slice(0, 16))

    if (ciphertext.length < 48) {
      console.log('  too short')
      return null
    }

    const receivedHmac = ciphertext.slice(-32)
    const signedData = ciphertext.slice(0, -32)
    const expectedHmac = _hmacSha256(signingKey, signedData)

    console.log('  hmac match:', arraysEqual(receivedHmac, expectedHmac))
    if (!arraysEqual(receivedHmac, expectedHmac)) return null

    const iv = signedData.slice(0, 16)
    const actualCiphertext = signedData.slice(16)
    const paddedPlaintext = _aesCbcDecrypt(encryptionKey, iv, actualCiphertext)
    console.log('  decrypted padded length:', paddedPlaintext.length)

    const result = _pkcs7Unpad(paddedPlaintext)
    console.log('  unpadded length:', result ? result.length : 'failed')
    return result
  } catch (e) {
    console.log('  error:', e.message)
    return null
  }
}

export function messageDecrypt(packet, identity, ratchets = null) {
  const data = packet.data
  if (data.length < 81) return null // Min: 32 (ephemeral) + 16 (IV) + 16 (min cipher) + 32 (HMAC) + others

  // Calculate identity hash
  const identityData = concatArrays([identity.public.encrypt, identity.public.sign])
  const identityHash = _sha256(identityData).slice(0, 16)

  // Extract components
  const ephemeralPub = data.slice(0, 32)
  const ciphertext = data.slice(32)

  console.log('data length:', data.length)
  console.log('ephemeralPub:', Buffer.from(ephemeralPub).toString('hex'))
  console.log('trying decrypt...')

  // Try decryption with ratchets first
  if (ratchets && Array.isArray(ratchets)) {
    for (const ratchet of ratchets) {
      const result = tryDecrypt(ephemeralPub, ciphertext, ratchet, identityHash)
      if (result) return result
    }
  }

  // Try with identity private key
  return tryDecrypt(ephemeralPub, ciphertext, identity.private.encrypt, identityHash)
}
