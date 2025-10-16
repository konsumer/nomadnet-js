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
  const encryptPrivate = x25519.utils.randomPrivateKey()
  const encryptPublic = x25519.getPublicKey(encryptPrivate)

  const signPrivate = ed25519.utils.randomPrivateKey()
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
  return x25519.utils.randomPrivateKey()
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

// Packet encoding/decoding
export function decodePacket(packetBytes) {
  const result = {
    raw: packetBytes,
    ifacFlag: Boolean(packetBytes[0] & 0b10000000),
    headerType: Boolean(packetBytes[0] & 0b01000000),
    contextFlag: Boolean(packetBytes[0] & 0b00100000),
    propagationType: Boolean(packetBytes[0] & 0b00010000),
    destinationType: packetBytes[0] & 0b00001100,
    packetType: packetBytes[0] & 0b00000011,
    hops: packetBytes[1]
  }

  let offset = 2

  result.destinationHash = packetBytes.slice(offset, offset + 16)
  offset += 16

  if (result.headerType) {
    result.sourceHash = packetBytes.slice(offset, offset + 16)
    offset += 16
  } else {
    result.sourceHash = null
  }

  if (result.contextFlag) {
    result.context = packetBytes[offset]
    offset += 1
  } else {
    result.context = null
  }

  result.data = packetBytes.slice(offset)

  return result
}

export function encodePacket(packet) {
  let headerByte = 0

  const sourceHash = packet.sourceHash
  if (sourceHash) {
    packet.headerType = 1
  }

  if (packet.ifacFlag) {
    headerByte |= 0b10000000
  }

  if (packet.headerType) {
    headerByte |= 0b01000000
  }

  const hasContext = 'context' in packet
  if (hasContext) {
    packet.contextFlag = true
  }

  if (packet.contextFlag) {
    headerByte |= 0b00100000
  }

  if (packet.propagationType) {
    headerByte |= 0b00010000
  }

  const destinationType = (packet.destinationType || 0) & 0b00001100
  headerByte |= destinationType

  const packetType = (packet.packetType || 0) & 0b00000011
  headerByte |= packetType

  const parts = []
  parts.push(new Uint8Array([headerByte]))
  parts.push(new Uint8Array([(packet.hops || 0) & 0xff]))

  const dest = packet.destinationHash || new Uint8Array(0)
  if (dest.length !== 16) {
    throw new Error('destination_hash must be 16 bytes')
  }
  parts.push(dest)

  if (sourceHash) {
    if (sourceHash.length !== 16) {
      throw new Error('source_hash must be 16 bytes')
    }
    parts.push(sourceHash)
  }

  if (packet.contextFlag) {
    parts.push(new Uint8Array([(packet.context || 0) & 0xff]))
  }

  parts.push(packet.data || new Uint8Array(0))

  const totalLength = parts.reduce((sum, part) => sum + part.length, 0)
  const result = new Uint8Array(totalLength)
  let offset = 0
  for (const part of parts) {
    result.set(part, offset)
    offset += part.length
  }

  return result
}

// Announce functions
export function buildAnnounce(identity, destination, name = 'lxmf.delivery', ratchetPub = null, appData = null) {
  const pubEnc = identity.public.encrypt
  const pubSig = identity.public.sign

  if (pubEnc.length !== 32 || pubSig.length !== 32) {
    throw new Error('Keys must be 32 bytes')
  }

  const keys = new Uint8Array(64)
  keys.set(pubEnc)
  keys.set(pubSig, 32)

  const nameHash = _sha256(new TextEncoder().encode(name)).slice(0, 10)
  const randomHash = randomBytes(10)

  let appDataBytes
  if (appData === null) {
    appDataBytes = new Uint8Array(0)
  } else if (typeof appData === 'string') {
    appDataBytes = new TextEncoder().encode(appData)
  } else {
    appDataBytes = appData
  }

  let effectiveRatchet
  let contextVal

  if (ratchetPub === null || arraysEqual(ratchetPub, pubEnc)) {
    effectiveRatchet = pubEnc
    contextVal = 0
  } else {
    if (ratchetPub.length !== 32) {
      throw new Error('ratchet_pub must be 32 bytes')
    }
    effectiveRatchet = ratchetPub
    contextVal = 1
  }

  const signedDataParts = [destination, keys, nameHash, randomHash, effectiveRatchet, appDataBytes]
  const signedData = concatArrays(signedDataParts)
  const signature = _ed25519Sign(signedData, identity.private.sign)

  let payload
  if (contextVal === 1) {
    payload = concatArrays([keys, nameHash, randomHash, effectiveRatchet, signature, appDataBytes])
  } else {
    payload = concatArrays([keys, nameHash, randomHash, signature, appDataBytes])
  }

  const pkt = {
    destinationHash: destination,
    packetType: PACKET_ANNOUNCE,
    destinationType: 0,
    hops: 0,
    data: payload,
    context: contextVal,
    contextFlag: true
  }

  return encodePacket(pkt)
}

export function announceParse(packet) {
  const keysize = 64
  const perKeysize = 32
  const ratchetsize = 32
  const nameHashLen = 10
  const randomHashLen = 10
  const sigLen = 64

  const data = packet.data
  const out = { valid: false }

  out.keyPubEncrypt = data.slice(0, perKeysize)
  out.keyPubSignature = data.slice(perKeysize, keysize)
  out.nameHash = data.slice(keysize, keysize + nameHashLen)
  out.randomHash = data.slice(keysize + nameHashLen, keysize + nameHashLen + randomHashLen)

  // Mimic Python's: packet.get('context_flag', packet.get('context', 0))
  // In Python, True == 1 evaluates to True
  let contextFlag
  if ('contextFlag' in packet && packet.contextFlag !== null && packet.contextFlag !== undefined) {
    contextFlag = packet.contextFlag ? 1 : 0
  } else if ('context' in packet && packet.context !== null && packet.context !== undefined) {
    contextFlag = packet.context
  } else {
    contextFlag = 0
  }

  if (contextFlag == 1) {
    const ratchetStart = keysize + nameHashLen + randomHashLen
    out.ratchetPub = data.slice(ratchetStart, ratchetStart + ratchetsize)
    out.signature = data.slice(ratchetStart + ratchetsize, ratchetStart + ratchetsize + sigLen)

    if (data.length > ratchetStart + ratchetsize + sigLen) {
      out.appData = data.slice(ratchetStart + ratchetsize + sigLen)
    } else {
      out.appData = new Uint8Array(0)
    }
  } else {
    out.ratchetPub = out.keyPubEncrypt
    const sigStart = keysize + nameHashLen + randomHashLen
    out.signature = data.slice(sigStart, sigStart + sigLen)

    if (data.length > sigStart + sigLen) {
      out.appData = data.slice(sigStart + sigLen)
    } else {
      out.appData = new Uint8Array(0)
    }
  }

  const signedData = concatArrays([packet.destinationHash, out.keyPubEncrypt, out.keyPubSignature, out.nameHash, out.randomHash, out.ratchetPub, out.appData || new Uint8Array(0)])

  out.valid = _ed25519Validate(out.keyPubSignature, out.signature, signedData)
  out.destinationHash = packet.destinationHash

  return out
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

export function proofValidate(packet, identity, fullPacketHash) {
  return _ed25519Validate(identity.public.sign, packet.data.slice(1, 65), fullPacketHash)
}

export function messageDecrypt(packet, identity, ratchets = null) {
  const identityData = new Uint8Array(64)
  identityData.set(identity.public.encrypt)
  identityData.set(identity.public.sign, 32)
  const identityHash = _sha256(identityData).slice(0, 16)

  const ciphertextToken = packet.data

  if (!ciphertextToken || ciphertextToken.length <= 49) {
    return null
  }

  const peerPubBytes = ciphertextToken.slice(1, 33)
  const ciphertext = ciphertextToken.slice(33)

  if (ratchets) {
    for (const ratchet of ratchets) {
      if (ratchet.length !== 32) {
        continue
      }

      try {
        const sharedKey = _x25519Exchange(ratchet, peerPubBytes)
        const derivedKey = _hkdf(64, sharedKey, identityHash, new Uint8Array(0))

        const signingKey = derivedKey.slice(0, 32)
        const encryptionKey = derivedKey.slice(32)

        if (ciphertext.length <= 48) {
          continue
        }

        const receivedHmac = ciphertext.slice(-32)
        const signedData = ciphertext.slice(0, -32)
        const expectedHmac = _hmacSha256(signingKey, signedData)

        if (!arraysEqual(receivedHmac, expectedHmac)) {
          continue
        }

        const iv = ciphertext.slice(0, 16)
        const ciphertextData = ciphertext.slice(16, -32)

        // Noble's CBC automatically removes PKCS7 padding
        const plaintext = _aesCbcDecrypt(encryptionKey, iv, ciphertextData)

        return plaintext
      } catch (e) {
        continue
      }
    }
  }

  return null
}

export function buildProof(identity, packet, messageId = null) {
  if (messageId === null) {
    messageId = getMessageId(packet)
  }

  const proofDestination = messageId.slice(0, 16)
  const signature = _ed25519Sign(messageId, identity.private.sign)

  const proofData = new Uint8Array(1 + signature.length)
  proofData[0] = 0x00
  proofData.set(signature, 1)

  const pkt = {
    destinationHash: proofDestination,
    packetType: PACKET_PROOF,
    destinationType: 0,
    hops: 0,
    data: proofData
  }

  return encodePacket(pkt)
}

export function buildData(identity, recipientAnnounce, plaintext, ratchet = null) {
  const recipientIdentityData = new Uint8Array(64)
  recipientIdentityData.set(recipientAnnounce.keyPubEncrypt)
  recipientIdentityData.set(recipientAnnounce.keyPubSignature, 32)
  const recipientIdentityHash = _sha256(recipientIdentityData).slice(0, 16)

  if (ratchet === null) {
    ratchet = identity.private.encrypt
  }

  const ephemeralKey = x25519.utils.randomPrivateKey()
  const ephemeralPub = x25519.getPublicKey(ephemeralKey)

  const sharedKey = _x25519Exchange(ephemeralKey, recipientAnnounce.ratchetPub)

  const derivedKey = _hkdf(64, sharedKey, recipientIdentityHash, new Uint8Array(0))
  const signingKey = derivedKey.slice(0, 32)
  const encryptionKey = derivedKey.slice(32)

  const paddedPlaintext = _pkcs7Pad(plaintext)
  const iv = randomBytes(16)
  const ciphertext = _aesCbcEncrypt(encryptionKey, iv, paddedPlaintext)

  const signedData = concatArrays([iv, ciphertext])
  const hmacSig = _hmacSha256(signingKey, signedData)

  const token = concatArrays([new Uint8Array([0x00]), ephemeralPub, iv, ciphertext, hmacSig])

  const recipientDest =
    recipientAnnounce.destinationHash ||
    getDestinationHash(
      {
        public: {
          encrypt: recipientAnnounce.keyPubEncrypt,
          sign: recipientAnnounce.keyPubSignature
        }
      },
      'lxmf',
      'delivery'
    )

  const pkt = {
    destinationHash: recipientDest,
    packetType: PACKET_DATA,
    destinationType: 0,
    hops: 0,
    data: token
  }

  return encodePacket(pkt)
}

export function buildLxmfMessage(myIdentity, myDest, myRatchet, recipientAnnounce, message) {
  const recipientDest = recipientAnnounce.destinationHash

  const timestamp = message.timestamp || Date.now() / 1000
  let title = message.title || new Uint8Array(0)
  if (typeof title === 'string') {
    title = new TextEncoder().encode(title)
  }

  let content = message.content || new Uint8Array(0)
  if (typeof content === 'string') {
    content = new TextEncoder().encode(content)
  }

  const fields = {}
  for (const [k, v] of Object.entries(message)) {
    if (!['timestamp', 'title', 'content'].includes(k)) {
      fields[k] = v
    }
  }

  const payload = [timestamp, title, content, fields]
  const packedPayload = pack(payload)

  const hashedPartLen = 16 + 16 + packedPayload.length
  const hashedPart = new Uint8Array(hashedPartLen)
  hashedPart.set(recipientDest, 0)
  hashedPart.set(myDest, 16)
  hashedPart.set(packedPayload, 32)

  const messageHash = _sha256(hashedPart)

  const signedPart = concatArrays([hashedPart, messageHash])
  const signature = _ed25519Sign(signedPart, myIdentity.private.sign)

  const lxmfMessage = concatArrays([myDest, signature, packedPayload])

  return buildData(myIdentity, recipientAnnounce, lxmfMessage, myRatchet)
}

export function parseLxmfMessage(plaintext) {
  const sourceHash = plaintext.slice(0, 16)
  const signature = plaintext.slice(16, 80)

  const [timestamp, title, content, fields] = unpack(plaintext.slice(80))

  return {
    ...fields,
    sourceHash,
    signature,
    timestamp,
    title,
    content
  }
}

// Utility functions
function arraysEqual(a, b) {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

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
