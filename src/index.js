import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { cbc } from '@noble/ciphers/aes.js'
import { hmac } from '@noble/hashes/hmac.js'
import { hexToBytes, bytesToHex, concatBytes } from '@noble/curves/utils.js'
import { unpack, pack } from 'msgpackr'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

// Packet-types
export const PACKET_DATA = 0
export const PACKET_ANNOUNCE = 1
export const PACKET_LINKREQUEST = 2
export const PACKET_PROOF = 3

// Destination type constants (match RNS.Destination types)
export const DESTINATION_SINGLE = 0x00 // Single (encrypted)
export const DESTINATION_GROUP = 0x01 // Group (shared key)
export const DESTINATION_PLAIN = 0x02 // Plaintext
export const DESTINATION_LINK = 0x03 // Link (uses link_id in header)

// Packet context-types
export const CONTEXT_NONE = 0x00 // Generic data packet
export const CONTEXT_RESOURCE = 0x01 // Packet is part of a resource
export const CONTEXT_RESOURCE_ADV = 0x02 // Packet is a resource advertisement
export const CONTEXT_RESOURCE_REQ = 0x03 // Packet is a resource part request
export const CONTEXT_RESOURCE_HMU = 0x04 // Packet is a resource hashmap update
export const CONTEXT_RESOURCE_PRF = 0x05 // Packet is a resource proof
export const CONTEXT_RESOURCE_ICL = 0x06 // Packet is a resource initiator cancel message
export const CONTEXT_RESOURCE_RCL = 0x07 // Packet is a resource receiver cancel message
export const CONTEXT_CACHE_REQUEST = 0x08 // Packet is a cache request
export const CONTEXT_REQUEST = 0x09 // Packet is a request
export const CONTEXT_RESPONSE = 0x0a // Packet is a response to a request
export const CONTEXT_PATH_RESPONSE = 0x0b // Packet is a response to a path request
export const CONTEXT_COMMAND = 0x0c // Packet is a command
export const CONTEXT_COMMAND_STATUS = 0x0d // Packet is a status of an executed command
export const CONTEXT_CHANNEL = 0x0e // Packet contains link channel data
export const CONTEXT_KEEPALIVE = 0xfa // Packet is a keepalive packet
export const CONTEXT_LINKIDENTIFY = 0xfb // Packet is a link peer identification proof
export const CONTEXT_LINKCLOSE = 0xfc // Packet is a link close message
export const CONTEXT_LINKPROOF = 0xfd // Packet is a link packet proof
export const CONTEXT_LRRTT = 0xfe // Packet is a link request round-trip time measurement
export const CONTEXT_LRPROOF = 0xff // Packet is a link request proof

// Serialization (storing string)
export const serializeIdentity = ({ encPriv, sigPriv }) => bytesToHex(new Uint8Array([...encPriv, ...sigPriv]))
export const unserializeIdentity = (s) => {
  const keyBytes = hexToBytes(s)
  let id = {
    encPriv: keyBytes.slice(0, 32),
    sigPriv: keyBytes.slice(32)
  }
  id = { ...id, ...pubFromPrivate(id) }
  id = { ...id, ...getLxmfIdentity(id) }
  return id
}

// Generate identity keys
export function generateIdentity() {
  const encPriv = x25519.utils.randomSecretKey()
  const sigPriv = ed25519.utils.randomSecretKey()
  return { encPriv, sigPriv }
}

// Get LXMF address info from pub keys
export function getLxmfIdentity({ encPub, sigPub, name = 'lxmf.delivery' }) {
  const nameHash = sha256(encoder.encode(name)).slice(0, 10) // 10 bytes
  const pubBlob = concatBytes(encPub, sigPub) // get_public_key() equivalent
  const identityHash = sha256(pubBlob).slice(0, 16) // 16 bytes
  const destinationHash = sha256(concatBytes(nameHash, identityHash)).slice(0, 16) // 16 bytes
  return { identityHash, destinationHash }
}

export function pubFromPrivate({ encPriv, sigPriv }) {
  const encPub = x25519.getPublicKey(encPriv) // 32 bytes
  const sigPub = ed25519.getPublicKey(sigPriv) // 32 bytes
  return { encPub, sigPub }
}

export function loadPacket(buffer) {
  const out = {
    flags: buffer[0],
    hops: buffer[1],
    raw: new Uint8Array(buffer)
  }

  out.headerType = (out.flags & 0b01000000) >> 6
  out.contextFlag = (out.flags & 0b00100000) >> 5
  out.transportType = (out.flags & 0b00010000) >> 4
  out.destinationType = (out.flags & 0b00001100) >> 2
  out.packetType = out.flags & 0b00000011

  // 2 addresses?
  if (out.headerType === 1) {
    out.transportId = out.raw.slice(2, 18)
    out.destinationHash = out.raw.slice(18, 34)
    out.context = buffer[34]
    out.data = out.raw.slice(35)
  } else {
    out.destinationHash = out.raw.slice(2, 18)
    out.context = buffer[18]
    out.data = out.raw.slice(19)
  }
  return out
}

// Verify and parse an announce packet (output from unpackHeader)
export function parseAnnounce(packet) {
  const out = { ...packet }

  const keysize = 64
  const ratchetsize = 32
  const name_hash_len = 10
  const sig_len = 64

  out.pubKeyEncrypt = packet.data.slice(0, keysize / 2)
  out.pubKeySignature = packet.data.slice(keysize / 2, keysize)

  out.nameHash = packet.data.slice(keysize, keysize + name_hash_len)
  out.randomHash = packet.data.slice(keysize + name_hash_len, keysize + name_hash_len + 10)

  if (packet.contextFlag === 1) {
    out.ratchet = packet.data.slice(keysize + name_hash_len + 10, keysize + name_hash_len + 10 + ratchetsize)
    out.signature = packet.data.slice(keysize + name_hash_len + 10 + ratchetsize, keysize + name_hash_len + 10 + ratchetsize + sig_len)
    if (packet.data.length > keysize + name_hash_len + 10 + sig_len + ratchetsize) {
      out.appData = packet.data.slice(keysize + name_hash_len + 10 + sig_len + ratchetsize)
    } else {
      out.appData = new Uint8Array()
    }
  } else {
    out.ratchet = new Uint8Array()
    out.signature = packet.data.slice(keysize + name_hash_len + 10, keysize + name_hash_len + 10 + sig_len)
    if (packet.data.length > keysize + name_hash_len + 10 + sig_len) {
      out.appData = packet.data.slice(keysize + name_hash_len + 10 + sig_len)
    } else {
      out.appData = new Uint8Array()
    }
  }

  const signedData = new Uint8Array([...out.destinationHash, ...out.pubKeyEncrypt, ...out.pubKeySignature, ...out.nameHash, ...out.randomHash, ...out.ratchet, ...out.appData])
  out.verified = ed25519.verify(out.signature, signedData, out.pubKeySignature)

  if (out.appData.length) {
    try {
      out.appData = unpack(out.appData)
      out.peerName = decoder.decode(out.appData[0])
    } catch (e) {}
  }

  return out
}

// this is still not working
export async function decryptMessage(packet, identity, ratchets) {
  const DERIVED_KEY_LENGTH = 64

  const peerPublicKey = packet.data.slice(0, 32) // Ephemeral public key from sender
  const ciphertext = packet.data.slice(32) // Encrypted payload

  // Try each ratchet key
  for (const ratchet of ratchets) {
    try {
      const sharedKey = x25519.getSharedSecret(ratchet, peerPublicKey)
      const derivedKey = hkdf(sha256, sharedKey, sha256(identity.encPub), new Uint8Array(0), DERIVED_KEY_LENGTH)
      const plaintext = await fernetDecrypt(derivedKey, ciphertext)
      if (plaintext !== null) {
        return plaintext
      }
    } catch (e) {
      // Try next ratchet on failure
      console.log(e)
      continue
    }
  }
  return null
}

async function fernetDecrypt(key, token) {
  // Require minimum size: 16 IV + 32 HMAC
  if (token.length < 64) return null
  const iv = token.slice(0, 16)
  const hmacSig = token.slice(token.length - 32)
  const ciphertext = token.slice(16, token.length - 32)
  const encKey = key.slice(0, 32)
  const macKey = key.slice(32, 64)
  const dataToVerify = token.slice(0, token.length - 32)
  const computedHmac = hmac(sha256, macKey, dataToVerify)
  // console.log(bytesToHex(hmacSig.slice(0, 8)), bytesToHex(computedHmac.slice(0, 8)))
  if (!constantTimeCompare(hmacSig, computedHmac)) return null
  const plaintext = await aes256CbcDecrypt(encKey, iv, ciphertext)
  if (!plaintext) return null
  return removePkcs7Padding(plaintext)
}

// compare if 2 arrays have equal value, using contant-time (prevents sideband attacks)
export function constantTimeCompare(a, b) {
  if (a.length !== b.length) return false
  let result = 0
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i]
  }
  return result === 0
}

// compare if 2 arrays have equal value
export function byteCompare(a, b) {
  if (a.length !== b.length) return false
  for (const i in a) {
    if (a[i] !== b[i]) {
      return false
    }
  }
  return true
}

async function aes128CbcDecrypt(key, iv, ciphertext) {
  try {
    // Import key for Web Crypto API
    const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'AES-CBC' }, false, ['decrypt'])

    // Decrypt
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-CBC',
        iv: iv
      },
      cryptoKey,
      ciphertext
    )

    return new Uint8Array(decrypted)
  } catch (e) {
    return null
  }
}

function removePkcs7Padding(data) {
  const paddingLength = data[data.length - 1]
  if (paddingLength > 16 || paddingLength > data.length) {
    throw new Error('Invalid padding')
  }
  return data.slice(0, data.length - paddingLength)
}
