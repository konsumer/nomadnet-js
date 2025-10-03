import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { cbc } from '@noble/ciphers/aes.js'
import { hmac } from '@noble/hashes/hmac.js'
import { hexToBytes, bytesToHex, concatBytes, randomBytes } from '@noble/curves/utils.js'
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

// Packet propagation-types
export const PROPOGATION_BROADCAST = 0x00
export const PROPOGATION_TRANSPORT = 0x01
export const PROPOGATION_RELAY = 0x02
export const PROPOGATION_TUNNEL = 0x03

// Serialize identity as just 2 privatge keys, encopded as hex-string
export const serializeIdentity = ({ encPriv, sigPriv }) => bytesToHex(new Uint8Array([...encPriv, ...sigPriv]))

// Deserialize identity private keys (hex string of 2 keys) and derive public & address-info
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

// Generate fresh & complete identity
export function generateIdentity() {
  const encPriv = x25519.utils.randomSecretKey()
  let sigPriv = ed25519.utils.randomSecretKey()
  let id = { encPriv, sigPriv }
  id = { ...id, ...pubFromPrivate(id) }
  id = { ...id, ...getLxmfIdentity(id) }
  return id
}

export function generateRatchet() {
  const ratchetPriv = randomBytes(32)
  const ratchetPub = x25519.getPublicKey(ratchetPriv)
  return { ratchetPriv, ratchetPub }
}

// Get LXMF address info from pub keys
export function getLxmfIdentity({ encPub, sigPub, name = 'lxmf.delivery' }) {
  const nameHash = sha256(encoder.encode(name)).slice(0, 10) // 10 bytes
  const pubBlob = concatBytes(encPub, sigPub) // get_public_key() equivalent
  const identityHash = sha256(pubBlob).slice(0, 16) // 16 bytes
  const destinationHash = sha256(concatBytes(nameHash, identityHash)).slice(0, 16) // 16 bytes
  return { identityHash, destinationHash }
}

// get public-keys from private-keys
export function pubFromPrivate({ encPriv, sigPriv }) {
  const encPub = x25519.getPublicKey(encPriv) // 32 bytes
  const sigPub = ed25519.getPublicKey(sigPriv) // 32 bytes
  return { encPub, sigPub }
}

// to use: create a shared-key with x25519.getSharedSecret(myRatchetPriv, theirRatchetPubFromAnnounce)

// compare if 2 arrays have equal value, using constant-time (prevents sideband attacks)
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

// Parse a reticulum packet into it's parts
export function loadPacket(buffer) {
  const flags = buffer[0]
  const out = {
    hops: buffer[1],
    raw: new Uint8Array(buffer)
  }

  out.ifac = (flags & 0b10000000) >> 7
  out.headerType = (flags & 0b01000000) >> 6
  out.contextFlag = (flags & 0b00100000) >> 5
  out.propogationType = (flags & 0b00010000) >> 4
  out.destinationType = (flags & 0b00001100) >> 2
  out.packetType = flags & 0b00000011

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

// Verify and parse an announce packet (output from loadPacket)
export function parseAnnounce(packet) {
  const out = { ...packet }
  const keysize = 64
  const ratchetsize = 32
  const name_hash_len = 10
  const random_hash_len = 10 // Not 32!
  const sig_len = 64

  out.pubKeyEncrypt = packet.data.slice(0, keysize / 2)
  out.pubKeySignature = packet.data.slice(keysize / 2, keysize)

  out.nameHash = packet.data.slice(keysize, keysize + name_hash_len)
  out.randomHash = packet.data.slice(keysize + name_hash_len, keysize + name_hash_len + random_hash_len)

  // does this packet have a ratchet pubkey?
  if (packet.contextFlag === 1) {
    out.ratchetPub = packet.data.slice(keysize + name_hash_len + random_hash_len, keysize + name_hash_len + random_hash_len + ratchetsize)
    out.signature = packet.data.slice(keysize + name_hash_len + random_hash_len + ratchetsize, keysize + name_hash_len + random_hash_len + ratchetsize + sig_len)
    if (packet.data.length > keysize + name_hash_len + random_hash_len + ratchetsize + sig_len) {
      out.appData = packet.data.slice(keysize + name_hash_len + random_hash_len + ratchetsize + sig_len)
    }
  } else {
    out.ratchetPub = out.pubKeyEncrypt
    out.signature = packet.data.slice(keysize + name_hash_len + random_hash_len, keysize + name_hash_len + random_hash_len + sig_len)
    if (packet.data.length > keysize + name_hash_len + random_hash_len + sig_len) {
      out.appData = packet.data.slice(keysize + name_hash_len + random_hash_len + sig_len)
    }
  }

  const signedData = new Uint8Array([...out.destinationHash, ...out.pubKeyEncrypt, ...out.pubKeySignature, ...out.nameHash, ...out.randomHash, ...(out.ratchetPub || []), ...(out.appData || [])])
  out.verified = ed25519.verify(out.signature, signedData, out.pubKeySignature)

  if (out.appData?.length) {
    try {
      out.appData = unpack(out.appData)
      out.peerName = decoder.decode(out.appData[0])
    } catch (e) {}
  }

  return out
}

// Build a raw Reticulum packet from components (Reverse of loadPacket())
export function buildPacket(packet) {
  // Build flags byte from components
  const flags = ((packet.ifac || 0) << 7) | ((packet.headerType || 0) << 6) | ((packet.contextFlag || 0) << 5) | ((packet.propogationType || 0) << 4) | ((packet.destinationType || 0) << 2) | (packet.packetType || 0)

  const parts = [new Uint8Array([flags]), new Uint8Array([packet.hops || 0])]

  // Header type 1 = two addresses (transport + destination)
  if (packet.headerType === 1) {
    parts.push(packet.transportId) // 16 bytes
    parts.push(packet.destinationHash) // 16 bytes
    parts.push(new Uint8Array([packet.context || 0]))
  } else {
    // Header type 0 = single address (destination only)
    parts.push(packet.destinationHash) // 16 bytes
    parts.push(new Uint8Array([packet.context || 0]))
  }

  // Add data payload
  if (packet.data) {
    parts.push(packet.data)
  }

  // Concatenate all parts
  const totalLength = parts.reduce((sum, arr) => sum + (arr?.length || 0), 0)
  const buffer = new Uint8Array(totalLength)
  let offset = 0

  for (const part of parts) {
    if (part) {
      buffer.set(part, offset)
      offset += part.length
    }
  }

  return buffer
}

// Build an ANNOUNCE packet from components (Reverse of parseAnnounce())
export function buildAnnounce(announce, identity) {
  const parts = []

  // Public keys (64 bytes total)
  parts.push(identity.encPub) // 32 bytes
  parts.push(identity.sigPub) // 32 bytes

  const fullAppName = announce.aspects && announce.aspects.length > 0 ? `${announce.appName}.${announce.aspects.join('.')}` : announce.appName

  const nameHash = sha256(new TextEncoder().encode(fullAppName)).slice(0, 10)
  const randomHash = randomBytes(10)

  // Hashes
  parts.push(nameHash) // 10 bytes
  parts.push(randomHash) // 10 bytes

  // Ratchet public key (only if enabled)
  if (announce.contextFlag && announce.ratchetPub) {
    parts.push(announce.ratchetPub) // 32 bytes
  }

  // App data (optional)
  if (announce.appData) {
    parts.push(announce.appData)
  }

  // Build data section
  const dataLength = parts.reduce((sum, arr) => sum + arr.length, 0)
  const data = new Uint8Array(dataLength)
  let offset = 0
  for (const part of parts) {
    data.set(part, offset)
    offset += part.length
  }

  // Create signed data (what gets signed)
  const signedData = new Uint8Array([...identity.destinationHash, ...identity.encPub, ...identity.sigPub, ...nameHash, ...randomHash, ...(announce.useRatchet && announce.ratchetPub ? announce.ratchetPub : []), ...(announce.appData || [])])

  // Sign with Ed25519 private key
  const signature = ed25519.sign(signedData, identity.sigPriv)

  // Add signature to data
  const finalData = new Uint8Array(data.length + signature.length)
  finalData.set(data, 0)
  finalData.set(signature, data.length)

  const { ifac = 0, headerType, contextFlag, propogationType = PROPOGATION_BROADCAST, destinationType = DESTINATION_SINGLE, packetType = PACKET_ANNOUNCE, hops = 0, destinationHash, transportId, context = 0 } = announce

  // Build complete packet structure
  return {
    ifac,
    headerType,
    contextFlag,
    propogationType,
    destinationType,
    packetType,
    hops,
    destinationHash,
    transportId,
    context,
    data: finalData
  }
}

function reticulumFernetDecrypt(token, derivedKey64) {
  if (token.length < 48) throw new Error('Invalid token length')

  const iv = token.slice(0, 16)
  const ciphertext = token.slice(16, -32)
  const receivedHmac = token.slice(-32)

  const signingKey = derivedKey64.slice(0, 32)
  const encryptionKey = derivedKey64.slice(32, 64)

  // Verify HMAC
  const hmacData = token.slice(0, -32)
  const computedHmac = hmac(sha256, signingKey, hmacData)

  let hmacMatch = true
  for (let i = 0; i < 32; i++) {
    if (receivedHmac[i] !== computedHmac[i]) hmacMatch = false
  }
  if (!hmacMatch) throw new Error('HMAC verification failed')

  // Try different approaches with @noble/ciphers
  // Option 1: Direct decrypt call
  let plaintext = cbc(encryptionKey, iv).decrypt(ciphertext)

  // Manually remove PKCS7 padding
  const paddingLength = plaintext[plaintext.length - 1]
  if (paddingLength > 0 && paddingLength <= 16) {
    plaintext = plaintext.slice(0, plaintext.length - paddingLength)
  }

  return plaintext
}

/**
 * Decrypt a Reticulum DATA packet using ratchets
 */
export function identityDecrypt(data, identity, ratchets = []) {
  const ephemeralPub = data.slice(0, 32)
  const ciphertext = data.slice(32)

  for (let i = 0; i < ratchets.length; i++) {
    const privateKey = ratchets[i]

    try {
      const sharedSecret = x25519.getSharedSecret(privateKey, ephemeralPub)
      const derivedKey = hkdf(sha256, sharedSecret, identity.identityHash, undefined, 64)
      const plaintext = reticulumFernetDecrypt(ciphertext, derivedKey)
      return plaintext
    } catch (e) {
      continue
    }
  }

  throw new Error('Decryption failed with all available ratchets')
}

/**
 * Process a DATA packet
 */
export function processMessage(packet, identity, ratchets = []) {
  const decryptedBytes = identityDecrypt(packet.data, identity, ratchets)
  const messageData = decryptedBytes.slice(80)
  const [timestamp, title, content, fields] = unpack(messageData)
  return { timestamp, title, content, fields }
}

/**
 * Reticulum's modified Fernet encrypt using @noble
 */
function reticulumFernetEncrypt(plaintext, derivedKey64) {
  // Add PKCS7 padding
  const blockSize = 16
  const paddingLength = blockSize - (plaintext.length % blockSize)
  const padding = new Uint8Array(paddingLength).fill(paddingLength)
  const paddedPlaintext = new Uint8Array([...plaintext, ...padding])

  // Generate random IV
  const iv = randomBytes(16)

  // Split the 64-byte derived key
  const signingKey = derivedKey64.slice(0, 32)
  const encryptionKey = derivedKey64.slice(32, 64)

  // Encrypt with AES-256-CBC
  const cipher = cbc(encryptionKey, iv)
  const ciphertext = cipher.encrypt(paddedPlaintext)

  // Build token: IV + Ciphertext
  const token = new Uint8Array(iv.length + ciphertext.length)
  token.set(iv, 0)
  token.set(ciphertext, iv.length)

  // Calculate HMAC over IV + Ciphertext
  const tokenHmac = hmac(sha256, signingKey, token)

  // Final token: IV + Ciphertext + HMAC
  const finalToken = new Uint8Array(token.length + tokenHmac.length)
  finalToken.set(token, 0)
  finalToken.set(tokenHmac, token.length)

  return finalToken
}

/**
 * Encrypt data for a Reticulum DATA packet
 *
 * @param {Uint8Array} plaintext - The data to encrypt
 * @param {Uint8Array} recipientPubKey - Recipient's ratchet public key or identity encryption key (32 bytes)
 * @param {Uint8Array} recipientIdentityHash - Recipient's identity hash (16 bytes)
 * @returns {Uint8Array} Encrypted packet data (ephemeral_pub + fernet_token)
 */
export function encryptData(plaintext, recipientPubKey, recipientIdentityHash) {
  // Generate ephemeral X25519 key pair
  const ephemeralPriv = randomBytes(32)
  const ephemeralPub = x25519.getPublicKey(ephemeralPriv)

  // Perform ECDH with recipient's public key
  const sharedSecret = x25519.getSharedSecret(ephemeralPriv, recipientPubKey)

  // Derive 64-byte key using HKDF (salt=identity hash, info=undefined)
  const derivedKey = hkdf(sha256, sharedSecret, recipientIdentityHash, undefined, 64)

  // Encrypt with Reticulum's modified Fernet
  const fernetToken = reticulumFernetEncrypt(plaintext, derivedKey)

  // Prepend ephemeral public key
  const encryptedData = new Uint8Array(ephemeralPub.length + fernetToken.length)
  encryptedData.set(ephemeralPub, 0)
  encryptedData.set(fernetToken, ephemeralPub.length)

  return encryptedData
}

/**
 * Build an encrypted DATA packet for LXMF/NomadNet
 *
 * @param {Object} message - Message content
 * @param {string} message.content - Message body text
 * @param {string} message.title - Message title (optional, empty string for chat)
 * @param {Object} message.fields - Additional fields (optional, empty object)
 * @param {Uint8Array} recipientDestinationHash - Recipient's destination hash (16 bytes)
 * @param {Uint8Array} recipientRatchetPub - Recipient's current ratchet public key (32 bytes)
 * @param {Uint8Array} recipientIdentityHash - Recipient's identity hash (16 bytes)
 * @returns {Object} Complete packet ready for buildPacket()
 */
export function buildMessage(message, recipientDestinationHash, recipientRatchetPriv, recipientIdentityHash) {
  const timestamp = Date.now() / 1000
  const titleBytes = message.title ? encoder.encode(message.title) : new Uint8Array()
  const contentBytes = message.content ? encoder.encode(message.content) : new Uint8Array()
  const messageData = pack([timestamp, titleBytes, contentBytes, message.fields || {}])

  // Add 80-byte header
  // TODO: what is this?
  const header = new Uint8Array(80)
  const plaintext = new Uint8Array([...header, ...messageData])

  const recipientRatchetPub = x25519.getPublicKey(recipientRatchetPriv) // Derive public key
  const encryptedData = encryptData(plaintext, recipientRatchetPub, recipientIdentityHash)

  // Build complete DATA packet
  return {
    ifac: 0,
    headerType: 0,
    contextFlag: 0,
    propogationType: 0,
    destinationType: 0,
    packetType: 0,
    hops: 0,
    destinationHash: recipientDestinationHash,
    context: 0,
    data: encryptedData
  }
}
