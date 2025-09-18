/**
 * Reticulum Network Stack (RNS) JavaScript Implementation
 * A clean, functional library for RNS/LXMF/NomadNet communication
 */

// Zero-dependency implementation using only Web Crypto API
import { deriveX25519PublicKey, deriveEd25519PublicKey } from './curves.js'

// =============================================================================
// Constants
// =============================================================================

const IDENTITY_KEYSIZE = 256 * 2 // Total bits for combined keys
const TRUNCATED_HASHLENGTH = 128 // Bits for truncated hashes
const NAME_HASH_LENGTH = 80 // Bits for name hashes

// Packet types
const PACKET_TYPE = {
  DATA: 0x00,
  ANNOUNCE: 0x01,
  LINKREQUEST: 0x02,
  PROOF: 0x03
}

// Destination types
const DESTINATION_TYPE = {
  SINGLE: 0x00,
  GROUP: 0x01,
  PLAIN: 0x02
}

// HDLC framing constants
const HDLC = {
  FLAG: 0x7e,
  ESC: 0x7d,
  ESC_MASK: 0x20
}

// =============================================================================
// Cryptographic Functions
// =============================================================================

/**
 * Compute SHA-256 hash
 */
export async function sha256(data) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  return new Uint8Array(hashBuffer)
}

/**
 * Compute truncated hash (first 128 bits of SHA-256)
 */
export async function truncatedHash(data) {
  const hash = await sha256(data)
  return hash.slice(0, TRUNCATED_HASHLENGTH / 8)
}

/**
 * Generate a random hash
 */
export async function getRandomHash() {
  const randomData = new Uint8Array(TRUNCATED_HASHLENGTH / 8)
  crypto.getRandomValues(randomData)
  return await truncatedHash(randomData)
}

// =============================================================================
// Identity Management
// =============================================================================

/**
 * Generate a new identity with X25519 and Ed25519 keypairs
 */
export async function generateIdentity() {
  // Generate X25519 keypair for encryption
  const encKeyPair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveKey', 'deriveBits'])

  // Generate Ed25519 keypair for signing
  const sigKeyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])

  // Export public keys to combine them
  const encPublic = new Uint8Array(await crypto.subtle.exportKey('raw', encKeyPair.publicKey))
  const sigPublic = new Uint8Array(await crypto.subtle.exportKey('raw', sigKeyPair.publicKey))

  // Combine public keys and compute identity hash
  const publicKey = new Uint8Array(64)
  publicKey.set(encPublic, 0)
  publicKey.set(sigPublic, 32)

  const hash = await truncatedHash(publicKey)
  const hexhash = bytesToHex(hash)

  return {
    encKeyPair,
    sigKeyPair,
    encPublic,
    sigPublic,
    publicKey,
    hash,
    hexhash
  }
}

/**
 * Get the combined private key bytes for storage
 */
export async function getPrivateKeyBytes(identity) {
  const encPrivate = new Uint8Array(await crypto.subtle.exportKey('raw', identity.encKeyPair.privateKey))
  const sigPrivate = new Uint8Array(await crypto.subtle.exportKey('raw', identity.sigKeyPair.privateKey))

  const privateKey = new Uint8Array(64)
  privateKey.set(encPrivate, 0)
  privateKey.set(sigPrivate, 32)
  return privateKey
}

/**
 * Load identity from private key bytes
 */
export async function loadIdentity(privateKeyBytes) {
  if (privateKeyBytes.length !== 64) {
    throw new Error('Invalid private key length')
  }

  // Extract private keys
  const encPrivate = privateKeyBytes.slice(0, 32)
  const sigPrivate = privateKeyBytes.slice(32, 64)

  // Import private keys as CryptoKey objects
  const encKeyPair = {
    privateKey: await crypto.subtle.importKey('raw', encPrivate, { name: 'X25519' }, true, ['deriveKey', 'deriveBits']),
    publicKey: null // Will be derived when needed
  }

  const sigKeyPair = {
    privateKey: await crypto.subtle.importKey('raw', sigPrivate, { name: 'Ed25519' }, true, ['sign']),
    publicKey: null // Will be derived when needed
  }

  // Derive public keys from private keys using our curve implementations
  const encPublic = deriveX25519PublicKey(encPrivate)
  const sigPublic = await deriveEd25519PublicKey(sigPrivate)

  // Import the derived public keys as CryptoKey objects
  encKeyPair.publicKey = await crypto.subtle.importKey('raw', encPublic, { name: 'X25519' }, true, [])

  sigKeyPair.publicKey = await crypto.subtle.importKey('raw', sigPublic, { name: 'Ed25519' }, true, ['verify'])

  // Combine public keys and compute hash
  const publicKey = new Uint8Array(64)
  publicKey.set(encPublic, 0)
  publicKey.set(sigPublic, 32)

  const hash = await truncatedHash(publicKey)
  const hexhash = bytesToHex(hash)

  return {
    encKeyPair,
    sigKeyPair,
    encPublic,
    sigPublic,
    publicKey,
    hash,
    hexhash
  }
}

/**
 * Sign data with identity
 */
export async function sign(identity, data) {
  const signature = await crypto.subtle.sign('Ed25519', identity.sigKeyPair.privateKey, data)
  return new Uint8Array(signature)
}

/**
 * Verify signature with identity
 */
export async function verify(identity, signature, data) {
  return await crypto.subtle.verify('Ed25519', identity.sigKeyPair.publicKey, signature, data)
}

// =============================================================================
// Destination Functions
// =============================================================================

/**
 * Expand a destination name
 */
export function expandDestinationName(identity, appName, ...aspects) {
  if (appName.includes('.')) {
    throw new Error("Dots can't be used in app names")
  }

  let name = appName
  for (const aspect of aspects) {
    if (aspect.includes('.')) {
      throw new Error("Dots can't be used in aspects")
    }
    name += '.' + aspect
  }

  if (identity !== null) {
    name += '.' + identity.hexhash
  }

  return name
}

/**
 * Calculate destination hash
 */
export async function destinationHash(identity, appName, ...aspects) {
  // Create name hash from expanded name
  const expandedName = expandDestinationName(null, appName, ...aspects)
  const nameBytes = new TextEncoder().encode(expandedName)
  const nameHashFull = await sha256(nameBytes)
  const nameHash = nameHashFull.slice(0, NAME_HASH_LENGTH / 8)

  // Build address hash material
  let addrHashMaterial = nameHash

  if (identity !== null) {
    addrHashMaterial = new Uint8Array(nameHash.length + identity.hash.length)
    addrHashMaterial.set(nameHash, 0)
    addrHashMaterial.set(identity.hash, nameHash.length)
  }

  // Return truncated hash
  return await truncatedHash(addrHashMaterial)
}

// =============================================================================
// Announcement Creation
// =============================================================================

/**
 * Create an announcement packet
 */
export async function createAnnouncement(identity, appName, aspects = [], displayName = null) {
  // Calculate destination hash
  const destHash = await destinationHash(identity, appName, ...aspects)

  // Calculate name hash
  const expandedName = expandDestinationName(null, appName, ...aspects)
  const nameBytes = new TextEncoder().encode(expandedName)
  const nameHashFull = await sha256(nameBytes)
  const nameHash = nameHashFull.slice(0, NAME_HASH_LENGTH / 8)

  // Generate random hash with timestamp
  const randomPart = new Uint8Array(5)
  crypto.getRandomValues(randomPart)
  const timestamp = Math.floor(Date.now() / 1000)
  const timestampBytes = new Uint8Array(5)
  let ts = timestamp
  for (let i = 4; i >= 0; i--) {
    timestampBytes[i] = ts & 0xff
    ts = ts >> 8
  }
  const randomHash = new Uint8Array(10)
  randomHash.set(randomPart, 0)
  randomHash.set(timestampBytes, 5)

  // Create app data (plain UTF-8 for display name)
  const appData = displayName ? new TextEncoder().encode(displayName) : null

  // Build signed data
  const signedDataParts = [destHash, identity.publicKey, nameHash, randomHash]
  if (appData) {
    signedDataParts.push(appData)
  }

  let signedDataLength = 0
  for (const part of signedDataParts) {
    signedDataLength += part.length
  }

  const signedData = new Uint8Array(signedDataLength)
  let offset = 0
  for (const part of signedDataParts) {
    signedData.set(part, offset)
    offset += part.length
  }

  // Sign the data
  const signature = await sign(identity, signedData)

  // Build announce data
  const announceDataParts = [identity.publicKey, nameHash, randomHash, signature]
  if (appData) {
    announceDataParts.push(appData)
  }

  let announceDataLength = 0
  for (const part of announceDataParts) {
    announceDataLength += part.length
  }

  const announceData = new Uint8Array(announceDataLength)
  offset = 0
  for (const part of announceDataParts) {
    announceData.set(part, offset)
    offset += part.length
  }

  // Create packet header
  const flags = PACKET_TYPE.ANNOUNCE | (DESTINATION_TYPE.SINGLE << 4)
  const hops = 0
  const context = 0x00

  // Assemble complete packet
  const packet = new Uint8Array(19 + announceData.length)
  packet[0] = flags
  packet[1] = hops
  packet.set(destHash, 2)
  packet[18] = context
  packet.set(announceData, 19)

  return packet
}

// =============================================================================
// HDLC Framing
// =============================================================================

/**
 * Escape data for HDLC framing
 */
export function hdlcEscape(data) {
  const escaped = []
  for (const byte of data) {
    if (byte === HDLC.FLAG || byte === HDLC.ESC) {
      escaped.push(HDLC.ESC)
      escaped.push(byte ^ HDLC.ESC_MASK)
    } else {
      escaped.push(byte)
    }
  }
  return new Uint8Array(escaped)
}

/**
 * Frame a packet with HDLC
 */
export function hdlcFrame(packet) {
  const escaped = hdlcEscape(packet)
  const frame = new Uint8Array(escaped.length + 2)
  frame[0] = HDLC.FLAG
  frame.set(escaped, 1)
  frame[frame.length - 1] = HDLC.FLAG
  return frame
}

/**
 * Unescape HDLC data
 */
export function hdlcUnescape(data) {
  const unescaped = []
  let escaping = false

  for (const byte of data) {
    if (escaping) {
      unescaped.push(byte ^ HDLC.ESC_MASK)
      escaping = false
    } else if (byte === HDLC.ESC) {
      escaping = true
    } else if (byte !== HDLC.FLAG) {
      unescaped.push(byte)
    }
  }

  return new Uint8Array(unescaped)
}

/**
 * Extract HDLC frames from a buffer
 */
export function extractHdlcFrames(buffer) {
  const frames = []
  let start = -1

  for (let i = 0; i < buffer.length; i++) {
    if (buffer[i] === HDLC.FLAG) {
      if (start !== -1 && i > start + 1) {
        // Found end of frame
        const frameData = buffer.slice(start + 1, i)
        if (frameData.length > 0) {
          frames.push(hdlcUnescape(frameData))
        }
      }
      start = i
    }
  }

  return frames
}

// =============================================================================
// Packet Parsing
// =============================================================================

/**
 * Parse a packet and extract relevant information based on packet type
 * @param {Uint8Array} packet - The raw packet data to parse
 * @returns {Object} Parsed packet information including type and relevant data
 */
export async function parsePacket(packet) {
  if (!packet || packet.length < 19) {
    return { type: 'invalid', error: 'Packet too short' }
  }

  // Extract header fields
  const flags = packet[0]
  const hops = packet[1]
  const packetType = flags & 0x0f
  const destinationType = (flags >> 4) & 0x0f
  const destHash = packet.slice(2, 18)
  const context = packet[18]
  const data = packet.slice(19)

  // Base packet info
  const result = {
    type: null,
    packetType,
    destinationType,
    hops,
    destHash,
    context,
    raw: packet
  }

  // Parse based on packet type
  switch (packetType) {
    case PACKET_TYPE.ANNOUNCE:
      result.type = 'announce'

      // Parse announcement data structure
      // Structure: publicKey(64) + nameHash(10) + randomHash(10) + signature(64) + appData(variable)
      const minLength = 64 + 10 + 10 + 64 // 148 bytes minimum
      if (data.length >= minLength) {
        let offset = 0

        // Extract fields
        result.publicKey = data.slice(offset, offset + 64)
        offset += 64

        result.nameHash = data.slice(offset, offset + 10)
        offset += 10

        result.randomHash = data.slice(offset, offset + 10)
        offset += 10

        result.signature = data.slice(offset, offset + 64)
        offset += 64

        // Extract timestamp from random hash (last 5 bytes, big-endian)
        let timestamp = 0
        for (let i = 5; i < 10; i++) {
          timestamp = (timestamp << 8) | result.randomHash[i]
        }
        result.timestamp = timestamp

        // App data (display name) if present
        if (data.length > offset) {
          result.appData = data.slice(offset)

          // Search for printable ASCII strings in the app data
          // The display name is embedded somewhere in this binary data
          let bestMatch = ''
          let currentString = ''

          for (let i = 0; i < result.appData.length; i++) {
            const byte = result.appData[i]

            // Check if it's a printable ASCII character (32-126)
            if (byte >= 32 && byte <= 126) {
              currentString += String.fromCharCode(byte)
            } else {
              // End of current string, check if it's a good candidate
              if (currentString.length > bestMatch.length && currentString.length >= 3) {
                bestMatch = currentString
              }
              currentString = ''
            }
          }

          // Check final string
          if (currentString.length > bestMatch.length && currentString.length >= 3) {
            bestMatch = currentString
          }

          result.displayName = bestMatch || null
        }

        // Extract encryption and signing public keys
        result.encPublic = result.publicKey.slice(0, 32)
        result.sigPublic = result.publicKey.slice(32, 64)

        // Calculate identity hash from public key
        result.identityHash = await truncatedHash(result.publicKey)
        result.identity = bytesToHex(result.identityHash) // NomadNet UI terminology
        result.address = result.identity // Backward compatibility
      } else {
        result.error = `Invalid announcement data length: ${data.length} < ${minLength}`
      }
      break

    case PACKET_TYPE.DATA:
      result.type = 'message'
      // For messages, we need to check if destination matches our identity
      // The actual message data would need decryption
      result.messageData = data
      // Caller should check if destHash matches their identity's destination hash
      break

    case PACKET_TYPE.LINKREQUEST:
      result.type = 'linkrequest'
      result.linkData = data
      break

    case PACKET_TYPE.PROOF:
      result.type = 'proof'
      result.proofData = data
      break

    default:
      result.type = 'unknown'
      result.data = data
  }

  return result
}

/**
 * Check if a message packet is for a specific identity
 * @param {Object} parsedPacket - The parsed packet from parsePacket()
 * @param {Object} identity - The identity to check against
 * @param {string} appName - The app name
 * @param {Array} aspects - The aspects array
 * @returns {boolean} True if the message is for this identity
 */
export async function isMessageForIdentity(parsedPacket, identity, appName, aspects = []) {
  if (parsedPacket.type !== 'message') {
    return false
  }

  // Calculate what our destination hash would be
  const ourDestHash = await destinationHash(identity, appName, ...aspects)

  // Compare destination hashes
  if (parsedPacket.destHash.length !== ourDestHash.length) {
    return false
  }

  for (let i = 0; i < ourDestHash.length; i++) {
    if (parsedPacket.destHash[i] !== ourDestHash[i]) {
      return false
    }
  }

  return true
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Convert bytes to hex string
 */
export function bytesToHex(bytes) {
  if (!bytes) {
    return ''
  }
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Convert hex string to bytes
 */
export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16)
  }
  return bytes
}

/**
 * Format a hash for display
 */
export function prettyHash(hash) {
  const hex = typeof hash === 'string' ? hash : bytesToHex(hash)
  return `<${hex}>`
}
