/**
 * Reticulum Network Stack (RNS) JavaScript Implementation
 * A clean, functional library for RNS/LXMF/NomadNet communication
 */

import * as ed25519 from '@noble/ed25519'
import { x25519 } from '@noble/curves/ed25519'
import { randomBytes, createHash } from 'crypto'

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
export function sha256(data) {
  return new Uint8Array(createHash('sha256').update(data).digest())
}

/**
 * Compute truncated hash (first 128 bits of SHA-256)
 */
export function truncatedHash(data) {
  return sha256(data).slice(0, TRUNCATED_HASHLENGTH / 8)
}

/**
 * Generate a random hash
 */
export function getRandomHash() {
  return truncatedHash(randomBytes(TRUNCATED_HASHLENGTH / 8))
}

// =============================================================================
// Identity Management
// =============================================================================

/**
 * Generate a new identity with X25519 and Ed25519 keypairs
 */
export async function generateIdentity() {
  // Generate X25519 keypair for encryption
  const encPrivate = x25519.utils.randomPrivateKey()
  const encPublic = x25519.getPublicKey(encPrivate)

  // Generate Ed25519 keypair for signing
  const sigPrivate = ed25519.utils.randomPrivateKey()
  const sigPublic = await ed25519.getPublicKeyAsync(sigPrivate)

  // Combine public keys and compute identity hash
  const publicKey = new Uint8Array(64)
  publicKey.set(encPublic, 0)
  publicKey.set(sigPublic, 32)

  const hash = truncatedHash(publicKey)
  const hexhash = bytesToHex(hash)

  return {
    encPrivate,
    encPublic,
    sigPrivate,
    sigPublic,
    publicKey,
    hash,
    hexhash
  }
}

/**
 * Get the combined private key bytes for storage
 */
export function getPrivateKeyBytes(identity) {
  const privateKey = new Uint8Array(64)
  privateKey.set(identity.encPrivate, 0)
  privateKey.set(identity.sigPrivate, 32)
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

  // Derive public keys
  const encPublic = x25519.getPublicKey(encPrivate)
  const sigPublic = await ed25519.getPublicKeyAsync(sigPrivate)

  // Combine public keys and compute hash
  const publicKey = new Uint8Array(64)
  publicKey.set(encPublic, 0)
  publicKey.set(sigPublic, 32)

  const hash = truncatedHash(publicKey)
  const hexhash = bytesToHex(hash)

  return {
    encPrivate,
    encPublic,
    sigPrivate,
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
  return await ed25519.signAsync(data, identity.sigPrivate)
}

/**
 * Verify signature with identity
 */
export async function verify(identity, signature, data) {
  return await ed25519.verifyAsync(signature, data, identity.sigPublic)
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
export function destinationHash(identity, appName, ...aspects) {
  // Create name hash from expanded name
  const expandedName = expandDestinationName(null, appName, ...aspects)
  const nameBytes = new TextEncoder().encode(expandedName)
  const nameHash = sha256(nameBytes).slice(0, NAME_HASH_LENGTH / 8)

  // Build address hash material
  let addrHashMaterial = nameHash

  if (identity !== null) {
    addrHashMaterial = new Uint8Array(nameHash.length + identity.hash.length)
    addrHashMaterial.set(nameHash, 0)
    addrHashMaterial.set(identity.hash, nameHash.length)
  }

  // Return truncated hash
  return truncatedHash(addrHashMaterial)
}

// =============================================================================
// Announcement Creation
// =============================================================================

/**
 * Create an announcement packet
 */
export async function createAnnouncement(identity, appName, aspects = [], displayName = null) {
  // Calculate destination hash
  const destHash = destinationHash(identity, appName, ...aspects)

  // Calculate name hash
  const expandedName = expandDestinationName(null, appName, ...aspects)
  const nameBytes = new TextEncoder().encode(expandedName)
  const nameHash = sha256(nameBytes).slice(0, NAME_HASH_LENGTH / 8)

  // Generate random hash with timestamp
  const randomPart = randomBytes(5)
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
// Utility Functions
// =============================================================================

/**
 * Convert bytes to hex string
 */
export function bytesToHex(bytes) {
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
