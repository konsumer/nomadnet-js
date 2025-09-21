import * as msgpack from 'msgpackr'
import { ed25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256, sha512 } from '@noble/hashes/sha2.js'
import { randomBytes } from '@noble/hashes/utils.js'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

// Constants from Reticulum
export const TRUNCATED_HASHLENGTH = 16
export const HASHLENGTH = 32
export const SIGLENGTH = 64

export const MTU = 500
export const MAX_QUEUED_ANNOUNCES = 16384
export const QUEUED_ANNOUNCE_LIFE = 60 * 60 * 24

// HDLC constants
export const HDLC_FLAG = 0x7e
export const HDLC_ESC = 0x7d
export const HDLC_ESC_MASK = 0x20

// Reticulum constants
export const HEADER_MINSIZE = 2 + 1 + 1
export const HEADER_MAXSIZE = 2 + 2 + 1 + 1
export const IFAC_MIN_SIZE = 1
export const IFAC_OVERHEAD = 1 + 1 + HASHLENGTH // Identity indentifier, IFAC flag, IFAC value

// Packet types
export const PACKET_DATA = 0x00
export const PACKET_ANNOUNCE = 0x01
export const PACKET_LINKREQUEST = 0x02
export const PACKET_PROOF = 0x03

// Header types
export const HEADER_1 = 0x00
export const HEADER_2 = 0x01

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
export const CONTEXT_KEEPALIVE = 0x0f

// Destination types
export const DESTINATION_SINGLE = 0x00
export const DESTINATION_GROUP = 0x01
export const DESTINATION_PLAIN = 0x02
export const DESTINATION_LINK = 0x03

// Packet flags
export const FLAG_SPLIT = 0x01
export const FLAG_TRANSPORT = 0x02

// Cryptographic constants used in Reticulum
const reticulumHkdfSalt = new Uint8Array([0xd3, 0x49, 0xf6, 0xd6, 0xe7, 0x89, 0xe6, 0x4a, 0xd4, 0xd3, 0x8f, 0x80, 0xea, 0x56, 0xed, 0x54, 0xde, 0x31, 0x84, 0xc1, 0xae, 0xab, 0xd8, 0x8c, 0x82, 0xc8, 0xda, 0xd5, 0xf1, 0x18, 0x0b, 0xa3])
const reticulumHkdfInfo = encoder.encode('Reticulum/Expand')

// Announce types
export const ANNOUNCE_CAP = 0x00
export const ANNOUNCE_PATH = 0x01

// Identity and crypto functions
export function generateIdentity() {
  const privateKey = ed25519.utils.randomSecretKey()
  const publicKey = ed25519.getPublicKey(privateKey)

  return {
    privateKey,
    publicKey,
    hash: getIdentityHash(publicKey)
  }
}

export function getIdentityHash(publicKey) {
  const hash = sha256(publicKey)
  return hash.slice(0, TRUNCATED_HASHLENGTH)
}

export function getDestinationHash(identity, appName, aspects) {
  const nameHash = sha256(encoder.encode(appName))
  const aspectsData = encoder.encode(aspects || '')

  const combined = new Uint8Array(nameHash.length + aspectsData.length + identity.publicKey.length)
  combined.set(nameHash, 0)
  combined.set(aspectsData, nameHash.length)
  combined.set(identity.publicKey, nameHash.length + aspectsData.length)

  const fullHash = sha256(combined)
  return fullHash.slice(0, TRUNCATED_HASHLENGTH)
}

export function signData(privateKey, data) {
  return ed25519.sign(data, privateKey)
}

export function verifySignature(publicKey, data, signature) {
  return ed25519.verify(signature, data, publicKey)
}

// Packet building functions
export function buildPacketHeader(flags) {
  const header = new Uint8Array(2)

  // Byte 1: [IFAC Flag], [Header Type], [Propagation Type], [Destination Type] and [Packet Type]
  header[0] = (flags.ifac ? 0x80 : 0) | (flags.headerType << 6) | (flags.propagationType << 4) | (flags.destinationType << 2) | flags.packetType

  // Byte 2: Hops
  header[1] = flags.hops || 0

  return header
}

export function buildAnnouncePacket(identity, appName, aspects = '') {
  const destinationHash = getDestinationHash(identity, appName, aspects)

  // Build announce data
  const nameData = encoder.encode(appName)
  const aspectsData = encoder.encode(aspects)

  // Announce data structure: publicKey + nameLength (1 byte) + name + aspectsLength (1 byte) + aspects
  const announceData = new Uint8Array(identity.publicKey.length + 1 + nameData.length + 1 + aspectsData.length)

  let offset = 0
  announceData.set(identity.publicKey, offset)
  offset += identity.publicKey.length

  announceData[offset] = nameData.length
  offset += 1

  announceData.set(nameData, offset)
  offset += nameData.length

  announceData[offset] = aspectsData.length
  offset += 1

  announceData.set(aspectsData, offset)

  // Sign the announce data
  const signature = signData(identity.privateKey, announceData)

  // Build complete packet
  const header = buildPacketHeader({
    ifac: false,
    headerType: HEADER_1,
    propagationType: 0, // broadcast
    destinationType: DESTINATION_SINGLE,
    packetType: PACKET_ANNOUNCE,
    hops: 0
  })

  const context = new Uint8Array([ANNOUNCE_CAP])

  // Packet structure: [HEADER] [DESTINATION_HASH] [CONTEXT] [PUBLIC_KEY + SIGNATURE + NAME/ASPECTS]
  const packet = new Uint8Array(header.length + destinationHash.length + context.length + announceData.length + signature.length)

  offset = 0
  packet.set(header, offset)
  offset += header.length

  packet.set(destinationHash, offset)
  offset += destinationHash.length

  packet.set(context, offset)
  offset += context.length

  packet.set(announceData, offset)
  offset += announceData.length

  packet.set(signature, offset)

  return packet
}

export function parsePacketHeader(data) {
  if (data.length < 2) throw new Error('Packet too small for header')

  const byte1 = data[0]
  const byte2 = data[1]

  return {
    ifac: (byte1 & 0x80) !== 0,
    headerType: (byte1 >> 6) & 0x01,
    propagationType: (byte1 >> 4) & 0x03,
    destinationType: (byte1 >> 2) & 0x03,
    packetType: byte1 & 0x03,
    hops: byte2
  }
}

export function parsePacket(data) {
  const header = parsePacketHeader(data)
  let offset = 2

  // Skip IFAC if present
  if (header.ifac) {
    // For now, we'll skip IFAC parsing
    throw new Error('IFAC parsing not implemented')
  }

  // Parse addresses based on header type
  let destination, source

  if (header.headerType === HEADER_1) {
    destination = data.slice(offset, offset + TRUNCATED_HASHLENGTH)
    offset += TRUNCATED_HASHLENGTH
  } else if (header.headerType === HEADER_2) {
    destination = data.slice(offset, offset + TRUNCATED_HASHLENGTH)
    offset += TRUNCATED_HASHLENGTH
    source = data.slice(offset, offset + TRUNCATED_HASHLENGTH)
    offset += TRUNCATED_HASHLENGTH
  }

  // Context byte
  const context = data[offset]
  offset += 1

  // Remaining data
  const payload = data.slice(offset)

  return {
    header,
    destination,
    source,
    context,
    payload
  }
}

export function parseAnnouncePacket(packet) {
  const parsed = parsePacket(packet)

  if (parsed.header.packetType !== PACKET_ANNOUNCE) {
    throw new Error('Not an announce packet')
  }

  // Parse announce payload
  let offset = 0
  const payload = parsed.payload

  // Extract public key (32 bytes for Ed25519)
  const publicKey = payload.slice(offset, offset + 32)
  offset += 32

  // Extract name length and name
  const nameLength = payload[offset]
  offset += 1

  const nameData = payload.slice(offset, offset + nameLength)
  const name = decoder.decode(nameData)
  offset += nameLength

  // Extract aspects length and aspects
  const aspectsLength = payload[offset]
  offset += 1

  const aspectsData = payload.slice(offset, offset + aspectsLength)
  const aspects = decoder.decode(aspectsData)
  offset += aspectsLength

  // Extract signature (should be remaining 64 bytes)
  const signature = payload.slice(offset, offset + SIGLENGTH)

  // Verify signature
  // The announce data that was signed is everything before the signature
  const announceData = payload.slice(0, offset)
  const isValid = verifySignature(publicKey, announceData, signature)

  return {
    destination: parsed.destination,
    publicKey,
    name,
    aspects,
    signature,
    isValid
  }
}

// LXMF functions
export function buildLxmfMessage(sourceIdentity, destinationHash, content, title = '', fields = {}) {
  const timestamp = Date.now() / 1000

  // Pack payload using msgpack
  const payload = msgpack.pack([timestamp, content || '', title || '', fields || {}])

  // Build message structure
  const message = {
    destination: destinationHash,
    source: sourceIdentity.hash,
    payload
  }

  // Create message ID (hash of destination + source + payload)
  const messageIdData = new Uint8Array(destinationHash.length + sourceIdentity.hash.length + payload.length)

  let offset = 0
  messageIdData.set(destinationHash, offset)
  offset += destinationHash.length
  messageIdData.set(sourceIdentity.hash, offset)
  offset += sourceIdentity.hash.length
  messageIdData.set(payload, offset)

  const messageId = sha256(messageIdData)

  // Sign the message (destination + source + payload + messageId)
  const signData = new Uint8Array(destinationHash.length + sourceIdentity.hash.length + payload.length + messageId.length)

  offset = 0
  signData.set(destinationHash, offset)
  offset += destinationHash.length
  signData.set(sourceIdentity.hash, offset)
  offset += sourceIdentity.hash.length
  signData.set(payload, offset)
  offset += payload.length
  signData.set(messageId, offset)

  const signature = ed25519.sign(signData, sourceIdentity.privateKey)

  return {
    destination: destinationHash,
    source: sourceIdentity.hash,
    signature,
    payload,
    messageId
  }
}

export function parseLxmfMessage(data) {
  // Unpack the LXMF message structure
  const unpacked = msgpack.unpack(new Uint8Array(data))

  if (!Array.isArray(unpacked) || unpacked.length !== 4) {
    throw new Error('Invalid LXMF message structure')
  }

  const [destination, source, signature, payload] = unpacked

  // Unpack payload
  const payloadData = msgpack.unpack(payload)

  if (!Array.isArray(payloadData) || payloadData.length !== 4) {
    throw new Error('Invalid LXMF payload structure')
  }

  const [timestamp, content, title, fields] = payloadData

  // Convert destination and source to Uint8Array if they're Buffers
  const destArray = new Uint8Array(destination)
  const srcArray = new Uint8Array(source)
  const payloadArray = new Uint8Array(payload)

  // Calculate message ID
  const messageIdData = new Uint8Array(destArray.length + srcArray.length + payloadArray.length)

  let offset = 0
  messageIdData.set(destArray, offset)
  offset += destArray.length
  messageIdData.set(srcArray, offset)
  offset += srcArray.length
  messageIdData.set(payloadArray, offset)

  const messageId = sha256(messageIdData)

  return {
    destination: destArray,
    source: srcArray,
    signature: new Uint8Array(signature),
    messageId,
    timestamp,
    content,
    title,
    fields
  }
}

// Link establishment functions
export function buildLinkRequestPacket(sourceIdentity, destinationHash, linkId) {
  const header = buildPacketHeader({
    ifac: false,
    headerType: HEADER_1,
    propagationType: 0, // broadcast
    destinationType: DESTINATION_SINGLE,
    packetType: PACKET_LINKREQUEST,
    hops: 0
  })

  // Link request contains public key and link ID
  const linkData = new Uint8Array(sourceIdentity.publicKey.length + linkId.length)
  linkData.set(sourceIdentity.publicKey, 0)
  linkData.set(linkId, sourceIdentity.publicKey.length)

  const packet = new Uint8Array(
    header.length +
      destinationHash.length +
      1 + // context
      linkData.length
  )

  let offset = 0
  packet.set(header, offset)
  offset += header.length

  packet.set(destinationHash, offset)
  offset += destinationHash.length

  packet[offset] = CONTEXT_NONE
  offset += 1

  packet.set(linkData, offset)

  return packet
}

// HDLC framing functions
export function hdlcEncode(data) {
  const encoded = []

  encoded.push(HDLC_FLAG)

  for (const byte of data) {
    if (byte === HDLC_FLAG || byte === HDLC_ESC) {
      encoded.push(HDLC_ESC)
      encoded.push(byte ^ HDLC_ESC_MASK)
    } else {
      encoded.push(byte)
    }
  }

  encoded.push(HDLC_FLAG)

  return new Uint8Array(encoded)
}

export function hdlcDecode(data) {
  const decoded = []
  let escaped = false
  let inFrame = false

  for (const byte of data) {
    if (byte === HDLC_FLAG) {
      if (inFrame && decoded.length > 0) {
        return new Uint8Array(decoded)
      }
      inFrame = true
      decoded.length = 0
    } else if (inFrame) {
      if (escaped) {
        decoded.push(byte ^ HDLC_ESC_MASK)
        escaped = false
      } else if (byte === HDLC_ESC) {
        escaped = true
      } else {
        decoded.push(byte)
      }
    }
  }

  return null
}

// Identity storage functions
export function saveIdentity(identity) {
  // Pack identity data with msgpack
  // Format: [privateKey, publicKey]
  return msgpack.pack([identity.privateKey, identity.publicKey])
}

export function parseIdentityBytes(data) {
  try {
    // Unpack the msgpack data
    const unpacked = msgpack.unpack(data)

    if (!Array.isArray(unpacked) || unpacked.length !== 2) {
      throw new Error('Invalid identity format')
    }

    const [privateKey, publicKey] = unpacked

    // Convert to Uint8Array if needed
    const privKey = new Uint8Array(privateKey)
    const pubKey = new Uint8Array(publicKey)

    // Validate key sizes
    if (privKey.length !== 32 || pubKey.length !== 32) {
      throw new Error('Invalid key sizes in identity')
    }

    return {
      privateKey: privKey,
      publicKey: pubKey,
      hash: getIdentityHash(pubKey)
    }
  } catch (error) {
    throw new Error(`Failed to parse identity: ${error.message}`)
  }
}
