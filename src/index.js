import * as msgpack from 'msgpackr'
import { ed25519 } from '@noble/curves/ed25519.js'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

const reticulumHkdfSalt = new Uint8Array([0xd3, 0x49, 0xf6, 0xd6, 0xe7, 0x89, 0xe6, 0x4a, 0xd4, 0xd3, 0x8f, 0x80, 0xea, 0x56, 0xed, 0x54, 0xde, 0x31, 0x84, 0xc1, 0xae, 0xab, 0xd8, 0x8c, 0x82, 0xc8, 0xda, 0xd5, 0xf1, 0x18, 0x0b, 0xa3])
const reticulumHkdfInfo = encoder.encode('Reticulum/Link')

// Create a LXMF message
export async function lxmfLinkMessage({ content, title, ...fields }, destinationId, sourceId, hopsLimit = 10) {
  const destinationHashBytes = destinationId.keysetHash.slice(0, 16)
  const sourceHashBytes = sourceId.keysetHash.slice(0, 16)
  const payload = msgpack.pack([Date.now() / 1000, content || '', title || '', fields])
  const messageId = new Uint8Array(await crypto.subtle.digest('SHA-256', concatBytes(destinationHashBytes, sourceHashBytes, payload)))
  const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', sourceId.ed25519PrivateKey, concatBytes(destinationHashBytes, sourceHashBytes, payload, messageId)))
  const unencryptedReticulumPayload = concatBytes(destinationHashBytes, sourceHashBytes, signature, payload)
  const { aesKey, hmacKey, ephemeralPublicKeyBuffer } = await deriveEncryptionKeys(destinationId.x25519PublicKey)
  const { iv, encryptedPayload, hmac } = await encryptAndAuthenticate(unencryptedReticulumPayload, aesKey, hmacKey)
  const headerBytes = buildReticulumHeader({
    ifacFlag: 0,
    headerType: 0,
    contextFlag: 1, // Link
    propagationType: 2, // Transport
    destinationType: 0, // Single
    packetType: 3, // Link Packet
    hopsLimit
  })
  return concatBytes(headerBytes, [0x00], ephemeralPublicKeyBuffer, iv, encryptedPayload, hmac)
}

// Generate the crypto-stuff (keys, etc) needed by a message "source" (user)
export async function generateSourceId() {
  const ed25519KeyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const x25519KeyPair = await crypto.subtle.generateKey({ name: 'X25519', namedCurve: 'X25519' }, true, ['deriveBits'])
  const ed25519PublicKeyBuffer = new Uint8Array(await crypto.subtle.exportKey('raw', ed25519KeyPair.publicKey))
  const x25519PublicKeyBuffer = new Uint8Array(await crypto.subtle.exportKey('raw', x25519KeyPair.publicKey))
  const keyset = concatBytes(x25519PublicKeyBuffer, ed25519PublicKeyBuffer)
  const keysetHash = new Uint8Array(await crypto.subtle.digest('SHA-256', keyset))
  const ed25519PrivateKey = ed25519KeyPair.privateKey
  const x25519PrivateKey = x25519KeyPair.privateKey
  const x25519PublicKey = x25519KeyPair.publicKey
  return { ed25519PrivateKey, x25519PrivateKey, x25519PublicKey, keysetHash }
}

// Parse any Reticulum packet and return structured data (first stage)
export function parsePacket(packetBytes) {
  // Remove HDLC framing if present (0x7e delimiters)
  let packet = packetBytes
  if (packet[0] === 0x7e && packet[packet.length - 1] === 0x7e) {
    packet = packet.slice(1, -1)
  }

  // Parse header bytes
  const byte1 = packet[0]
  const byte2 = packet[1]

  // Byte 1 breakdown
  const ifacFlag = (byte1 >> 7) & 1
  const headerType = (byte1 >> 6) & 1
  const contextFlag = (byte1 >> 4) & 1
  const propagationType = (byte1 >> 2) & 3
  const destinationType = byte1 & 3

  // Byte 2 breakdown
  const hops = (byte2 >> 3) & 31
  const packetType = byte2 & 7

  // Determine address count based on header type
  const addressCount = headerType === 0 ? 1 : 2
  const addressesSize = addressCount * 16

  // Extract addresses
  let destination = null
  let source = null

  if (addressCount === 1) {
    destination = packet.slice(2, 18)
  } else {
    destination = packet.slice(2, 18)
    source = packet.slice(18, 34)
  }

  // Extract context byte if present
  let context = null
  let dataStart = 2 + addressesSize
  if (contextFlag) {
    context = packet[dataStart]
    dataStart += 1
  }

  // Extract data payload
  const dataPayload = packet.slice(dataStart)

  // Return base packet info
  return {
    type: ['data', 'announce', 'link_request', 'proof'][packetType] || `unknown_${packetType}`,
    packetType,
    ifacFlag,
    headerType,
    contextFlag,
    propagationType: ['broadcast', 'transport', 'reserved', 'reserved'][propagationType],
    destinationType: ['single', 'group', 'plain', 'link'][destinationType],
    hops,
    destination,
    source,
    context,
    dataPayload,
    raw: packet
  }
}

// Check if a packet is addressed to a specific identity
export function isPacketForMe(packet, myIdentity) {
  if (!myIdentity?.keysetHash || !packet?.destination) {
    return false
  }

  // Compare first 16 bytes of our keyset hash with destination
  const myAddress = myIdentity.keysetHash.slice(0, 16)
  return packet.destination.every((byte, i) => byte === myAddress[i])
}

// Parse data packet (second stage) - for encrypted/decrypted message data
export async function parseDataPacket(packet, recipientIdentity = null, senderIdentity = null) {
  if (packet.type !== 'data') {
    throw new Error(`Expected data packet, got ${packet.type}`)
  }

  const result = { ...packet }

  // Check if this is a broadcast data packet containing announce data
  // These are data packets (type 0) sent to group destinations that contain announce information
  if (packet.destinationType === 'group' && packet.propagationType === 'broadcast' && packet.dataPayload.length >= 144) {
    // Try to parse as announce data
    const announceData = await parseAnnouncePayload(packet.dataPayload)
    if (announceData) {
      result.announce = announceData
      result.subType = 'announce' // Mark as data packet containing announce
      return result
    }
  }

  if (packet.destinationType === 'link') {
    // Link data packets are encrypted - need keys to decrypt
    result.encrypted = true
    result.encryptedData = packet.dataPayload

    // TODO: If we have the keys, decrypt the data
    if (recipientIdentity && senderIdentity) {
      // Future: Implement decryption
      // result.decryptedData = await decryptLinkData(packet.dataPayload, recipientIdentity, senderIdentity)
    }
  } else if (packet.destinationType === 'plain') {
    // Plain packets are unencrypted
    result.plainData = packet.dataPayload
  } else {
    // Single/group packets may be encrypted or contain other data
    result.data = packet.dataPayload
  }

  return result
}

// Parse announce packet (second stage)
export async function parseAnnouncePacket(packet) {
  if (packet.type !== 'announce' && packet.type !== 'data') {
    throw new Error(`Expected announce or data packet, got ${packet.type}`)
  }

  // For data packets containing announce, parse the payload
  if (packet.type === 'data') {
    const parsed = await parseDataPacket(packet)
    if (!parsed.announce) {
      throw new Error('Data packet does not contain announce information')
    }
    return parsed.announce
  }

  // For actual announce packets (type 1), parse directly
  return await parseAnnouncePayload(packet.dataPayload)
}

// Parse announce payload from raw data
async function parseAnnouncePayload(dataPayload) {
  // Announce data structure (not msgpack, but raw binary):
  // [destination_hash 16] [public_key 32] [name_hash 16] [random_hash 16] [signature 64] [app_data variable]

  if (dataPayload.length < 144) {
    // Not enough data for a valid announce
    return null
  }

  // Extract the components
  const destinationHash = dataPayload.slice(0, 16)
  const ed25519PublicKeyBuffer = dataPayload.slice(16, 48)
  const nameHash = dataPayload.slice(48, 64)
  const randomHash = dataPayload.slice(64, 80)
  const signature = dataPayload.slice(80, 144)
  const appDataBytes = dataPayload.slice(144)
  // Parse app data
  let appData = null
  let appHash = null
  let appRatchet = null

  if (appDataBytes.length >= 40) {
    // Extract the hash and ratchet
    appHash = appDataBytes.slice(0, 32)
    appRatchet = appDataBytes.slice(32, 40)

    // Parse the msgpack portion
    const msgpackData = appDataBytes.slice(40)

    if (msgpackData.length > 0) {
      try {
        // Try to unpack as msgpack
        if (msgpackData[0] === 0xc4 && msgpackData.length > 2) {
          // bin8 format: 0xc4 [1-byte length] [data]
          const binLength = msgpackData[1]
          if (msgpackData.length >= 2 + binLength) {
            const binData = msgpackData.slice(2, 2 + binLength)
            appData = decoder.decode(binData)
          }
        } else {
          // Try standard msgpack unpack
          appData = msgpack.unpack(msgpackData)
        }
      } catch (e) {
        // If msgpack fails, try to extract readable text
        try {
          const text = decoder.decode(msgpackData)
          const match = text.match(/[\x20-\x7E]{3,}/)
          if (match) {
            appData = match[0]
          }
        } catch (e2) {
          appData = msgpackData
        }
      }
    }
  } else if (appDataBytes.length > 0) {
    // For short app data, try msgpack first, then plain text
    try {
      appData = msgpack.unpack(appDataBytes)
    } catch (e) {
      try {
        appData = decoder.decode(appDataBytes)
      } catch (e2) {
        appData = appDataBytes
      }
    }
  }

  // Convert Ed25519 public key to X25519 for encryption
  const x25519PublicKeyBuffer = ed25519.utils.toMontgomery(ed25519PublicKeyBuffer)
  const x25519PublicKey = await crypto.subtle.importKey('raw', x25519PublicKeyBuffer, { name: 'X25519', namedCurve: 'X25519' }, false, [])

  // Compute the keyset hash (used as the destination address)
  const keyset = concatBytes(x25519PublicKeyBuffer, ed25519PublicKeyBuffer)
  const keysetHash = new Uint8Array(await crypto.subtle.digest('SHA-256', keyset))

  return {
    x25519PublicKey,
    keysetHash,
    appData,
    destinationHash,
    nameHash,
    randomHash,
    signature,
    ...(appHash && { appHash }),
    ...(appRatchet && { appRatchet })
  }
}

// Parse link request packet (second stage)
export function parseLinkRequestPacket(packet) {
  if (packet.type !== 'link_request') {
    throw new Error(`Expected link_request packet, got ${packet.type}`)
  }

  // Link request structure:
  // [public_key 32] [signature 64]

  if (packet.dataPayload.length < 96) {
    throw new Error('Invalid link request: too short')
  }

  const publicKey = packet.dataPayload.slice(0, 32)
  const signature = packet.dataPayload.slice(32, 96)
  const additionalData = packet.dataPayload.slice(96)

  return {
    publicKey,
    signature,
    additionalData: additionalData.length > 0 ? additionalData : null
  }
}

// Parse proof packet (second stage)
export function parseProofPacket(packet) {
  if (packet.type !== 'proof') {
    throw new Error(`Expected proof packet, got ${packet.type}`)
  }

  // Proof packets contain cryptographic proofs for path establishment
  // The exact structure depends on the proof type

  return {
    data: packet.dataPayload,
    length: packet.dataPayload.length
    // TODO: Implement detailed proof parsing when we understand the structure better
  }
}

// Used in lxmfLinkMessage to get the keys needed for Reticulum link messages
async function deriveEncryptionKeys(recipientPublicKey) {
  const ephemeralKeyPair = await crypto.subtle.generateKey({ name: 'X25519', namedCurve: 'X25519' }, true, ['deriveBits'])
  const sharedSecretBuffer = await crypto.subtle.deriveBits({ name: 'ECDH', namedCurve: 'X25519', public: recipientPublicKey }, ephemeralKeyPair.privateKey, 256)
  const sharedSecretKey = await crypto.subtle.importKey('raw', sharedSecretBuffer, { name: 'HKDF' }, false, ['deriveKey'])
  const aesKey = await crypto.subtle.deriveKey({ name: 'HKDF', salt: reticulumHkdfSalt, info: reticulumHkdfInfo, hash: 'SHA-256' }, sharedSecretKey, { name: 'AES-CBC', length: 256 }, false, ['encrypt'])
  const hmacKey = await crypto.subtle.deriveKey({ name: 'HKDF', salt: reticulumHkdfSalt, info: reticulumHkdfInfo, hash: 'SHA-256' }, sharedSecretKey, { name: 'HMAC', hash: { name: 'SHA-256' } }, false, ['sign'])
  const ephemeralPublicKeyBuffer = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey))
  return { aesKey, hmacKey, ephemeralPublicKeyBuffer }
}

// Used in lxmfLinkMessage to actually encrypt for Reticulum link messages
async function encryptAndAuthenticate(payloadBytes, aesKey, hmacKey) {
  const iv = crypto.getRandomValues(new Uint8Array(16))
  const encryptedPayload = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: iv }, aesKey, payloadBytes))
  const hmacData = concatBytes(iv, encryptedPayload)
  const hmac = new Uint8Array(await crypto.subtle.sign({ name: 'HMAC', hash: 'SHA-256' }, hmacKey, hmacData))
  return { iv, encryptedPayload, hmac }
}

// Build 2-byte Reticulum header for some options
function buildReticulumHeader({ ifacFlag = 0, headerType = 0, contextFlag = 0, propagationType = 0, destinationType = 0, packetType = 0, hopsLimit = 10 }) {
  if (hopsLimit > 31 || packetType > 7) {
    throw new Error('Invalid header parameters.')
  }
  const byte1 = (ifacFlag << 7) | (headerType << 5) | (contextFlag << 4) | (propagationType << 2) | destinationType
  const byte2 = (hopsLimit << 3) | packetType
  return new Uint8Array([byte1, byte2])
}

// Merge some byte-arrays
const concatBytes = (...arrays) => {
  let totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0)
  let result = new Uint8Array(totalLength)
  let offset = 0
  for (let arr of arrays) {
    result.set(arr, offset)
    offset += arr.length
  }
  return result
}
