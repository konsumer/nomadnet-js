/**
 * Lightweight Reticulum library for JavaScript
 */

// prettier-ignore
import {
  aesCbcDecrypt,
  aesCbcEncrypt,
  bytesToHex,
  concatBytes,
  ed25519Sign,
  ed25519Validate,
  equalBytes,
  getIdentityFromBytes,
  hexToBytes,
  hkdf,
  hmacSha256,
  identityCreate,
  msgpack,
  msgunpack,
  randomBytes,
  sha256,
  x25519Exchange,
  x25519PrivateCreateNew,
  x25519PublicForPrivate
} from './utils.js'

export { identityCreate, getIdentityFromBytes }
export const ratchetCreateNew = x25519PrivateCreateNew
export const ratchetGetPublic = x25519PublicForPrivate

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

const encoder = new TextEncoder()
const decoder = new TextDecoder()

export function getDestinationHash(identity, appName, ...aspects) {
  const identityData = new Uint8Array(64)
  identityData.set(identity.public.encrypt)
  identityData.set(identity.public.sign, 32)
  const identityHash = sha256(identityData).slice(0, 16)
  let fullName = appName
  for (const aspect of aspects) {
    fullName += '.' + aspect
  }
  const nameHash = sha256(encoder.encode(fullName)).slice(0, 10)
  const addrHashMaterial = new Uint8Array(26)
  addrHashMaterial.set(nameHash)
  addrHashMaterial.set(identityHash, 10)
  return sha256(addrHashMaterial).slice(0, 16)
}

export function getMessageId(packet) {
  const headerType = (packet.raw[0] >> 6) & 0b11
  const hashablePart = new Uint8Array(packet.raw.length - (headerType === 1 ? 18 : 2) + 1)
  hashablePart[0] = packet.raw[0] & 0b00001111
  if (headerType === 1) {
    hashablePart.set(packet.raw.slice(18), 1)
  } else {
    hashablePart.set(packet.raw.slice(2), 1)
  }
  return sha256(hashablePart)
}

export function packetPack(packet) {
  let headerByte = 0

  // Build header byte
  if (packet.ifacFlag) headerByte |= 0b10000000
  if (packet.headerType) headerByte |= 0b01000000
  if (packet.contextFlag) headerByte |= 0b00100000
  if (packet.propagationType) headerByte |= 0b00010000
  headerByte |= ((packet.destinationType || 0) << 2) & 0b00001100
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

export function packetUnpack(packetBytes) {
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

export function buildAnnounce(identity, destination, fullName = 'lxmf.delivery', ratchetPub = null, appData = null) {
  const nameHash = sha256(encoder.encode(fullName)).slice(0, 10)
  const randomHash = randomBytes(10)

  // Determine effective ratchet and context
  let ratchetForSigning, contextVal, hasExplicitRatchet
  if (ratchetPub === null || equalBytes(ratchetPub, identity.public.encrypt)) {
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
    appDataBytes = typeof appData === 'string' ? encoder.encode(appData) : appData
  }

  // Build signed data
  const publicKeys = concatBytes(identity.public.encrypt, identity.public.sign)
  const signedData = concatBytes(
    destination,
    publicKeys,
    nameHash,
    randomHash,
    ratchetForSigning, // Empty or explicit ratchet
    appDataBytes
  )

  const signature = ed25519Sign(signedData, identity.private.sign)

  // Build payload (data part of packet)
  let payload
  if (hasExplicitRatchet) {
    // Include explicit ratchet in payload
    payload = concatBytes(publicKeys, nameHash, randomHash, ratchetPub, signature, appDataBytes)
  } else {
    // No explicit ratchet in payload
    payload = concatBytes(publicKeys, nameHash, randomHash, signature, appDataBytes)
  }

  return packetPack({
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
  const signedData = concatBytes(packet.destinationHash, publicKey, announce.nameHash, announce.randomHash, ratchetForSigning, announce.appData)

  // Verify signature
  announce.valid = ed25519Validate(announce.keyPubSignature, announce.signature, signedData)
  announce.destinationHash = packet.destinationHash

  return announce
}

export function buildProof(identity, packet, messageId = null) {
  if (!messageId) {
    messageId = getMessageId(packet)
  }

  // Sign the full message ID
  const signature = ed25519Sign(messageId, identity.private.sign)

  // Explicit proof: full hash + signature (no version byte)
  const proofData = new Uint8Array([...messageId, ...signature])

  return packetPack({
    destinationHash: messageId.slice(0, 16), // First 16 bytes of message ID
    packetType: PACKET_PROOF,
    destinationType: 0,
    hops: 0,
    context: 0,
    contextFlag: false,
    data: proofData
  })
}

export function proofValidate(packet, identity, fullPacketHash) {
  if (packet.data.length === 96) {
    // Explicit proof: 32-byte hash + 64-byte signature
    const proofHash = packet.data.slice(0, 32)
    const signature = packet.data.slice(32, 96)

    // Verify the hash matches what we expect
    const hashMatch = proofHash.every((byte, i) => byte === fullPacketHash[i])
    if (!hashMatch) {
      return false
    }

    // Verify the signature
    return ed25519Validate(identity.public.sign, signature, fullPacketHash)
  } else if (packet.data.length === 64) {
    // Implicit proof: just 64-byte signature
    const signature = packet.data
    return ed25519Validate(identity.public.sign, signature, fullPacketHash)
  } else if (packet.data.length === 65) {
    // Old format: version byte + 64-byte signature
    const signature = packet.data.slice(1, 65)
    return ed25519Validate(identity.public.sign, signature, fullPacketHash)
  } else {
    return false
  }
}

export function buildData(identity, recipientAnnounce, plaintext) {
  // Calculate recipient identity hash for HKDF
  const recipientIdentityData = concatBytes(recipientAnnounce.keyPubEncrypt, recipientAnnounce.keyPubSignature)
  const recipientIdentityHash = sha256(recipientIdentityData).slice(0, 16)

  // Generate ephemeral keypair
  const ephemeralKey = randomBytes(32)
  const ephemeralPub = x25519PublicForPrivate(ephemeralKey)

  // Perform X25519 key exchange with recipient's ratchet
  const sharedKey = x25519Exchange(ephemeralKey, recipientAnnounce.ratchetPub)

  // Derive encryption and signing keys
  const derivedKey = hkdf(64, sharedKey, recipientIdentityHash, new Uint8Array(0))
  const signingKey = derivedKey.slice(0, 32)
  const encryptionKey = derivedKey.slice(32, 64)

  // Encrypt the plaintext
  const iv = randomBytes(16)
  const ciphertext = aesCbcEncrypt(encryptionKey, iv, plaintext)

  // Create HMAC over IV + ciphertext
  const signedData = concatBytes(iv, ciphertext)
  const hmac = hmacSha256(signingKey, signedData)

  // Build token: ephemeralPub + IV + ciphertext + HMAC
  const token = concatBytes(ephemeralPub, iv, ciphertext, hmac)

  return packetPack({
    destinationHash: recipientAnnounce.destinationHash,
    packetType: PACKET_DATA,
    destinationType: 0,
    hops: 0,
    context: 0,
    contextFlag: false,
    data: token
  })
}

export function messageDecrypt(packet, identity, ratchets = []) {
  const identityData = new Uint8Array(64)
  identityData.set(identity.public.encrypt)
  identityData.set(identity.public.sign, 32)
  const identityHash = sha256(identityData).slice(0, 16)
  const ciphertextToken = packet.data

  if (!ciphertextToken || ciphertextToken.length <= 49) {
    return null
  }

  // Fix: slice(0, 32) instead of slice(1, 33)
  const peerPubBytes = ciphertextToken.slice(0, 32)
  const ciphertext = ciphertextToken.slice(32)

  // Fix: use identity.private.encrypt for key exchange
  ratchets.push(identity.private.encrypt)

  for (const ratchet of ratchets) {
    if (ratchet.length !== 32) {
      continue
    }

    try {
      const sharedKey = x25519Exchange(ratchet, peerPubBytes)
      const derivedKey = hkdf(64, sharedKey, identityHash, new Uint8Array(0))
      const signingKey = derivedKey.slice(0, 32)
      const encryptionKey = derivedKey.slice(32)

      if (ciphertext.length <= 48) {
        continue
      }

      const receivedHmac = ciphertext.slice(-32)
      const signedData = ciphertext.slice(0, -32)
      const expectedHmac = hmacSha256(signingKey, signedData)

      if (!equalBytes(receivedHmac, expectedHmac)) {
        continue
      }

      const iv = ciphertext.slice(0, 16)
      const ciphertextData = ciphertext.slice(16, -32)

      const plaintext = aesCbcDecrypt(encryptionKey, iv, ciphertextData)
      return plaintext
    } catch (e) {
      console.error(e)
      continue
    }
  }

  return null
}

export function decodeLxmfMessage(plaintext) {
  const senderHash = plaintext.slice(0, 16)
  const signature = plaintext.slice(16, 80)
  const payload = plaintext.slice(80)
  const [ts, title, content, fields] = msgunpack(payload)
  return {
    ts,
    senderHash,
    signature,
    payload,
    title: decoder.decode(title),
    content: decoder.decode(content),
    fields
  }
}

export function validateLxmfMessage(decodedMessage, myDest, senderPublicSignKey) {
  const hashedPart = new Uint8Array([...myDest, ...decodedMessage.senderHash, ...decodedMessage.payload])
  const messageHash = sha256(hashedPart)
  const signedData = new Uint8Array([...hashedPart, ...messageHash])
  return ed25519Validate(senderPublicSignKey, decodedMessage.signature, signedData)
}

export function encodeLxmfMessage(senderIdentity, senderDest, recipientAnnounce, message) {
  const recipientDest = recipientAnnounce.destinationHash
  let { timestamp, title, content, ...fields } = message
  timestamp = timestamp || Math.floor(Date.now() / 1000)
  title = title ? encoder.encode(title) : new Uint8Array(0)
  content = content ? encoder.encode(content) : new Uint8Array(0)
  const payload = msgpack([timestamp, title, content, fields])
  const hashedPart = new Uint8Array([...recipientDest, ...senderDest, ...payload])
  const messageHash = sha256(hashedPart)
  const signedData = new Uint8Array([...hashedPart, ...messageHash])
  const signature = ed25519Sign(signedData, senderIdentity.private.sign)
  const lxmfMessage = new Uint8Array([...senderDest, ...signature, ...payload])
  return buildData(senderIdentity, recipientAnnounce, lxmfMessage)
}
