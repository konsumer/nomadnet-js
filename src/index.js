/**
 * Lightweight Reticulum library for JavaScript
 */

// prettier-ignore
import {
  hexToBytes,
  bytesToHex,
  randomBytes,
  concatBytes,
  equalBytes,
  
  msgunpack,
  msgpack,
  
  sha256,
  hmacSha256,
  hkdf,

  aesCbcDecrypt,
  aesCbcEncrypt,
  
  ed25519PublicForPrivate,
  ed25519Sign,
  ed25519Validate,
  
  x25519Exchange,
  x25519PublicForPrivate
} from './utils.js'

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

// build packet-bytes from packet object
// build packet-bytes from packet object
export function buildPacket(packet) {
  const { hops = 0, destinationType = DEST_SINGLE, transportType = TRANSPORT_BROADCAST, packetType, context, transportId, destinationHash, data } = packet

  // Set flags byte
  const contextFlag = context !== undefined ? 1 : 0
  const headerType = transportId !== undefined ? 1 : 0

  const flags = (headerType << 6) | (contextFlag << 5) | (transportType << 4) | (destinationType << 2) | packetType

  // Build packet
  const parts = [new Uint8Array([flags, hops])]

  if (headerType === 1) {
    parts.push(transportId)
  }

  parts.push(destinationHash)

  // parsePacket always expects a byte at the context position
  // even when contextFlag is 0, so we must include it
  parts.push(new Uint8Array([context !== undefined ? context : 0]))

  if (data) {
    parts.push(data)
  }

  return concatBytes(...parts)
}

// build packet-bytes for ANNOUNCE
export function buildAnnounce(identityPrivBytes, identityPubBytes, ratchet_pub, app_data, name = 'lxmf.delivery') {
  const destinationHash = getDestinationHash(identityPubBytes, name)

  // Generate random hash
  const randomHash = randomBytes(10)

  // Build name hash
  const nameHash = sha256(encoder.encode(name)).slice(0, 10)

  // Determine if we have an explicit ratchet
  const hasExplicitRatchet = ratchet_pub && !equalBytes(ratchet_pub, identityPubBytes.slice(0, 32))
  const ratchetForSigning = hasExplicitRatchet ? ratchet_pub : new Uint8Array(0)

  // Build announce data before signature
  const appDataBytes = app_data ? (typeof app_data === 'string' ? encoder.encode(app_data) : app_data) : new Uint8Array(0)

  // Build signed data
  const signedData = concatBytes(destinationHash, identityPubBytes, nameHash, randomHash, ratchetForSigning, appDataBytes)

  // Sign with Ed25519 private key (second 32 bytes of identity)
  const signature = ed25519Sign(signedData, identityPrivBytes.slice(32, 64))

  // Build announce data payload
  const dataParts = [
    identityPubBytes, // 64 bytes (encrypt + sign keys)
    nameHash, // 10 bytes
    randomHash // 10 bytes
  ]

  if (hasExplicitRatchet) {
    dataParts.push(ratchet_pub) // 32 bytes
  }

  dataParts.push(signature) // 64 bytes

  if (appDataBytes.length > 0) {
    dataParts.push(appDataBytes)
  }

  const data = concatBytes(...dataParts)

  // Build packet
  return buildPacket({
    hops: 0,
    destinationType: DEST_SINGLE,
    transportType: TRANSPORT_BROADCAST,
    packetType: PACKET_ANNOUNCE,
    context: hasExplicitRatchet ? CONTEXT_NONE : undefined,
    destinationHash,
    data
  })
}

// build packet-bytes for DATA packet
export function buildData(destinationHash, data, context = CONTEXT_NONE, transportId) {
  return buildPacket({
    hops: 0,
    destinationType: DEST_SINGLE,
    transportType: transportId ? TRANSPORT_TRANSPORT : TRANSPORT_BROADCAST,
    packetType: PACKET_DATA,
    context,
    transportId,
    destinationHash,
    data
  })
}

// build packet-bytes for LXMF DATA packet
export function buildLxmf({ sourceHash, senderPrivBytes, receiverPubBytes, receiverRatchetPub, timestamp, title = '', content = '', fields = {} }) {
  const lxmfContent = msgpack([timestamp, encoder.encode(title), encoder.encode(content), fields])

  // Get the destination hash
  const destinationHash = getDestinationHash(receiverPubBytes, 'lxmf.delivery')

  // Calculate message-id: SHA-256(Destination + Source + Payload)
  const messageId = sha256(concatBytes(destinationHash, sourceHash, lxmfContent))

  // Sign: Destination + Source + Payload + message-id
  const messageToSign = concatBytes(destinationHash, sourceHash, lxmfContent, messageId)
  const signature = ed25519Sign(messageToSign, senderPrivBytes.slice(32, 64))

  // Build plaintext: Source + Signature + Payload
  const plaintext = concatBytes(sourceHash, signature, lxmfContent)

  // Encrypt and build packet
  const encrypted = messageEncrypt(plaintext, receiverPubBytes, receiverRatchetPub)
  return buildData(destinationHash, encrypted, CONTEXT_NONE)
}

export function buildProof(dataPacket, identityPrivBytes) {
  // Get the packet hash and destination hash from the data packet
  let packetHash, destinationHash

  if (dataPacket instanceof Uint8Array) {
    const parsed = parsePacket(dataPacket)
    packetHash = parsed.packetHash
    destinationHash = parsed.destinationHash
  } else {
    packetHash = dataPacket.packetHash
    destinationHash = dataPacket.destinationHash
  }

  // Sign the packet hash with the private signing key (32 bytes)
  const signingPrivKey = identityPrivBytes.slice(32, 64)
  const signature = ed25519Sign(packetHash, signingPrivKey)

  // Build proof packet
  return buildPacket({
    hops: 0,
    destinationType: DEST_SINGLE,
    transportType: TRANSPORT_BROADCAST,
    packetType: PACKET_PROOF,
    destinationHash,
    data: signature
  })
}

// Helper function for message encryption (mirrors messageDecrypt)
function messageEncrypt(plaintext, identityPub, ratchet) {
  const identity_hash = sha256(identityPub).slice(0, 16)

  // Generate ephemeral key pair
  const ephemeral_priv = randomBytes(32)
  const ephemeral_pub = x25519PublicForPrivate(ephemeral_priv)

  // Derive shared key
  const peer_pub = ratchet // Use ratchet as the public key to exchange with
  const shared_key = x25519Exchange(ephemeral_priv, peer_pub)
  const derived_key = hkdf(64, shared_key, identity_hash)

  const signing_key = derived_key.slice(0, 32)
  const encryption_key = derived_key.slice(32)

  // Generate IV
  const iv = randomBytes(16)

  // Encrypt plaintext
  const ciphertext_data = aesCbcEncrypt(encryption_key, iv, plaintext)

  // Build data to HMAC (iv + ciphertext_data)
  const signed_data = concatBytes(iv, ciphertext_data)
  const hmac = hmacSha256(signing_key, signed_data)

  // Build final token: ephemeral_pub + iv + ciphertext + hmac
  return concatBytes(ephemeral_pub, iv, ciphertext_data, hmac)
}

// Get the destination hash (address) for a publicc key ([ DECRYPT(32), SIGN(32) ])
export function getDestinationHash(identityPubBytes, fullName = 'lxmf.delivery') {
  const identityHash = sha256(identityPubBytes).slice(0, 16)
  const nameHash = sha256(encoder.encode(fullName)).slice(0, 10)
  const addrHashMaterial = new Uint8Array(26)
  addrHashMaterial.set(nameHash)
  addrHashMaterial.set(identityHash, 10)
  return sha256(addrHashMaterial).slice(0, 16)
}

// Get the message-id for raw packet-bytes
export function getMessageId(packetBytes) {
  const headerType = (packetBytes[0] >> 6) & 0b11
  const hashablePart = new Uint8Array(packetBytes.length - (headerType === 1 ? 18 : 2) + 1)
  hashablePart[0] = packetBytes[0] & 0b00001111
  if (headerType === 1) {
    hashablePart.set(packetBytes.slice(18), 1)
  } else {
    hashablePart.set(packetBytes.slice(2), 1)
  }
  return sha256(hashablePart)
}

export const privateIdentity = () => randomBytes(64) // encrypt, sign

export function publicIdentity(identityPrivBytes) {
  return new Uint8Array([...x25519PublicForPrivate(identityPrivBytes.slice(0, 32)), ...ed25519PublicForPrivate(identityPrivBytes.slice(32, 64))])
}

export const privateRatchet = () => randomBytes(32)
export const publicRatchet = x25519PublicForPrivate

export function parsePacket(packetBytes) {
  const packet = { raw: packetBytes, packetHash: getMessageId(packetBytes) }
  packet['flags'] = packet['raw'][0]
  packet['hops'] = packet['raw'][1]

  packet['headerType'] = (packet['flags'] & 0b01000000) >> 6
  packet['contextFlag'] = (packet['flags'] & 0b00100000) >> 5
  packet['transportType'] = (packet['flags'] & 0b00010000) >> 4
  packet['destinationType'] = (packet['flags'] & 0b00001100) >> 2
  packet['packetType'] = packet['flags'] & 0b00000011

  const DST_LEN = 16 // RNS.Reticulum.TRUNCATED_HASHLENGTH//8

  if (packet['headerType'] == 1) {
    packet['transportId'] = packet['raw'].slice(2, DST_LEN + 2)
    packet['destinationHash'] = packet['raw'].slice(DST_LEN + 2, 2 * DST_LEN + 2)
    packet['context'] = packet['raw'].slice(2 * DST_LEN + 2, 2 * DST_LEN + 3)
    packet['data'] = packet['raw'].slice(2 * DST_LEN + 3)
  } else {
    packet['transportId'] = undefined
    packet['destinationHash'] = packet['raw'].slice(2, DST_LEN + 2)
    packet['context'] = packet['raw'].slice(DST_LEN + 2, DST_LEN + 3)
    packet['data'] = packet['raw'].slice(DST_LEN + 3)
  }

  return packet
}

export function parseAnnounce(packet) {
  const data = packet.data
  const announce = { valid: false }

  // Extract keys (64 bytes total)
  const publicKey = data.slice(0, 64)
  announce.publicKey = publicKey
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

export function parseLxmf(packet, identityPub, ratchets = []) {
  const plaintext = messageDecrypt(packet, identityPub, ratchets)
  if (plaintext) {
    const sourceHash = plaintext.slice(0, 16)
    const signature = plaintext.slice(16, 80)

    const [timestamp, title, content, fields] = msgunpack(plaintext.slice(80))
    return {
      sourceHash,
      signature,
      timestamp,
      title: decoder.decode(title),
      content: decoder.decode(content),
      fields
    }
  }
  return null
}

export function parseProof(packet, identityPub, fullPacketHash) {
  const valid = ed25519Validate(identityPub.slice(32), packet.data.slice(0, 64), fullPacketHash)
  return { valid }
}

export function messageDecrypt(packet, identityPub, ratchets = []) {
  const identity_hash = sha256(identityPub).slice(0, 16)
  const ciphertext_token = packet.data
  if (!ciphertext_token || ciphertext_token.length <= 49) {
    return null
  }

  // Extract ephemeral public key and token
  const peer_pub_bytes = ciphertext_token.slice(0, 32)
  const ciphertext = ciphertext_token.slice(32)

  for (let ratchet of ratchets) {
    if (ratchet.length !== 32) {
      // console.error('invalid ratchet length')
      continue
    }
    try {
      const shared_key = x25519Exchange(ratchet, peer_pub_bytes)
      const derived_key = hkdf(64, shared_key, identity_hash)
      const signing_key = derived_key.slice(0, 32)
      const encryption_key = derived_key.slice(32)
      const received_hmac = ciphertext.slice(-32)
      const signed_data = ciphertext.slice(0, -32)
      const expected_hmac = hmacSha256(signing_key, signed_data)
      if (!equalBytes(expected_hmac, received_hmac)) {
        // console.error('hmac fail', expected_hmac, received_hmac)
        continue
      }
      const iv = ciphertext.slice(0, 16)
      const ciphertext_data = ciphertext.slice(16, -32)
      return aesCbcDecrypt(encryption_key, iv, ciphertext_data)
    } catch (e) {
      // console.error(e.message)
    }
  }
  return null
}
