import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { hexToBytes, bytesToHex, concatBytes } from '@noble/curves/utils.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { unpack, pack } from 'msgpackr'

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

const encoder = new TextEncoder()
const decoder = new TextDecoder()

// Serialization (storing string)
export const serializeIdentity = ({ encPriv, sigPriv }) => bytesToHex(new Uint8Array([...encPriv, ...sigPriv]))
export const unserializeIdentity = (s) => {
  const keyBytes = hexToBytes(s)
  return {
    encPriv: keyBytes.slice(0, 32),
    sigPriv: keyBytes.slice(32)
  }
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

// Unpack a reticulum packet header from bytes
export function unpackReticulum(buffer) {
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

// Generic Reticulum packet builder (header + payload)
export function buildReticulum({
  packetType, // 0..3
  headerType = 0, // 0: [flags,hops,dst,ctx], 1: [flags,hops,transportId,dst,ctx]
  transportId, // Uint8Array(16) if headerType=1
  transportType = 0, // 0..1
  destinationType = 0, // 0..3
  hops = 0x00, // 0..255
  destinationHash, // Uint8Array(16)
  context = 0x00, // 0..255
  contextFlag = 0, // 0..1 (ratchet indicator or similar)
  payload // Uint8Array
}) {
  const flags = ((headerType & 0b1) << 6) | ((contextFlag & 0b1) << 5) | ((transportType & 0b1) << 4) | ((destinationType & 0b11) << 2) | (packetType & 0b11)

  const headFixed = Uint8Array.of(flags, hops)
  const headTail = Uint8Array.of(context)
  const header = headerType === 1 ? concatBytes(headFixed, transportId, destinationHash, headTail) : concatBytes(headFixed, destinationHash, headTail)

  return concatBytes(header, payload)
}

// Build ANNOUNCE packet directly from a 64-byte identity hex
export function buildAnnounce({
  encPriv,
  sigPriv,
  appName, // e.g. "myapp"
  aspects = [], // e.g. ["inbox"]
  data = undefined, // Object or undefined
  ratchet = null, // Uint8Array(32) or null
  headerType = 0,
  transportId = undefined,
  transportType = 0,
  destinationType = 0,
  hops = 0x00,
  context = 0x00,
  peerName = undefined // string that names peer ("Annonymous Peer")
} = {}) {
  const encPub = x25519.getPublicKey(encPriv) // 32B
  const sigPub = ed25519.getPublicKey(sigPriv) // 32B

  let appData = undefined
  if (data || peerName) {
    appData = pack([encoder.encode(peerName || 'Annonymous Peer'), data])
  }

  // nameHash: 10B = trunc(SHA256("app.aspect1.aspect2"))
  if (!appName || appName.includes('.')) throw new Error('Invalid appName')
  for (const a of aspects) if (!a || a.includes('.')) throw new Error('Invalid aspect')
  const fullName = aspects.length ? `${appName}.${aspects.join('.')}` : appName
  const nameHash = sha256(encoder.encode(fullName)).slice(0, 10)

  // identityHash: 16B = trunc(SHA256(encPub||sigPub))
  const identityHash = sha256(concatBytes(encPub, sigPub)).slice(0, 16)

  // destinationHash: 16B = trunc(SHA256(nameHash||identityHash))
  const destinationHash = sha256(concatBytes(nameHash, identityHash)).slice(0, 16)

  // randomHash: 10B = 5 random + 5B big-endian unix time
  const r = new Uint8Array(5)
  if (!crypto?.getRandomValues) throw new Error('Secure RNG required')
  crypto.getRandomValues(r)
  const t = Math.floor(Date.now() / 1000)
  const ts = new Uint8Array([(t >>> 32) & 255, (t >>> 24) & 255, (t >>> 16) & 255, (t >>> 8) & 255, t & 255])
  const randomHash = concatBytes(r, ts)

  // Sign over: dstHash || encPub || sigPub || nameHash || randomHash || [ratchet?] || [appData?]
  const toSign = concatBytes(destinationHash, encPub, sigPub, nameHash, randomHash, ratchet ?? new Uint8Array(0), appData ?? new Uint8Array(0))
  const signature = ed25519.sign(toSign, sigPriv) // 64B

  // Payload: encPub || sigPub || nameHash || randomHash || [ratchet?] || signature || [appData?]
  const payload = concatBytes(encPub, sigPub, nameHash, randomHash, ratchet ?? new Uint8Array(0), signature, appData ?? new Uint8Array(0))

  // Build the full packet via the generic builder
  const packet = buildReticulum({
    packetType: 1, // ANNOUNCE
    headerType,
    transportId,
    transportType,
    destinationType,
    hops,
    destinationHash,
    context,
    contextFlag: ratchet ? 1 : 0,
    payload
  })

  return {
    packet, // Uint8Array
    destinationHash, // 16B
    nameHash, // 10B
    randomHash, // 10B
    encPub, // 32B
    sigPub, // 32B
    signature // 64B
  }
}

// Decrypts the DATA field from unpackReticulum()
// params:
// - packet: output of unpackReticulum(buffer)
// - keys: { encPriv, sigPriv, peerEncPub?, groupKey?, info?, salt? }
// returns { plaintext, verifiedAuth }
export function decryptDataPacket(packet, keys = {}) {
  const { destinationType, data } = packet

  // Plaintext case
  if (destinationType === DESTINATION_PLAIN) {
    return { plaintext: data, verifiedAuth: false }
  }

  // Expect a framed blob: [ephemeralHeader|cipher|tag]
  // A practical minimal framing:
  // - 32B ephPub (for SINGLE) or 0B (for GROUP)
  // - 16B iv
  // - ciphertext...
  // - 32B hmac tag at end
  if (data.length < IV_LEN + HMAC_TAG_LEN + (destinationType === DESTINATION_SINGLE ? 32 : 0)) {
    throw new Error('DATA too short')
  }

  let offset = 0
  let sharedSecret = null

  if (destinationType === DESTINATION_SINGLE) {
    const ephPub = data.slice(0, 32)
    offset += 32
    if (!keys.encPriv) throw new Error('encPriv required for SINGLE')
    // ECDH: X25519
    sharedSecret = x25519.getSharedSecret(keys.encPriv, ephPub)
  } else if (destinationType === DESTINATION_GROUP) {
    if (!keys.groupKey || keys.groupKey.length !== AES_KEY_LEN) {
      throw new Error('groupKey (32B) required for GROUP')
    }
    // Use group key as IKM
    sharedSecret = keys.groupKey
  } else {
    throw new Error('Unsupported destinationType for decryption')
  }

  const iv = data.slice(offset, offset + IV_LEN)
  offset += IV_LEN
  const tag = data.slice(data.length - HMAC_TAG_LEN)
  const ciphertext = data.slice(offset, data.length - HMAC_TAG_LEN)

  // Derive encKey and authKey via HKDF-SHA256
  const salt = keys.salt || iv
  const info = keys.info || encoder.encode('reticulum-lxmf-data')
  const okm = hkdfSha256(sharedSecret, salt, info, AES_KEY_LEN + AES_KEY_LEN)
  const encKey = okm.slice(0, AES_KEY_LEN)
  const authKey = okm.slice(AES_KEY_LEN)

  // Verify HMAC over (header parts helpful): destinationHash || context || iv || ciphertext
  // Including destinationHash and context binds to routing metadata while keeping source private
  const macInput = concatBytes(packet.destinationHash, Uint8Array.of(packet.context), iv, ciphertext)
  const calc = hmacSha256(authKey, macInput)
  const verifiedAuth = bytesToHex(calc) === bytesToHex(tag)
  if (!verifiedAuth) throw new Error('HMAC verification failed')

  // AES-256-CBC decrypt
  const aesCbc = cbc(aes(encKey), iv)
  const plaintext = aesCbc.decrypt(ciphertext)

  return { plaintext, verifiedAuth }
}

// Parse LXMF envelope + decrypt payload into structured message.
// packet: output of unpackReticulum
// keys: passed to decryptDataPacket (encPriv, groupKey, etc.)
// returns object with fields and verification flags
export function parseLxmf(packet, keys = {}) {
  if (packet.packetType !== PACKET_DATA) {
    throw new Error('Not a DATA packet')
  }
  // If a specific context is used for LXMF in this app, enforce it:
  // if (packet.context !== LXMF_CONTEXT) throw new Error('Unexpected context');

  // Envelope layout (outer, not encrypted):
  // 16B destination || 16B source || 64B signature || encryptedPayload...
  const minEnv = 16 + 16 + 64 + 1
  if (packet.data.length < minEnv) throw new Error('LXMF envelope too short')

  const dst = packet.data.slice(0, 16)
  const src = packet.data.slice(16, 32)
  const signature = packet.data.slice(32, 96)
  const encryptedPayload = packet.data.slice(96)

  // Decrypt inner payload with decryptDataPacket applied to a "sub-packet"
  const subPacket = { ...packet, data: encryptedPayload }
  const { plaintext, verifiedAuth } = decryptDataPacket(subPacket, keys)

  // Expect msgpack list [timestamp, content, title, fields]
  let parts
  try {
    parts = unpack(plaintext)
  } catch (e) {
    throw new Error('Invalid LXMF payload msgpack')
  }
  if (!Array.isArray(parts) || parts.length < 4) {
    throw new Error('Invalid LXMF payload structure')
  }
  const [timestamp, content, title, fields] = parts

  // Compute message-id = SHA256(dst || src || payload)
  const msgId = SHA256(concatBytes(dst, src, plaintext))

  // Verify Ed25519 signature over (dst || src || payload || msgId)
  // Caller must provide sender’s sig public key to verify (peerSigPub).
  let sigVerified = false
  if (keys.peerSigPub) {
    const toVerify = concatBytes(dst, src, plaintext, msgId)
    sigVerified = ed25519.verify(signature, toVerify, keys.peerSigPub)
  }

  return {
    destination: dst,
    source: src,
    signature,
    msgId,
    timestamp,
    content,
    title,
    fields: fields || {},
    authVerified: verifiedAuth,
    sigVerified
  }
}
