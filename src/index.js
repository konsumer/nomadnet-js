import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { hexToBytes, bytesToHex, concatBytes } from '@noble/curves/utils.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { unpack, pack } from 'msgpackr'

// Packet-types
export const PACKET_DATA = 0
export const PACKET_ANNOUNCE = 1
export const PACKET_LINKREQUEST = 2
export const PACKET_PROOF = 3

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

// serialization (storing string)
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

// get the LXMF address from your keys
export function deriveLxmfAddress({ encPriv, sigPriv }) {
  const encPub = x25519.getPublicKey(encPriv) // 32 bytes
  const sigPub = ed25519.getPublicKey(sigPriv) // 32 bytes
  const nameHash = sha256(encoder.encode('lxmf.delivery')).slice(0, 10) // 10 bytes
  const pubBlob = concatBytes(encPub, sigPub) // get_public_key() equivalent
  const identityHash = sha256(pubBlob).slice(0, 16) // 16 bytes
  const destinationHash = sha256(concatBytes(nameHash, identityHash)).slice(0, 16) // 16 bytes
  return { destinationHash, encPub, sigPub } // Uint8Arrays
}

// Unpack a reticulum packet header
export function unpackHeader(buffer) {
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

// verify an announce packet (output from unpackHeader)
export function verifyAnnounce(packet) {
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
