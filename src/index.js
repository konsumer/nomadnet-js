// Lightweight Reticulum library for JavaScript

import { Packr, unpack } from 'msgpackr'

// Configure msgpackr to match Python msgpack encoding
// - useRecords: false - don't use msgpack extension types
// - variableMapSize: true - use fixmap (0x80) for small maps instead of map16
// - mapsAsObjects: true - encode objects as maps
const packr = new Packr({ useRecords: false, variableMapSize: true, mapsAsObjects: true })
const pack = (data) => packr.pack(data)

// prettier-ignore
import {
  private_identity,
  public_identity,
  private_ratchet,
  public_ratchet,
  sha256,
  hmac_sha256,
  hkdf,
  aes_cbc_encrypt,
  aes_cbc_decrypt,
  ed25519_sign,
  ed25519_validate,
  x25519_exchange,
  randomBytes,
  hexToBytes,
  bytesToHex
} from './crypto.js'

// Re-export useful functions
export { private_identity, public_identity, private_ratchet, public_ratchet, hexToBytes, bytesToHex }

// Packet types
export const PACKET_DATA = 0x00
export const PACKET_ANNOUNCE = 0x01
export const PACKET_LINKREQUEST = 0x02
export const PACKET_PROOF = 0x03

// Destination types
export const DEST_SINGLE = 0x00
export const DEST_GROUP = 0x01
export const DEST_PLAIN = 0x02
export const DEST_LINK = 0x03

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

/**
 * Helper to concatenate Uint8Arrays
 */
// TODO: move this to crypto.js
function concat(...arrays) {
  const total = arrays.reduce((sum, arr) => sum + arr.length, 0)
  const result = new Uint8Array(total)
  let offset = 0
  for (const arr of arrays) {
    result.set(arr, offset)
    offset += arr.length
  }
  return result
}

/**
 * Get destination hash from identity public key
 */
export function get_identity_destination_hash(identity_pub, full_name = 'lxmf.delivery') {
  const identity_hash = sha256(identity_pub).slice(0, 16)
  const name_hash = sha256(new TextEncoder().encode(full_name)).slice(0, 10)
  const addr_hash_material = concat(name_hash, identity_hash)
  return sha256(addr_hash_material).slice(0, 16)
}

/**
 * Get message ID from packet bytes
 */
export function get_message_id(packet_bytes) {
  const header_type = (packet_bytes[0] >> 6) & 0b11
  const hashable_part = new Uint8Array([packet_bytes[0] & 0b00001111])

  let rest
  if (header_type === 1) {
    // Skip header + hops + transport_id (2 + 16 = 18 bytes)
    rest = packet_bytes.slice(18)
  } else {
    // Skip header + hops (2 bytes)
    rest = packet_bytes.slice(2)
  }

  return sha256(concat(hashable_part, rest))
}

/**
 * Unpack packet bytes into object
 */
export function packet_unpack(packet_bytes) {
  const DST_LEN = 16
  const flags = packet_bytes[0]
  const hops = packet_bytes[1]
  const header_type = (flags & 0b01000000) >> 6
  const context_flag = (flags & 0b00100000) >> 5
  const transport_type = (flags & 0b00010000) >> 4
  const destination_type = (flags & 0b00001100) >> 2
  const packet_type = flags & 0b00000011

  let transport_id, destination_hash, context, data

  if (header_type === 1) {
    transport_id = packet_bytes.slice(2, DST_LEN + 2)
    destination_hash = packet_bytes.slice(DST_LEN + 2, 2 * DST_LEN + 2)
    context = packet_bytes[2 * DST_LEN + 2]
    data = packet_bytes.slice(2 * DST_LEN + 3)
  } else {
    transport_id = null
    destination_hash = packet_bytes.slice(2, DST_LEN + 2)
    context = packet_bytes[DST_LEN + 2]
    data = packet_bytes.slice(DST_LEN + 3)
  }

  return {
    header_type,
    context_flag,
    transport_type,
    destination_type,
    packet_type,
    transport_id,
    destination_hash,
    context,
    data,
    hops,
    packet_hash: get_message_id(packet_bytes),
    raw: packet_bytes
  }
}

/**
 * Validate ANNOUNCE packet
 */
export function validate_announce(packet) {
  const keysize = 64
  const ratchetsize = 32
  const name_hash_len = 10
  const sig_len = 64
  const destination_hash = packet.destination_hash
  const public_key = packet.data.slice(0, keysize)

  let name_hash, random_hash, ratchet, signature, app_data

  if (packet.context_flag === 1) {
    name_hash = packet.data.slice(keysize, keysize + name_hash_len)
    random_hash = packet.data.slice(keysize + name_hash_len, keysize + name_hash_len + 10)
    ratchet = packet.data.slice(keysize + name_hash_len + 10, keysize + name_hash_len + 10 + ratchetsize)
    signature = packet.data.slice(keysize + name_hash_len + 10 + ratchetsize, keysize + name_hash_len + 10 + ratchetsize + sig_len)
    app_data = packet.data.length > keysize + name_hash_len + 10 + sig_len + ratchetsize ? packet.data.slice(keysize + name_hash_len + 10 + sig_len + ratchetsize) : new Uint8Array(0)
  } else {
    ratchet = new Uint8Array(0)
    name_hash = packet.data.slice(keysize, keysize + name_hash_len)
    random_hash = packet.data.slice(keysize + name_hash_len, keysize + name_hash_len + 10)
    signature = packet.data.slice(keysize + name_hash_len + 10, keysize + name_hash_len + 10 + sig_len)
    app_data = packet.data.length > keysize + name_hash_len + 10 + sig_len ? packet.data.slice(keysize + name_hash_len + 10 + sig_len) : new Uint8Array(0)
  }

  const signed_data = concat(destination_hash, public_key, name_hash, random_hash, ratchet, app_data)

  if (packet.data.length <= 64 + 10 + 10 + 64) {
    app_data = null
  }

  if (!ed25519_validate(signature, signed_data, public_key.slice(32, 64))) {
    return false
  }

  return {
    app_data,
    name_hash,
    public_key,
    random_hash,
    ratchet,
    signature,
    signed_data
  }
}

/**
 * Validate PROOF packet
 */
export function validate_proof(packet, sender_pub, full_packet_hash) {
  return ed25519_validate(packet.data.slice(0, 64), full_packet_hash, sender_pub.slice(32, 64))
}

/**
 * Decrypt message from DATA packet
 */
export function message_decrypt(packet, receiver_pub, ratchets = []) {
  if (packet.data.length < 49) {
    return null
  }

  const identity_hash = sha256(receiver_pub).slice(0, 16)
  const peer_pub_bytes = packet.data.slice(0, 32)
  const rest = packet.data.slice(32)

  if (rest.length < 48) {
    return null
  }

  const signed_data = rest.slice(0, -32)
  const received_hmac = rest.slice(-32)

  for (const ratchet of ratchets) {
    if (ratchet.length !== 32) {
      continue
    }
    try {
      const derived_key = hkdf(x25519_exchange(ratchet, peer_pub_bytes), 64, identity_hash)
      const expected_hmac = hmac_sha256(derived_key.slice(0, 32), signed_data)

      // Compare HMACs
      let hmac_match = true
      for (let i = 0; i < 32; i++) {
        if (expected_hmac[i] !== received_hmac[i]) {
          hmac_match = false
          break
        }
      }

      if (!hmac_match) {
        continue
      }

      const iv = signed_data.slice(0, 16)
      const ciphertext = signed_data.slice(16)
      return aes_cbc_decrypt(derived_key.slice(32), iv, ciphertext)
    } catch (e) {
      continue
    }
  }

  return null
}

/**
 * Pack packet object into bytes
 */
export function packet_pack(packet) {
  let flags = 0
  flags |= ((packet.header_type || 0) & 0b1) << 6
  flags |= ((packet.context_flag || 0) & 0b1) << 5
  flags |= ((packet.transport_type || 0) & 0b1) << 4
  flags |= ((packet.destination_type || 0) & 0b11) << 2
  flags |= (packet.packet_type || 0) & 0b11

  let result = new Uint8Array([flags, packet.hops || 0])

  if ((packet.header_type || 0) === 1) {
    result = concat(result, packet.transport_id)
  }

  result = concat(result, packet.destination_hash)
  result = concat(result, new Uint8Array([packet.context || 0]))
  result = concat(result, packet.data || new Uint8Array(0))

  return result
}

/**
 * Build ANNOUNCE packet
 */
export function build_announce(identity_priv, identity_pub = null, destination_hash = null, ratchet_priv = null, ratchet_pub = null, full_name = 'lxmf.delivery', app_data = new Uint8Array(0)) {
  // Get public key if needed
  identity_pub = identity_pub || public_identity(identity_priv)

  // Get destination hash
  destination_hash = destination_hash || get_identity_destination_hash(identity_pub, full_name)

  // Build announce data
  const public_key = identity_pub
  const name_hash = sha256(new TextEncoder().encode(full_name)).slice(0, 10)

  // Generate random hash (10 bytes)
  const random_hash = randomBytes(10)

  // Add ratchet if provided
  if (!ratchet_pub) {
    if (ratchet_priv) {
      ratchet_pub = public_ratchet(ratchet_priv)
    } else {
      ratchet_pub = new Uint8Array(0)
    }
  }

  const context_flag = ratchet_pub.length > 0 ? 1 : 0

  // Sign the announce
  const signed_data = concat(destination_hash, public_key, name_hash, random_hash, ratchet_pub, app_data)
  const signature = ed25519_sign(identity_priv.slice(32), signed_data)

  // Build data field
  let data = concat(public_key, name_hash, random_hash)
  if (ratchet_pub.length > 0) {
    data = concat(data, ratchet_pub)
  }
  data = concat(data, signature, app_data)

  // Build packet
  const packet = {
    header_type: 0,
    context_flag,
    transport_type: 0,
    destination_type: DEST_SINGLE,
    packet_type: PACKET_ANNOUNCE,
    hops: 0,
    destination_hash,
    context: CONTEXT_NONE,
    data
  }

  return packet_pack(packet)
}

/**
 * Build DATA packet
 */
export function build_data(plaintext, receiver_identity_pub, receiver_ratchet_pub, full_name = 'lxmf.delivery') {
  const destination_hash = get_identity_destination_hash(receiver_identity_pub, full_name)
  const identity_hash = sha256(receiver_identity_pub).slice(0, 16)

  // Generate ephemeral key pair
  const ephemeral_priv = private_ratchet()
  const ephemeral_pub = public_ratchet(ephemeral_priv)

  // Derive encryption keys
  const shared_secret = x25519_exchange(ephemeral_priv, receiver_ratchet_pub)
  const derived_key = hkdf(shared_secret, 64, identity_hash)

  const hmac_key = derived_key.slice(0, 32)
  const aes_key = derived_key.slice(32)

  // Generate random IV and encrypt
  const iv = randomBytes(16)
  const ciphertext = aes_cbc_encrypt(aes_key, iv, plaintext)

  // Build signed data and compute HMAC
  const signed_data = concat(iv, ciphertext)
  const message_hmac = hmac_sha256(hmac_key, signed_data)

  // Build data field
  const data = concat(ephemeral_pub, signed_data, message_hmac)

  // Build packet
  const packet = {
    header_type: 0,
    context_flag: 0,
    transport_type: 0,
    destination_type: DEST_SINGLE,
    packet_type: PACKET_DATA,
    hops: 0,
    destination_hash,
    context: CONTEXT_NONE,
    data
  }

  return packet_pack(packet)
}

/**
 * Build PROOF packet
 */
export function build_proof(data_packet_bytes, sender_identity_priv) {
  const full_message_id = get_message_id(data_packet_bytes)
  const truncated_message_id = full_message_id.slice(0, 16)
  const signature = ed25519_sign(sender_identity_priv.slice(32), full_message_id)

  const packet = {
    header_type: 0,
    context_flag: 0,
    transport_type: 0,
    destination_type: DEST_SINGLE,
    packet_type: PACKET_PROOF,
    hops: 0,
    destination_hash: truncated_message_id,
    context: CONTEXT_NONE,
    data: signature
  }

  return packet_pack(packet)
}

/**
 * Parse LXMF message
 */
export function lxmf_parse(decrypted_data, packet_destination_hash, sender_pub) {
  if (decrypted_data.length < 80) {
    return false
  }

  const source_hash = decrypted_data.slice(0, 16)
  const signature = decrypted_data.slice(16, 80)
  const msgpack_raw = decrypted_data.slice(80)

  try {
    const msgpack_data = unpack(msgpack_raw)

    if (!Array.isArray(msgpack_data) || msgpack_data.length < 3) {
      return false
    }

    const timestamp = msgpack_data[0]
    let title = msgpack_data[1]
    let content = msgpack_data[2]
    const fields = msgpack_data.length > 3 ? msgpack_data[3] : {}

    // Title and content should be Uint8Array (bytes), not strings
    // If they're already Uint8Array, keep them. If Buffer, convert to Uint8Array
    if (title && !(title instanceof Uint8Array)) {
      if (title.constructor.name === 'Buffer') {
        title = new Uint8Array(title)
      }
    }
    if (content && !(content instanceof Uint8Array)) {
      if (content.constructor.name === 'Buffer') {
        content = new Uint8Array(content)
      }
    }

    // Verify LXMF signature
    const message_id = sha256(concat(packet_destination_hash, source_hash, msgpack_raw))
    const signed_data = concat(packet_destination_hash, source_hash, msgpack_raw, message_id)

    const valid = ed25519_validate(signature, signed_data, sender_pub.slice(32, 64))

    return {
      source_hash,
      signature,
      timestamp,
      title,
      content,
      fields,
      message_id,
      valid
    }
  } catch {
    return false
  }
}

/**
 * Build LXMF message
 */
export function lxmf_build(content, source_priv, destination_hash, source_hash = null, timestamp = null, title = null, fields = null) {
  if (timestamp === null) {
    timestamp = Date.now() / 1000
  }
  if (title === null || title === '') {
    title = new Uint8Array(0)
  } else if (typeof title === 'string') {
    // Convert string to UTF-8 bytes for msgpack
    title = new TextEncoder().encode(title)
  }
  if (fields === null) {
    fields = {}
  }
  if (source_hash === null) {
    source_hash = get_identity_destination_hash(public_identity(source_priv))
  }

  // Convert content to bytes if it's a string
  if (typeof content === 'string') {
    if (content === '') {
      content = new Uint8Array(0)
    } else {
      content = new TextEncoder().encode(content)
    }
  }

  // Build msgpack: [timestamp, title, content, fields]
  const msgpack_data = [timestamp, title, content, fields]
  let msgpack_raw = pack(msgpack_data)

  // Ensure msgpack_raw is Uint8Array (msgpackr may return Buffer in Node.js)
  if (!(msgpack_raw instanceof Uint8Array)) {
    msgpack_raw = new Uint8Array(msgpack_raw)
  }

  // Sign
  const message_id = sha256(concat(destination_hash, source_hash, msgpack_raw))
  const signed_data = concat(destination_hash, source_hash, msgpack_raw, message_id)
  const signature = ed25519_sign(source_priv.slice(32), signed_data)

  // Build LXMF message
  return concat(source_hash, signature, msgpack_raw)
}
