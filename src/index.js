import { verify } from '@noble/ed25519'

export const PACKET_DATA = 0 // Data packets
export const PACKET_ANNOUNCE = 1 // Announces
export const PACKET_LINKREQ = 2 // Link requests
export const PACKET_PROOF = 3 // Proofs

export const PACKET_CONTEXT_NONE = 0x00 // Generic data packet
export const PACKET_CONTEXT_RESOURCE = 0x01 // Packet is part of a resource
export const PACKET_CONTEXT_RESOURCE_ADV = 0x02 // Packet is a resource advertisement
export const PACKET_CONTEXT_RESOURCE_REQ = 0x03 // Packet is a resource part request
export const PACKET_CONTEXT_RESOURCE_HMU = 0x04 // Packet is a resource hashmap update
export const PACKET_CONTEXT_RESOURCE_PRF = 0x05 // Packet is a resource proof
export const PACKET_CONTEXT_RESOURCE_ICL = 0x06 // Packet is a resource initiator cancel message
export const PACKET_CONTEXT_RESOURCE_RCL = 0x07 // Packet is a resource receiver cancel message
export const PACKET_CONTEXT_CACHE_REQUEST = 0x08 // Packet is a cache request
export const PACKET_CONTEXT_REQUEST = 0x09 // Packet is a request
export const PACKET_CONTEXT_RESPONSE = 0x0a // Packet is a response to a request
export const PACKET_CONTEXT_PATH_RESPONSE = 0x0b // Packet is a response to a path request
export const PACKET_CONTEXT_COMMAND = 0x0c // Packet is a command
export const PACKET_CONTEXT_COMMAND_STATUS = 0x0d // Packet is a status of an executed command
export const PACKET_CONTEXT_CHANNEL = 0x0e // Packet contains link channel data
export const PACKET_CONTEXT_KEEPALIVE = 0xfa // Packet is a keepalive packet
export const PACKET_CONTEXT_LINKIDENTIFY = 0xfb // Packet is a link peer identification proof
export const PACKET_CONTEXT_LINKCLOSE = 0xfc // Packet is a link close message
export const PACKET_CONTEXT_LINKPROOF = 0xfd // Packet is a link packet proof
export const PACKET_CONTEXT_LRRTT = 0xfe // Packet is a link request round-trip time measurement
export const PACKET_CONTEXT_LRPROOF = 0xff // Packet is a link request proof

export const hex = (bytes, seperator = '', upper = true) =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(seperator)
    [upper ? 'toUpperCase' : 'toLowerCase']()

export async function parseReticulum(packetData) {
  const raw = new Uint8Array(packetData)
  // [HEADER 2 bytes] [ADDRESSES 16/32 bytes] [CONTEXT 1 byte] [DATA 0-465 bytes]
  // 2 + 16 + 1
  if (raw.length < 19) {
    throw new Error('Invalid Reticulum packet: Data too short for header.')
  }

  // Extract fields using bitwise operations
  const out = { raw, reticulum: {} }

  out.reticulum.flags = raw[0]
  out.reticulum.hops = raw[1]

  out.reticulum.headerType = (out.reticulum.flags & 0b01000000) >> 6
  out.reticulum.contextFlag = (out.reticulum.flags & 0b00100000) >> 5
  out.reticulum.transportType = (out.reticulum.flags & 0b00010000) >> 4
  out.reticulum.destinationType = (out.reticulum.flags & 0b00001100) >> 2
  out.reticulum.packetType = out.reticulum.flags & 0b00000011
  out.reticulum.destinationHash = raw.slice(2, 18)

  const DST_LEN = 16
  if (out.reticulum.headerType === 1) {
    out.reticulum.trasnportId = raw.slice(2, DST_LEN + 2)
    out.reticulum.destinationHash = raw.slice(DST_LEN + 2, 2 * DST_LEN + 2)
    out.reticulum.context = raw[2 * DST_LEN + 2]
    out.reticulum.data = raw.slice(2 * DST_LEN + 3)
  } else {
    out.reticulum.destinationHash = raw.slice(2, DST_LEN + 2)
    out.reticulum.context = raw[DST_LEN + 2]
    out.reticulum.data = raw.slice(DST_LEN + 3)
  }

  if (out.reticulum.packetType === PACKET_ANNOUNCE) {
    out.announce = await parseAndVerifyAnnounce(out)
  }
  if (out.reticulum.packetType === PACKET_DATA) {
    out.data = {}
    // TODO: pull out fields from DATA packet, verify signatures, etc
  }
  if (out.reticulum.packetType === PACKET_LINKREQ) {
    out.link = {}
    // TODO: pull out fields from LIKREQ packet, verify signatures, etc
  }
  if (out.reticulum.packetType === PACKET_PROOF) {
    out.proof = {}
    // TODO: pull out fields from PROOF packet, verify signatures, etc
  }

  return out
}

export async function parseAndVerifyAnnounce({ reticulum: { data, destinationHash, contextFlag } }) {
  const keysize = 64 // Identity.KEYSIZE//8 (32 bytes each for encryption + signing keys)
  const nameHashLen = 10 // Identity.nameHashLenGTH//8
  const sigLen = 64 // Identity.SIGLENGTH//8
  const ratchetsize = 32 // Identity.RATCHETSIZE//8

  const publicKey = data.slice(0, keysize)

  let nameHash
  let randomHash
  let ratchet = new Uint8Array()
  let appData = new Uint8Array()
  let signature

  if (contextFlag) {
    nameHash = data.slice(keysize, keysize + nameHashLen)
    randomHash = data.slice(keysize + nameHashLen, keysize + nameHashLen + 10)
    ratchet = data.slice(keysize + nameHashLen + 10, keysize + nameHashLen + 10 + ratchetsize)
    signature = data.slice(keysize + nameHashLen + 10 + ratchetsize, keysize + nameHashLen + 10 + ratchetsize + sigLen)
    if (data.length > keysize + nameHashLen + 10 + sigLen + ratchetsize) {
      appData = data.slice(keysize + nameHashLen + 10 + sigLen + ratchetsize)
    }
  } else {
    nameHash = data.slice(keysize, keysize + nameHashLen)
    randomHash = data.slice(keysize + nameHashLen, keysize + nameHashLen + 10)
    signature = data.slice(keysize + nameHashLen + 10, keysize + nameHashLen + 10 + sigLen)
    if (data.length > keysize + nameHashLen + 10 + sigLen) {
      appData = data.sllice(keysize + nameHashLen + 10 + sigLen)
    }
  }

  const signedData = new Uint8Array([...destinationHash, ...publicKey, ...nameHash, ...randomHash, ...ratchet, ...appData])
  if (data.length <= 148) {
    appData = new Uint8Array()
  }

  // TODO: this throws
  const verified = verify(signature, signedData, publicKey)

  return {
    appData,
    ratchet,
    publicKey,
    verified
  }
}

/*
export async function parseAndVerifyAnnounce(out) {
  const data = out.reticulum.data

  // Constants from Identity.py
  const keysize = 64 // Identity.KEYSIZE//8 (32 bytes each for encryption + signing keys)
  const nameHashLen = 10 // Identity.nameHashLenGTH//8
  const sigLen = 64 // Identity.SIGLENGTH//8
  const ratchetsize = 32 // Identity.RATCHETSIZE//8

  if (!data || data.length < keysize + nameHashLen + 10 + sigLen) {
    throw new Error('Announce packet too short')
  }

  // Extract public key (first 64 bytes - 32 for encryption + 32 for signing)
  const publicKey = data.slice(0, keysize)

  let nameHash, randomHash, signature, appData, ratchet

  // Check if this announce contains a ratchet (you'll need to determine this from your packet parsing)
  // For now, assuming no ratchet (context_flag not set)
  const hasRatchet = false // You need to set this based on packet.context_flag

  if (hasRatchet) {
    nameHash = data.slice(keysize, keysize + nameHashLen)
    randomHash = data.slice(keysize + nameHashLen, keysize + nameHashLen + 10)
    ratchet = data.slice(keysize + nameHashLen + 10, keysize + nameHashLen + 10 + ratchetsize)
    signature = data.slice(keysize + nameHashLen + 10 + ratchetsize, keysize + nameHashLen + 10 + ratchetsize + sigLen)

    if (data.length > keysize + nameHashLen + 10 + sigLen + ratchetsize) {
      appData = data.slice(keysize + nameHashLen + 10 + sigLen + ratchetsize)
    } else {
      appData = new Uint8Array(0)
    }
  } else {
    ratchet = new Uint8Array(0)
    nameHash = data.slice(keysize, keysize + nameHashLen)
    randomHash = data.slice(keysize + nameHashLen, keysize + nameHashLen + 10)
    signature = data.slice(keysize + nameHashLen + 10, keysize + nameHashLen + 10 + sigLen)

    if (data.length > keysize + nameHashLen + 10 + sigLen) {
      appData = data.slice(keysize + nameHashLen + 10 + sigLen)
    } else {
      appData = new Uint8Array(0)
    }
  }

  // The signed data is: destination_hash + publicKey + nameHash + randomHash + ratchet + appData
  const signedData = new Uint8Array(out.reticulum.destinationHash.length + publicKey.length + nameHash.length + randomHash.length + ratchet.length + appData.length)

  let offset = 0
  signedData.set(out.reticulum.destinationHash, offset)
  offset += out.reticulum.destinationHash.length
  signedData.set(publicKey, offset)
  offset += publicKey.length
  signedData.set(nameHash, offset)
  offset += nameHash.length
  signedData.set(randomHash, offset)
  offset += randomHash.length
  signedData.set(ratchet, offset)
  offset += ratchet.length
  signedData.set(appData, offset)

  // Extract just the Ed25519 signing public key (last 32 bytes of the 64-byte public key)
  const signingPublicKey = publicKey.slice(32, 64)

  console.log(
    'Public key (full):',
    Array.from(publicKey)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  )
  console.log(
    'Signing public key:',
    Array.from(signingPublicKey)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  )
  console.log(
    'Name hash:',
    Array.from(nameHash)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  )
  console.log(
    'Random hash:',
    Array.from(randomHash)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  )
  console.log(
    'Signature:',
    Array.from(signature)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  )
  console.log('App data:', new TextDecoder().decode(appData))
  console.log(
    'Signed data:',
    Array.from(signedData)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  )

  try {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      signingPublicKey,
      {
        name: 'Ed25519'
      },
      false,
      ['verify']
    )

    const isValid = await crypto.subtle.verify('Ed25519', cryptoKey, signature, signedData)

    return {
      publicKey: publicKey,
      signingPublicKey: signingPublicKey,
      nameHash: nameHash,
      randomHash: randomHash,
      signature: signature,
      appData: appData,
      ratchet: ratchet,
      isValid: isValid,
      destinationHash: out.reticulum.destinationHash
    }
  } catch (error) {
    console.error('Signature verification failed:', error)
    return {
      publicKey: publicKey,
      signingPublicKey: signingPublicKey,
      nameHash: nameHash,
      randomHash: randomHash,
      signature: signature,
      appData: appData,
      ratchet: ratchet,
      isValid: false,
      destinationHash: out.reticulum.destinationHash,
      error: error.message
    }
  }
}

*/
