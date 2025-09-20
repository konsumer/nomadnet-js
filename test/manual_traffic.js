// this is a self-contained tester that will read info from test/b storage, and set things up

import { readFile, glob } from 'node:fs/promises'
import { unpack } from 'msgpackr'

// glob is experimental
process.removeAllListeners('warning')

const encoder = new TextEncoder()

async function parseReticulumIdentity(identityBytes) {
  if (!(identityBytes instanceof Uint8Array) || identityBytes.length !== 64) {
    throw new Error('Invalid Reticulum identity: must be a 64-byte Uint8Array')
  }

  // Split into Ed25519 and X25519 keys (32 bytes each)
  const ed25519PrivateKeyRaw = identityBytes.slice(0, 32)
  const x25519PrivateKeyRaw = identityBytes.slice(32, 64)

  // Convert Ed25519 private key to PKCS#8 format for Web Crypto API
  const ed25519Pkcs8 = createEd25519Pkcs8(ed25519PrivateKeyRaw)

  // Import Ed25519 key for signing
  const ed25519PrivateKey = await crypto.subtle.importKey('pkcs8', ed25519Pkcs8, { name: 'Ed25519' }, true, ['sign'])

  // Derive Ed25519 public key
  const ed25519PublicKeyRaw = await deriveEd25519PublicKey(ed25519PrivateKeyRaw)

  // Create public key for verification
  const ed25519PublicKeySpki = createEd25519Spki(ed25519PublicKeyRaw)
  const ed25519PublicKey = await crypto.subtle.importKey('spki', ed25519PublicKeySpki, { name: 'Ed25519' }, true, ['verify'])

  return {
    destinationHash: new Uint8Array(await crypto.subtle.digest('SHA-256', ed25519PublicKeyRaw)),
    ed25519PrivateKey,
    ed25519PublicKey,
    ed25519PrivateKeyRaw,
    ed25519PublicKeyRaw,
    x25519PrivateKeyRaw,

    // Sign a message using Ed25519
    async sign(message) {
      const data = typeof message === 'string' ? encoder.encode(message) : message
      return await crypto.subtle.sign('Ed25519', ed25519PrivateKey, data)
    },

    // Verify a signature using Ed25519
    async verify(message, signature) {
      const data = typeof message === 'string' ? encoder.encode(message) : message
      return await crypto.subtle.verify('Ed25519', ed25519PublicKey, signature, data)
    }
  }
}

// Import external Ed25519 public key for verification
async function importPublicKey(publicKeyRaw) {
  if (!(publicKeyRaw instanceof Uint8Array) || publicKeyRaw.length !== 32) {
    throw new Error('Public key must be a 32-byte Uint8Array')
  }
  const spki = createEd25519Spki(publicKeyRaw)
  return await crypto.subtle.importKey('spki', spki, { name: 'Ed25519' }, true, ['verify'])
}

// Helper function to create PKCS#8 format for Ed25519 private key
function createEd25519Pkcs8(privateKeyRaw) {
  // PKCS#8 prefix for Ed25519: 0x302e020100300506032b657004220420
  const prefix = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20])

  const pkcs8 = new Uint8Array(prefix.length + privateKeyRaw.length)
  pkcs8.set(prefix, 0)
  pkcs8.set(privateKeyRaw, prefix.length)

  return pkcs8
}

// Helper function to derive Ed25519 public key from private key
async function deriveEd25519PublicKey(privateKeyRaw) {
  const pkcs8 = createEd25519Pkcs8(privateKeyRaw)
  const tempKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign'])

  // Export as JWK to get public key
  const jwk = await crypto.subtle.exportKey('jwk', tempKey)

  // Convert base64url to raw bytes
  const publicKeyB64 = jwk.x.replace(/-/g, '+').replace(/_/g, '/')
  const padding = publicKeyB64.length % 4 === 0 ? 0 : 4 - (publicKeyB64.length % 4)
  const publicKeyBytes = atob(publicKeyB64 + '='.repeat(padding))

  return new Uint8Array(Array.from(publicKeyBytes, (c) => c.charCodeAt(0)))
}

async function parsePacket(packetBytes) {
  if (!(packetBytes instanceof Uint8Array)) {
    throw new Error('Packet must be a Uint8Array')
  }

  let data = packetBytes

  // Remove HDLC framing (0x7E delimiters)
  if (data.length >= 2 && data[0] === 0x7e) {
    let endIndex = data.length - 1
    while (endIndex > 0 && data[endIndex] !== 0x7e) {
      endIndex--
    }

    if (endIndex > 0 && data[endIndex] === 0x7e) {
      data = data.slice(1, endIndex)
    } else {
      data = data.slice(1)
    }
  } else if (data.length >= 1 && data[data.length - 1] === 0x7e) {
    data = data.slice(0, -1)
  }

  if (data.length < 3) {
    throw new Error('Packet too short: minimum 3 bytes required (header + context)')
  }

  let offset = 0

  // Parse HEADER (2 bytes)
  const headerByte1 = data[offset++]
  const hops = data[offset++]

  // Parse header byte 1 bit fields
  const ifacFlag = (headerByte1 & 0x80) >> 7
  const headerType = (headerByte1 & 0x40) >> 6
  const propagationType = (headerByte1 & 0x30) >> 4
  const destinationType = (headerByte1 & 0x0c) >> 2
  const packetType = headerByte1 & 0x03

  // Parse IFAC field if present
  let ifac = null
  if (ifacFlag === 1) {
    if (offset >= data.length) {
      throw new Error('Packet truncated: IFAC field missing')
    }
    ifac = data[offset++]
  }

  // Parse ADDRESSES field
  const addressCount = headerType === 0 ? 1 : 2
  const addressBytes = addressCount * 16

  if (offset + addressBytes > data.length) {
    throw new Error(`Packet truncated: need ${addressBytes} bytes for ${addressCount} address(es)`)
  }

  const addresses = []
  for (let i = 0; i < addressCount; i++) {
    addresses.push(data.slice(offset, offset + 16))
    offset += 16
  }

  // Parse CONTEXT field
  if (offset >= data.length) {
    throw new Error('Packet truncated: context field missing')
  }
  const context = data[offset++]

  // Parse DATA field (remaining bytes)
  const dataPayload = offset < data.length ? data.slice(offset) : new Uint8Array(0)

  // Map enums to human-readable strings
  const packetTypeNames = ['data', 'announce', 'linkreq', 'proof']
  const propagationTypeNames = ['broadcast', 'transport', 'reserved', 'reserved']
  const destinationTypeNames = ['single', 'group', 'plain', 'link']

  const result = {
    type: packetTypeNames[packetType] || `unknown(${packetType})`,
    hops: hops,
    context: context,
    ifacFlag: ifacFlag === 1,
    headerType: headerType,
    propagationType: propagationTypeNames[propagationType] || `unknown(${propagationType})`,
    destinationType: destinationTypeNames[destinationType] || `unknown(${destinationType})`,
    addresses: addresses,
    destinationHash: addresses[0] || null,
    sourceHash: addresses.length > 1 ? addresses[1] : null,
    data: dataPayload,
    dataLength: dataPayload.length,
    ifac: ifac,
    raw: {
      headerByte1: headerByte1,
      packetTypeRaw: packetType,
      propagationTypeRaw: propagationType,
      destinationTypeRaw: destinationType
    }
  }

  // Add packet-type specific parsing
  if (result.type === 'announce') {
    // For announce packets, pass the entire packet data for signature verification
    result.announce = await parseAnnounceData(dataPayload, data)
  }

  return result
}

// Updated parseAnnounceData function with correct signature verification
async function parseAnnounceData(announceData, fullPacketData) {
  if (announceData.length < 96) {
    // 32 (pubkey) + 64 (signature) minimum
    return { error: 'Announce data too short' }
  }

  // Public key is first 32 bytes
  const publicKey = announceData.slice(0, 32)

  // Signature is last 64 bytes
  const signature = announceData.slice(-64)

  // Everything between public key and signature is application data
  const applicationData = announceData.slice(32, -64)

  // The signed data is the entire packet EXCEPT the signature
  // This includes: header + addresses + context + (public key + app data)
  const signatureStartInFullPacket = fullPacketData.length - 64
  const signedData = fullPacketData.slice(0, signatureStartInFullPacket)

  // Verify signature
  let signatureValid = null
  try {
    // Import the Ed25519 public key for verification
    const spki = createEd25519Spki(publicKey)
    const publicKeyForVerification = await crypto.subtle.importKey('spki', spki, { name: 'Ed25519' }, false, ['verify'])

    // Verify the signature against the signed data
    signatureValid = await crypto.subtle.verify('Ed25519', publicKeyForVerification, signature, signedData)
  } catch (error) {
    console.error('Signature verification failed:', error)
    signatureValid = false
  }

  return {
    publicKey: publicKey,
    applicationData: applicationData,
    signature: signature,
    signatureValid: signatureValid,
    signedData: signedData // For debugging
  }
}

// Helper function to create SPKI format for Ed25519 public key (if not already defined)
function createEd25519Spki(publicKeyRaw) {
  // SPKI prefix for Ed25519: 0x302a300506032b6570032100
  const prefix = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00])

  const spki = new Uint8Array(prefix.length + publicKeyRaw.length)
  spki.set(prefix, 0)
  spki.set(publicKeyRaw, prefix.length)

  return spki
}

console.log('Load data from nomad files')
const peersettings = unpack(await readFile('test/b/nomad/storage/peersettings'))
const directory = unpack(await readFile('test/b/nomad/storage/directory'))
console.log('Peer Settings', peersettings)
console.log('Directory', directory)
const ratchets = {}
console.log('Ratchets: ')
for await (const f of glob('test/b/nomad/storage/lxmf/ratchets/*')) {
  const name = f.replace(/test\/b\/nomad\/storage\/lxmf\/ratchets\/(.+)\.ratchets/g, '$1')
  ratchets[name] = unpack(new Uint8Array(await readFile(f)))
  console.log('  ', name, ratchets[name])
}
const identity = await parseReticulumIdentity(new Uint8Array(await readFile('test/b/nomad/storage/identity')))
console.log('Identity', identity)

console.log('TEST parse reticulum packet')
const p = '7E 21 00 51 AD A5 7B 3C 8B C0 5C 4A 4E 82 FE C1 D0 68 F1 00 72 A1 CD 99 DB 8D 0A A2 52 43 E4 BA 3E 9B 79 1F 8A 7F A3 8C 23 05 B7 91 A7 75 F2 18 74 11 85 50 0D C3 9F 12 7C 03 14 84 D3 DB 63 A3 DF B0 72 36 C7 12 E2 E8 EE E8 F8 94 93 84 A1 31 AF 76 5B 17 6E C6 0B C3 18 E2 C0 F0 D9 08 D6 C0 DB 86 1D 00 68 CD B7 13 B8 6D 70 71 E2 BF 00 FE ED 0E AD 10 50 F3 85 EE CB C6 E2 E7 47 90 23 6E BB 81 7B E0 92 C9 B9 30 AC 1A FF 15 A4 4C 48 3F 26 19 BD 81 EE 1A 49 A2 78 4F 6D E2 C4 29 BC 2B 93 A0 8B 75 1A 1A 78 A7 D5 12 8E 17 AB 23 29 C7 81 B9 D9 19 FD 2F 3A 70 2B 81 C4 A0 62 ED 57 12 41 10 EA E3 C4 BE 18 02 92 C4 0E 41 6E 6F 6E 79 6D 6F 75 73 20 50 65 65 72 C0 7E'.split(' ').map((n) => parseInt(n, 16))
const packet = await parsePacket(new Uint8Array(p))
console.log('Packet:', packet)

console.log('TEST key-loading from nomad identity, and use it to sign')
const message = 'Hello from Reticulum!'
const signature = await identity.sign(message)
console.log('Signature:', new Uint8Array(signature))
console.log('Signature valid:', await identity.verify(message, signature))
console.log('External verification:', await identity.verify(message, signature, await importPublicKey(identity.ed25519PublicKeyRaw)))
