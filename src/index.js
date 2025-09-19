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

// Handle an anounce-packet, and pull out important fields
export async function parseAnnouncePacket(packetBytes) {
  const payloadEndIndex = packetBytes.length - 64 - 16
  const msgpackPayloadBytes = packetBytes.slice(2, payloadEndIndex)
  const [destinationHash, ed25519PublicKeyBuffer, appData] = msgpack.unpack(msgpackPayloadBytes)
  const x25519PublicKeyBuffer = ed25519.edwardsToMontgomeryPub(ed25519PublicKeyBuffer)
  const x25519PublicKey = await crypto.subtle.importKey('raw', x25519PublicKeyBuffer, { name: 'X25519', namedCurve: 'X25519' }, false, [])
  const keyset = concatBytes(x25519PublicKeyBuffer, ed25519PublicKeyBuffer)
  const keysetHash = new Uint8Array(await crypto.subtle.digest('SHA-256', keyset))
  return { x25519PublicKey, keysetHash, appData, destinationHash }
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
