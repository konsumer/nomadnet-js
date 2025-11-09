// Crypto utilities using Node.js native crypto module

import { createHash, createHmac, randomBytes as cryptoRandomBytes, hkdf as cryptoHkdf, createCipheriv, createDecipheriv, generateKeyPairSync, createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify, diffieHellman } from 'node:crypto'
import { promisify } from 'node:util'

const hkdfAsync = promisify(cryptoHkdf)

export const randomBytes = (length) => new Uint8Array(cryptoRandomBytes(length))

export const bytesToHex = (b) => new Uint8Array(Buffer.from(b).toString('hex'))

export const hexToBytes = (h) => new Uint8Array(Buffer.from(h, 'hex'))

/**
 * Create PKCS8 DER for Ed25519 private key
 * Based on: https://www.rfc-editor.org/rfc/rfc8410
 */
function createEd25519PrivateKeyDER(privateKey) {
  // PKCS#8 structure for Ed25519:
  // SEQUENCE (48 bytes total)
  //   INTEGER (version = 0)
  //   SEQUENCE (algorithm)
  //     OID (Ed25519)
  //   OCTET STRING
  //     OCTET STRING (32-byte private key)

  const oid = Buffer.from([0x06, 0x03, 0x2b, 0x65, 0x70]) // Ed25519 OID
  const keyOctetString = Buffer.concat([
    Buffer.from([0x04, 0x20]), // OCTET STRING, 32 bytes
    Buffer.from(privateKey)
  ])

  const algorithmSequence = Buffer.concat([
    Buffer.from([0x30, 0x05]), // SEQUENCE, 5 bytes
    oid
  ])

  const wrappedKey = Buffer.concat([
    Buffer.from([0x04, 0x22]), // OCTET STRING, 34 bytes (includes inner octet string)
    keyOctetString
  ])

  const sequence = Buffer.concat([
    Buffer.from([0x02, 0x01, 0x00]), // INTEGER version = 0
    algorithmSequence,
    wrappedKey
  ])

  return Buffer.concat([
    Buffer.from([0x30, 0x2e]), // SEQUENCE, 46 bytes
    sequence
  ])
}

/**
 * Create SPKI DER for Ed25519 public key
 */
function createEd25519PublicKeyDER(publicKey) {
  // SPKI structure for Ed25519:
  // SEQUENCE
  //   SEQUENCE (algorithm)
  //     OID (Ed25519)
  //   BIT STRING (public key)

  const oid = Buffer.from([0x06, 0x03, 0x2b, 0x65, 0x70]) // Ed25519 OID

  const algorithmSequence = Buffer.concat([
    Buffer.from([0x30, 0x05]), // SEQUENCE, 5 bytes
    oid
  ])

  const publicKeyBitString = Buffer.concat([
    Buffer.from([0x03, 0x21, 0x00]), // BIT STRING, 33 bytes (32 + 1 for unused bits)
    Buffer.from(publicKey)
  ])

  const sequence = Buffer.concat([algorithmSequence, publicKeyBitString])

  return Buffer.concat([
    Buffer.from([0x30, 0x2a]), // SEQUENCE, 42 bytes
    sequence
  ])
}

/**
 * Create PKCS8 DER for X25519 private key
 */
function createX25519PrivateKeyDER(privateKey) {
  const oid = Buffer.from([0x06, 0x03, 0x2b, 0x65, 0x6e]) // X25519 OID
  const keyOctetString = Buffer.concat([
    Buffer.from([0x04, 0x20]), // OCTET STRING, 32 bytes
    Buffer.from(privateKey)
  ])

  const algorithmSequence = Buffer.concat([
    Buffer.from([0x30, 0x05]), // SEQUENCE, 5 bytes
    oid
  ])

  const wrappedKey = Buffer.concat([
    Buffer.from([0x04, 0x22]), // OCTET STRING, 34 bytes
    keyOctetString
  ])

  const sequence = Buffer.concat([
    Buffer.from([0x02, 0x01, 0x00]), // INTEGER version = 0
    algorithmSequence,
    wrappedKey
  ])

  return Buffer.concat([
    Buffer.from([0x30, 0x2e]), // SEQUENCE, 46 bytes
    sequence
  ])
}

/**
 * Create SPKI DER for X25519 public key
 */
function createX25519PublicKeyDER(publicKey) {
  const oid = Buffer.from([0x06, 0x03, 0x2b, 0x65, 0x6e]) // X25519 OID

  const algorithmSequence = Buffer.concat([
    Buffer.from([0x30, 0x05]), // SEQUENCE, 5 bytes
    oid
  ])

  const publicKeyBitString = Buffer.concat([
    Buffer.from([0x03, 0x21, 0x00]), // BIT STRING, 33 bytes
    Buffer.from(publicKey)
  ])

  const sequence = Buffer.concat([algorithmSequence, publicKeyBitString])

  return Buffer.concat([
    Buffer.from([0x30, 0x2a]), // SEQUENCE, 42 bytes
    sequence
  ])
}

/**
 * Generate a 64-byte private identity: 32 bytes X25519 + 32 bytes Ed25519
 * @returns {Uint8Array} 64-byte identity
 */
export function private_identity() {
  const x25519_priv = randomBytes(32)
  const ed25519_priv = randomBytes(32)

  const result = new Uint8Array(64)
  result.set(x25519_priv, 0)
  result.set(ed25519_priv, 32)
  return result
}

/**
 * Get public identity from private identity
 * @param {Uint8Array} identity_priv - 64-byte private identity
 * @returns {Uint8Array} 64-byte public identity
 */
export function public_identity(identity_priv) {
  if (identity_priv.length !== 64) {
    throw new Error('identity_priv must be 64 bytes')
  }

  const x25519_priv = identity_priv.slice(0, 32)
  const ed25519_priv = identity_priv.slice(32, 64)

  const x25519_pub = x25519_public_for_private(x25519_priv)
  const ed25519_pub = ed25519_public_for_private(ed25519_priv)

  const result = new Uint8Array(64)
  result.set(x25519_pub, 0)
  result.set(ed25519_pub, 32)
  return result
}

/**
 * Generate a 32-byte private ratchet (X25519 private key)
 * @returns {Uint8Array} 32-byte ratchet
 */
export function private_ratchet() {
  return randomBytes(32)
}

/**
 * Get public ratchet from private ratchet
 * @param {Uint8Array} ratchet_priv - 32-byte private ratchet
 * @returns {Uint8Array} 32-byte public ratchet
 */
export function public_ratchet(ratchet_priv) {
  if (ratchet_priv.length !== 32) {
    throw new Error('ratchet_priv must be 32 bytes')
  }
  return x25519_public_for_private(ratchet_priv)
}

/**
 * SHA256 hash
 * @param {Uint8Array} data
 * @returns {Uint8Array} 32-byte hash
 */
export function sha256(data) {
  const hash = createHash('sha256')
  hash.update(data)
  return new Uint8Array(hash.digest())
}

/**
 * HMAC-SHA256
 * @param {Uint8Array} key
 * @param {Uint8Array} data
 * @returns {Uint8Array} 32-byte HMAC
 */
export function hmac_sha256(key, data) {
  const hmac = createHmac('sha256', key)
  hmac.update(data)
  return new Uint8Array(hmac.digest())
}

/**
 * HKDF key derivation
 * @param {Uint8Array} ikm - Input key material
 * @param {number} length - Output length
 * @param {Uint8Array} salt - Optional salt (default: 32 zero bytes)
 * @param {Uint8Array} info - Optional info (default: empty)
 * @returns {Promise<Uint8Array>} Derived key
 */
export async function hkdf(ikm, length, salt = null, info = null) {
  if (length < 1) {
    throw new Error('Invalid output key length')
  }

  if (!ikm || ikm.length === 0) {
    throw new Error('Cannot derive key from empty input material')
  }

  if (!salt) {
    salt = new Uint8Array(32)
  }

  if (!info) {
    info = new Uint8Array(0)
  }

  const derived = await hkdfAsync('sha256', ikm, salt, info, length)
  return new Uint8Array(derived)
}

/**
 * PKCS7 padding
 * @param {Uint8Array} data
 * @param {number} bs - Block size (default 16)
 * @returns {Uint8Array} Padded data
 */
export function pkcs7_pad(data, bs = 16) {
  const n = bs - (data.length % bs)
  const result = new Uint8Array(data.length + n)
  result.set(data)
  result.fill(n, data.length)
  return result
}

/**
 * PKCS7 unpadding
 * @param {Uint8Array} data
 * @returns {Uint8Array} Unpadded data
 */
export function pkcs7_unpad(data) {
  if (data.length === 0) {
    return data
  }

  const padding_length = data[data.length - 1]
  if (padding_length < 1 || padding_length > 16 || padding_length > data.length) {
    return data
  }

  // Verify padding
  for (let i = data.length - padding_length; i < data.length; i++) {
    if (data[i] !== padding_length) {
      return data
    }
  }

  return data.slice(0, data.length - padding_length)
}

/**
 * AES-CBC encryption
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} iv - 16-byte IV
 * @param {Uint8Array} plaintext
 * @returns {Uint8Array} Ciphertext
 */
export function aes_cbc_encrypt(key, iv, plaintext) {
  const cipher = createCipheriv('aes-256-cbc', key, iv)
  cipher.setAutoPadding(true)

  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()])

  return new Uint8Array(encrypted)
}

/**
 * AES-CBC decryption
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} iv - 16-byte IV
 * @param {Uint8Array} ciphertext
 * @returns {Uint8Array} Plaintext
 */
export function aes_cbc_decrypt(key, iv, ciphertext) {
  const decipher = createDecipheriv('aes-256-cbc', key, iv)
  decipher.setAutoPadding(true)

  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()])

  return new Uint8Array(decrypted)
}

/**
 * Ed25519 sign
 * @param {Uint8Array} private_key - 32-byte private key
 * @param {Uint8Array} message
 * @returns {Uint8Array} 64-byte signature
 */
export function ed25519_sign(private_key, message) {
  const pkcs8Der = createEd25519PrivateKeyDER(private_key)

  const keyObj = createPrivateKey({
    key: pkcs8Der,
    format: 'der',
    type: 'pkcs8'
  })

  const signature = cryptoSign(null, message, keyObj)
  return new Uint8Array(signature)
}

/**
 * Ed25519 verify
 * @param {Uint8Array} signature - 64-byte signature
 * @param {Uint8Array} message
 * @param {Uint8Array} public_key - 32-byte public key
 * @returns {boolean} Valid or not
 */
export function ed25519_validate(signature, message, public_key) {
  try {
    const spkiDer = createEd25519PublicKeyDER(public_key)

    const keyObj = createPublicKey({
      key: spkiDer,
      format: 'der',
      type: 'spki'
    })

    return cryptoVerify(null, message, keyObj, signature)
  } catch {
    return false
  }
}

/**
 * Get Ed25519 public key from private key
 * @param {Uint8Array} private_key - 32-byte private key
 * @returns {Uint8Array} 32-byte public key
 */
export function ed25519_public_for_private(private_key) {
  const pkcs8Der = createEd25519PrivateKeyDER(private_key)

  const keyObj = createPrivateKey({
    key: pkcs8Der,
    format: 'der',
    type: 'pkcs8'
  })

  // Export as SPKI to get public key
  const publicKeyObj = createPublicKey(keyObj)
  const spkiDer = publicKeyObj.export({ type: 'spki', format: 'der' })

  // Extract raw public key from SPKI (last 32 bytes)
  return new Uint8Array(spkiDer.slice(-32))
}

/**
 * X25519 key exchange
 * @param {Uint8Array} private_key - 32-byte private key
 * @param {Uint8Array} public_key - 32-byte public key
 * @returns {Uint8Array} 32-byte shared secret
 */
export function x25519_exchange(private_key, public_key) {
  const pkcs8Der = createX25519PrivateKeyDER(private_key)
  const spkiDer = createX25519PublicKeyDER(public_key)

  const privateKeyObj = createPrivateKey({
    key: pkcs8Der,
    format: 'der',
    type: 'pkcs8'
  })

  const publicKeyObj = createPublicKey({
    key: spkiDer,
    format: 'der',
    type: 'spki'
  })

  // Use the diffieHellman function from crypto module
  const sharedSecret = diffieHellman({
    privateKey: privateKeyObj,
    publicKey: publicKeyObj
  })

  return new Uint8Array(sharedSecret)
}

/**
 * Get X25519 public key from private key
 * @param {Uint8Array} private_key - 32-byte private key
 * @returns {Uint8Array} 32-byte public key
 */
export function x25519_public_for_private(private_key) {
  const pkcs8Der = createX25519PrivateKeyDER(private_key)

  const keyObj = createPrivateKey({
    key: pkcs8Der,
    format: 'der',
    type: 'pkcs8'
  })

  // Export as SPKI to get public key
  const publicKeyObj = createPublicKey(keyObj)
  const spkiDer = publicKeyObj.export({ type: 'spki', format: 'der' })

  // Extract raw public key from SPKI (last 32 bytes)
  return new Uint8Array(spkiDer.slice(-32))
}
