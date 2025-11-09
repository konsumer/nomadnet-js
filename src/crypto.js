// Crypto utilities using @noble/* libraries

import { ed25519 } from '@noble/curves/ed25519'
import { x25519 } from '@noble/curves/ed25519'
import { sha256 as sha256Hash } from '@noble/hashes/sha256'
import { hmac } from '@noble/hashes/hmac'
import { hkdf as hkdfDeriv } from '@noble/hashes/hkdf'
import { randomBytes, hexToBytes, bytesToHex } from '@noble/hashes/utils'
import { cbc } from '@noble/ciphers/aes.js'

export { randomBytes, hexToBytes, bytesToHex }

/**
 * Generate a 64-byte private identity: 32 bytes X25519 + 32 bytes Ed25519
 * @returns {Uint8Array} 64-byte identity
 */
export function private_identity() {
  const x25519_priv = randomBytes(32)
  const ed25519_priv = ed25519.utils.randomPrivateKey()
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

  const x25519_pub = x25519.getPublicKey(x25519_priv)
  const ed25519_pub = ed25519.getPublicKey(ed25519_priv)

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
  return x25519.getPublicKey(ratchet_priv)
}

/**
 * SHA256 hash
 * @param {Uint8Array} data
 * @returns {Uint8Array} 32-byte hash
 */
export function sha256(data) {
  return sha256Hash(data)
}

/**
 * HMAC-SHA256
 * @param {Uint8Array} key
 * @param {Uint8Array} data
 * @returns {Uint8Array} 32-byte HMAC
 */
export function hmac_sha256(key, data) {
  return hmac(sha256Hash, key, data)
}

/**
 * HKDF key derivation
 * @param {Uint8Array} ikm - Input key material
 * @param {number} length - Output length
 * @param {Uint8Array} salt - Optional salt (default: 32 zero bytes)
 * @param {Uint8Array} info - Optional info (default: empty)
 * @returns {Uint8Array} Derived key
 */
export function hkdf(ikm, length, salt = null, info = null) {
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
  return hkdfDeriv(sha256Hash, ikm, salt, info, length)
}

/**
 * AES-CBC encryption
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} iv - 16-byte IV
 * @param {Uint8Array} plaintext
 * @returns {Uint8Array} Ciphertext
 */
export function aes_cbc_encrypt(key, iv, plaintext) {
  // @noble/ciphers handles PKCS7 padding automatically
  const cipher = cbc(key, iv)
  return cipher.encrypt(plaintext)
}

/**
 * AES-CBC decryption
 * @param {Uint8Array} key - 32-byte key
 * @param {Uint8Array} iv - 16-byte IV
 * @param {Uint8Array} ciphertext
 * @returns {Uint8Array} Plaintext
 */
export function aes_cbc_decrypt(key, iv, ciphertext) {
  // @noble/ciphers handles PKCS7 unpadding automatically
  const cipher = cbc(key, iv)
  return cipher.decrypt(ciphertext)
}

/**
 * Ed25519 sign
 * @param {Uint8Array} private_key - 32-byte private key
 * @param {Uint8Array} message
 * @returns {Uint8Array} 64-byte signature
 */
export function ed25519_sign(private_key, message) {
  return ed25519.sign(message, private_key)
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
    return ed25519.verify(signature, message, public_key)
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
  return ed25519.getPublicKey(private_key)
}

/**
 * X25519 key exchange
 * @param {Uint8Array} private_key - 32-byte private key
 * @param {Uint8Array} public_key - 32-byte public key
 * @returns {Uint8Array} 32-byte shared secret
 */
export function x25519_exchange(private_key, public_key) {
  return x25519.getSharedSecret(private_key, public_key)
}

/**
 * Get X25519 public key from private key
 * @param {Uint8Array} private_key - 32-byte private key
 * @returns {Uint8Array} 32-byte public key
 */
export function x25519_public_for_private(private_key) {
  return x25519.getPublicKey(private_key)
}
