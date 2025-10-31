// this is a central collection of utils you will need in any reticulum implementation

import { cbc } from '@noble/ciphers/aes.js'
import { ed25519, x25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { hmac } from '@noble/hashes/hmac.js'
import { hkdf as hkdfReal } from '@noble/hashes/hkdf.js'
import { unpack as msgunpack, pack as msgpack } from 'msgpackr'
import { hexToBytes, bytesToHex, randomBytes, concatBytes, equalBytes } from '@noble/curves/utils.js'

export { hexToBytes, bytesToHex, randomBytes, concatBytes, equalBytes, msgunpack, msgpack, sha256 }

export const hmacSha256 = (key, data) => hmac(sha256, key, data)

export function hkdf(length, deriveFrom, salt, context = new Uint8Array(0)) {
  const hashLen = 32
  if (!length || length < 1) {
    throw new Error('Invalid output key length')
  }
  if (!deriveFrom || deriveFrom.length === 0) {
    throw new Error('Cannot derive key from empty input material')
  }
  if (!salt || salt.length === 0) {
    salt = new Uint8Array(hashLen)
  }
  return hkdfReal(sha256, deriveFrom, salt, context, length)
}

function pkcs7Pad(data, bs = 16) {
  const l = data.length
  const n = bs - (l % bs)
  const padding = new Uint8Array(n).fill(n)
  const result = new Uint8Array(l + n)
  result.set(data)
  result.set(padding, l)
  return result
}

function pkcs7Unpad(data) {
  if (data.length === 0) {
    return data
  }

  const paddingLength = data[data.length - 1]

  // Validate padding length
  if (paddingLength === 0 || paddingLength > 16 || paddingLength > data.length) {
    return data // Don't throw, just return as-is
  }

  // Verify ALL padding bytes are correct
  for (let i = data.length - paddingLength; i < data.length; i++) {
    if (data[i] !== paddingLength) {
      return data // Invalid padding, return as-is
    }
  }

  return data.slice(0, data.length - paddingLength)
}

export function aesCbcDecrypt(key, iv, ciphertext) {
  const cipher = cbc(key, iv)
  const result = cipher.decrypt(ciphertext)

  // Always try to unpad, but don't throw if invalid
  return pkcs7Unpad(result)
}

export function aesCbcEncrypt(key, iv, plaintext) {
  const cipher = cbc(key, iv)
  // Noble does NOT auto-pad on encrypt, so we must pad manually
  const padded = pkcs7Pad(plaintext)
  return cipher.encrypt(padded)
}

export function ed25519Sign(data, privateKey) {
  return ed25519.sign(data, privateKey)
}

export function ed25519Validate(publicKey, signature, message) {
  try {
    return ed25519.verify(signature, message, publicKey)
  } catch (e) {
    return false
  }
}

export function x25519Exchange(privateKey, publicKey) {
  return x25519.getSharedSecret(privateKey, publicKey)
}

export function identityCreate() {
  const encryptPrivate = randomBytes(32)
  const encryptPublic = x25519.getPublicKey(encryptPrivate)
  const signPrivate = randomBytes(32)
  const signPublic = ed25519.getPublicKey(signPrivate)
  return {
    public: { encrypt: encryptPublic, sign: signPublic },
    private: { encrypt: encryptPrivate, sign: signPrivate }
  }
}

export function getIdentityFromBytes(privateIdentityBytes) {
  if (privateIdentityBytes.length !== 64) {
    throw new Error('Private identity must be 64 bytes')
  }
  const encryptPrivate = privateIdentityBytes.slice(0, 32)
  const signPrivate = privateIdentityBytes.slice(32, 64)
  const encryptPublic = x25519.getPublicKey(encryptPrivate)
  const signPublic = ed25519.getPublicKey(signPrivate)
  return {
    public: {
      encrypt: encryptPublic,
      sign: signPublic
    },
    private: {
      encrypt: encryptPrivate,
      sign: signPrivate
    }
  }
}

export function x25519PrivateCreateNew() {
  return randomBytes(32)
}

export function x25519PublicForPrivate(privateRatchet) {
  return x25519.getPublicKey(privateRatchet)
}
