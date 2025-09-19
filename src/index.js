import { pack, unpack } from 'msgpackr'

const msgpack = obj => new Uint8Array(pack(obj))
const msgunpack = unpack

export const sha256 = async data => crypto.subtle.digest('SHA-256', data)

// Get a CryptoKey as Uint8Array
export async function exportCryptoKeyAsBytes(key) {
  if (!key.extractable) {
    throw new Error("Key is not extractable.")
  }
  return new Uint8Array(await crypto.subtle.exportKey('pkcs8', key))
}

// Generate a keypair for sign/verify
// { publicKey, privateKey }
export const ed25519Generate = async () => crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])

// Sign some Uint8Array data
export const ed25519Sign = async (privateKey, data) => crypto.subtle.sign({ name: "Ed25519" }, privateKey, data)

// Verify a signature of some Uint8Array data
export const ed25519Verify = async (publicKey, signature, data) => crypto.subtle.verify({ name: "Ed25519" }, publicKey, signature, data)

// Convert Uint8Array to hex string
export const bytesToHex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')

// Convert hex string to Uint8Array  
export const hexToBytes = hex => new Uint8Array(hex.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) ?? [])
