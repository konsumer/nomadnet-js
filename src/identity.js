import { x25519, ed25519 } from '@noble/curves/ed25519.js'
import { randomBytes } from '@noble/curves/utils.js'
import { hex } from './index.js' // Import hex helper

// Base class for all identities
export class ReticulmIdentity {
  constructor() {
    this.publicKey = null // Full 64-byte public key
    this.encryptPublicKey = null // X25519 32 bytes
    this.signPublicKey = null // Ed25519 32 bytes
    this.identityHash = null // SHA-256 of full public key, truncated to 16 bytes
    this.nameHash = null // 10 bytes
    this.aspectFilter = null
  }

  async init() {
    // Calculate identity hash (16 bytes)
    const fullHash = await crypto.subtle.digest('SHA-256', this.publicKey)
    this.identityHash = new Uint8Array(fullHash).slice(0, 16)
    return this
  }

  // Get destination hash for specific aspect
  async getDestinationHash(aspectName = null) {
    if (!aspectName) {
      return this.identityHash
    }

    // Calculate name hash for aspect
    const nameData = new TextEncoder().encode(aspectName)
    const nameFullHash = await crypto.subtle.digest('SHA-256', nameData)
    this.nameHash = new Uint8Array(nameFullHash).slice(0, 10)

    // Destination hash = truncate(sha256(identityHash + nameHash))
    const combined = new Uint8Array([...this.identityHash, ...this.nameHash])
    const destHash = await crypto.subtle.digest('SHA-256', combined)
    return new Uint8Array(destHash).slice(0, 16)
  }

  // Serialize to compact base64 string
  serialize() {
    const data = {
      pk: btoa(String.fromCharCode(...this.publicKey)),
      nh: this.nameHash ? btoa(String.fromCharCode(...this.nameHash)) : null,
      af: this.aspectFilter
    }
    return btoa(JSON.stringify(data))
  }

  // Helper to convert to hex for display
  toString() {
    return hex(this.identityHash, '', true).substring(0, 16)
  }
}

// Destination identity (from announce packet, public keys only)
export class DestinationIdentity extends ReticulmIdentity {
  constructor() {
    super()
    this.appData = null
    this.ratchet = null
    this.lastAnnounce = null
  }

  // Create from announce packet data
  static async fromAnnounce(announceData) {
    const dest = new DestinationIdentity()

    // Extract keys from announce
    dest.publicKey = new Uint8Array([...announceData.keyEncryptBytes, ...announceData.keyVerifyBytes])
    dest.encryptPublicKey = announceData.keyEncryptBytes
    dest.signPublicKey = announceData.keyVerifyBytes
    dest.appData = announceData.appData
    dest.lastAnnounce = Date.now()

    // Import verify key for signature verification
    dest.verifyKey = await crypto.subtle.importKey('raw', dest.signPublicKey, { name: 'Ed25519' }, false, ['verify'])

    await dest.init()
    return dest
  }

  // Verify a signature from this identity
  async verify(signature, data) {
    return crypto.subtle.verify('Ed25519', this.verifyKey, signature, data)
  }

  // Create shared secret with a sender identity
  getSharedSecret(senderPrivateKey) {
    return x25519.getSharedSecret(senderPrivateKey, this.encryptPublicKey)
  }

  // Deserialize
  static async fromSerialized(serialized) {
    const data = JSON.parse(atob(serialized))
    const dest = new DestinationIdentity()

    dest.publicKey = new Uint8Array([...atob(data.pk)].map((c) => c.charCodeAt(0)))
    dest.encryptPublicKey = dest.publicKey.slice(0, 32)
    dest.signPublicKey = dest.publicKey.slice(32)

    if (data.nh) {
      dest.nameHash = new Uint8Array([...atob(data.nh)].map((c) => c.charCodeAt(0)))
    }
    dest.aspectFilter = data.af

    dest.verifyKey = await crypto.subtle.importKey('raw', dest.signPublicKey, { name: 'Ed25519' }, false, ['verify'])

    await dest.init()
    return dest
  }
}

// Sender identity (with private keys for signing and encryption)
export class SenderIdentity extends ReticulmIdentity {
  constructor() {
    super()
    this.encryptPrivateKey = null // X25519 private
    this.signPrivateKey = null // Ed25519 private
    this.signKeyPair = null // Web Crypto key pair
  }

  // Generate new identity
  // Replace the generate method in SenderIdentity
  static async generate(aspectName = null) {
    const sender = new SenderIdentity()

    // Generate X25519 key pair for encryption
    sender.encryptPrivateKey = randomBytes(32)
    sender.encryptPublicKey = x25519.getPublicKey(sender.encryptPrivateKey)

    // Generate Ed25519 key pair - use Web Crypto as primary
    sender.signKeyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])

    // Export keys to raw bytes for consistency with Reticulum
    const webCryptoPublicKey = await crypto.subtle.exportKey('raw', sender.signKeyPair.publicKey)
    sender.signPublicKey = new Uint8Array(webCryptoPublicKey)

    // Export private key in PKCS8 format, then extract the raw 32 bytes
    const webCryptoPrivateKey = await crypto.subtle.exportKey('pkcs8', sender.signKeyPair.privateKey)
    // Extract the 32-byte private key from PKCS8 (last 32 bytes)
    sender.signPrivateKey = new Uint8Array(webCryptoPrivateKey).slice(-32)

    // Combine public keys as Reticulum does
    sender.publicKey = new Uint8Array([
      ...sender.encryptPublicKey, // First 32: X25519
      ...sender.signPublicKey // Last 32: Ed25519
    ])

    // Set aspect filter and calculate name hash if provided
    sender.aspectFilter = aspectName
    if (aspectName) {
      const nameData = new TextEncoder().encode(aspectName)
      const nameFullHash = await crypto.subtle.digest('SHA-256', nameData)
      sender.nameHash = new Uint8Array(nameFullHash).slice(0, 10)
    }

    await sender.init()
    return sender
  }

  // Sign data
  async sign(data) {
    // Use Web Crypto for signing
    return new Uint8Array(await crypto.subtle.sign('Ed25519', this.signKeyPair.privateKey, data))
  }

  // Create shared secret with destination
  getSharedSecret(destinationPublicKey) {
    const destEncryptKey = destinationPublicKey.slice(0, 32)
    return x25519.getSharedSecret(this.encryptPrivateKey, destEncryptKey)
  }

  // Serialize (includes private keys!)
  serialize() {
    const data = {
      pk: btoa(String.fromCharCode(...this.publicKey)),
      ep: btoa(String.fromCharCode(...this.encryptPrivateKey)),
      sp: btoa(String.fromCharCode(...this.signPrivateKey)),
      nh: this.nameHash ? btoa(String.fromCharCode(...this.nameHash)) : null,
      af: this.aspectFilter
    }
    return btoa(JSON.stringify(data))
  }

  // Deserialize
  static async fromSerialized(serialized) {
    const data = JSON.parse(atob(serialized))
    const sender = new SenderIdentity()

    sender.publicKey = new Uint8Array([...atob(data.pk)].map((c) => c.charCodeAt(0)))
    sender.encryptPrivateKey = new Uint8Array([...atob(data.ep)].map((c) => c.charCodeAt(0)))
    sender.signPrivateKey = new Uint8Array([...atob(data.sp)].map((c) => c.charCodeAt(0)))

    sender.encryptPublicKey = sender.publicKey.slice(0, 32)
    sender.signPublicKey = sender.publicKey.slice(32)

    if (data.nh) {
      sender.nameHash = new Uint8Array([...atob(data.nh)].map((c) => c.charCodeAt(0)))
    }
    sender.aspectFilter = data.af

    // Import signing key to Web Crypto
    sender.signKeyPair = {
      privateKey: await crypto.subtle.importKey(
        'pkcs8',
        // Need to wrap raw key in PKCS8 format
        wrapEd25519PrivateKey(sender.signPrivateKey),
        { name: 'Ed25519' },
        true,
        ['sign']
      ),
      publicKey: await crypto.subtle.importKey('raw', sender.signPublicKey, { name: 'Ed25519' }, true, ['verify'])
    }

    await sender.init()
    return sender
  }
}

// Helper function to wrap Ed25519 private key in PKCS8 format
function wrapEd25519PrivateKey(privateKey) {
  // PKCS8 wrapper for Ed25519 private key
  const pkcs8Header = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20])
  return new Uint8Array([...pkcs8Header, ...privateKey])
}
