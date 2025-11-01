import { describe, it } from 'node:test'
import assert from 'node:assert'

// prettier-ignore
import {
  hexToBytes,
  bytesToHex,
  randomBytes,
  concatBytes,
  equalBytes,
  msgunpack,
  msgpack,
  sha256,
  hmacSha256,
  hkdf,
  aesCbcDecrypt,
  aesCbcEncrypt,
  ed25519Sign,
  ed25519Validate,
  x25519Exchange,
  ed25519PublicForPrivate,
  x25519PublicForPrivate
} from '../src/utils.js'

describe('Utility Functions', () => {
  describe('hexToBytes and bytesToHex', () => {
    it('should convert hex string to bytes and back', () => {
      const hex = 'deadbeef'
      const bytes = hexToBytes(hex)
      assert.strictEqual(bytes.length, 4)
      assert.strictEqual(bytesToHex(bytes), hex)
    })

    it('should handle empty string', () => {
      const hex = ''
      const bytes = hexToBytes(hex)
      assert.strictEqual(bytes.length, 0)
      assert.strictEqual(bytesToHex(bytes), hex)
    })
  })

  describe('randomBytes', () => {
    it('should generate random bytes of specified length', () => {
      const bytes = randomBytes(32)
      assert.strictEqual(bytes.length, 32)
      assert.ok(bytes instanceof Uint8Array)
    })

    it('should generate different random values', () => {
      const bytes1 = randomBytes(16)
      const bytes2 = randomBytes(16)
      assert.ok(!equalBytes(bytes1, bytes2))
    })
  })

  describe('concatBytes', () => {
    it('should concatenate multiple byte arrays', () => {
      const a = new Uint8Array([1, 2, 3])
      const b = new Uint8Array([4, 5, 6])
      const c = new Uint8Array([7, 8, 9])
      const result = concatBytes(a, b, c)
      assert.deepStrictEqual(result, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9]))
    })
  })

  describe('equalBytes', () => {
    it('should return true for equal byte arrays', () => {
      const a = new Uint8Array([1, 2, 3, 4])
      const b = new Uint8Array([1, 2, 3, 4])
      assert.ok(equalBytes(a, b))
    })

    it('should return false for different byte arrays', () => {
      const a = new Uint8Array([1, 2, 3, 4])
      const b = new Uint8Array([1, 2, 3, 5])
      assert.ok(!equalBytes(a, b))
    })
  })

  describe('msgpack and msgunpack', () => {
    it('should pack and unpack objects', () => {
      const obj = { name: 'test', value: 123, nested: { foo: 'bar' } }
      const packed = msgpack(obj)
      const unpacked = msgunpack(packed)
      assert.deepStrictEqual(unpacked, obj)
    })

    it('should pack and unpack arrays', () => {
      const arr = [1, 2, 3, 'test', { key: 'value' }]
      const packed = msgpack(arr)
      const unpacked = msgunpack(packed)
      assert.deepStrictEqual(unpacked, arr)
    })
  })

  describe('sha256', () => {
    it('should hash data correctly', () => {
      const data = new Uint8Array([1, 2, 3, 4])
      const hash = sha256(data)
      assert.strictEqual(hash.length, 32)
      assert.ok(hash instanceof Uint8Array)
    })

    it('should produce consistent hashes', () => {
      const data = new Uint8Array([1, 2, 3, 4])
      const hash1 = sha256(data)
      const hash2 = sha256(data)
      assert.ok(equalBytes(hash1, hash2))
    })
  })

  describe('hmacSha256', () => {
    it('should compute HMAC-SHA256', () => {
      const key = new Uint8Array(32).fill(1)
      const data = new Uint8Array([1, 2, 3, 4])
      const hmac = hmacSha256(key, data)
      assert.strictEqual(hmac.length, 32)
      assert.ok(hmac instanceof Uint8Array)
    })

    it('should produce consistent HMACs', () => {
      const key = new Uint8Array(32).fill(1)
      const data = new Uint8Array([1, 2, 3, 4])
      const hmac1 = hmacSha256(key, data)
      const hmac2 = hmacSha256(key, data)
      assert.ok(equalBytes(hmac1, hmac2))
    })
  })

  describe('hkdf', () => {
    it('should derive key of specified length', () => {
      const deriveFrom = new Uint8Array(32).fill(1)
      const salt = new Uint8Array(32).fill(2)
      const derived = hkdf(64, deriveFrom, salt)
      assert.strictEqual(derived.length, 64)
    })

    it('should use default salt if not provided', () => {
      const deriveFrom = new Uint8Array(32).fill(1)
      const derived = hkdf(32, deriveFrom, null)
      assert.strictEqual(derived.length, 32)
    })

    it('should accept context parameter', () => {
      const deriveFrom = new Uint8Array(32).fill(1)
      const salt = new Uint8Array(32).fill(2)
      const context = new Uint8Array([3, 4, 5])
      const derived = hkdf(32, deriveFrom, salt, context)
      assert.strictEqual(derived.length, 32)
    })

    it('should throw for invalid length', () => {
      const deriveFrom = new Uint8Array(32).fill(1)
      const salt = new Uint8Array(32).fill(2)
      assert.throws(() => hkdf(0, deriveFrom, salt), /Invalid output key length/)
    })

    it('should throw for empty input material', () => {
      const salt = new Uint8Array(32).fill(2)
      assert.throws(() => hkdf(32, new Uint8Array(0), salt), /Cannot derive key from empty input material/)
    })
  })

  describe('AES-CBC Encryption/Decryption', () => {
    it('should encrypt and decrypt data correctly', () => {
      const key = new Uint8Array(32).fill(1)
      const iv = new Uint8Array(16).fill(2)
      const plaintext = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8])

      const ciphertext = aesCbcEncrypt(key, iv, plaintext)
      const decrypted = aesCbcDecrypt(key, iv, ciphertext)

      assert.ok(equalBytes(plaintext, decrypted))
    })

    it('should handle data that requires padding', () => {
      const key = new Uint8Array(32).fill(1)
      const iv = new Uint8Array(16).fill(2)
      const plaintext = new Uint8Array([1, 2, 3]) // Not block-aligned

      const ciphertext = aesCbcEncrypt(key, iv, plaintext)
      const decrypted = aesCbcDecrypt(key, iv, ciphertext)

      assert.ok(equalBytes(plaintext, decrypted))
    })

    it('should handle block-aligned data', () => {
      const key = new Uint8Array(32).fill(1)
      const iv = new Uint8Array(16).fill(2)
      const plaintext = new Uint8Array(16).fill(3) // Exactly one block

      const ciphertext = aesCbcEncrypt(key, iv, plaintext)
      const decrypted = aesCbcDecrypt(key, iv, ciphertext)

      assert.ok(equalBytes(plaintext, decrypted))
    })
  })

  describe('Ed25519 Key Generation', () => {
    it('should create 32-byte private key', () => {
      const privateKey = randomBytes(32)
      assert.strictEqual(privateKey.length, 32)
      assert.ok(privateKey instanceof Uint8Array)
    })

    it('should derive public key from private key', () => {
      const privateKey = randomBytes(32)
      const publicKey = ed25519PublicForPrivate(privateKey)
      assert.strictEqual(publicKey.length, 32)
      assert.ok(publicKey instanceof Uint8Array)
    })
  })

  describe('Ed25519 Signing and Validation', () => {
    it('should sign and validate message', () => {
      const privateKey = randomBytes(32)
      const publicKey = ed25519PublicForPrivate(privateKey)
      const message = new Uint8Array([1, 2, 3, 4, 5])

      const signature = ed25519Sign(message, privateKey)
      assert.strictEqual(signature.length, 64)

      const isValid = ed25519Validate(publicKey, signature, message)
      assert.ok(isValid)
    })

    it('should reject invalid signature', () => {
      const privateKey = randomBytes(32)
      const publicKey = ed25519PublicForPrivate(privateKey)
      const message = new Uint8Array([1, 2, 3, 4, 5])

      const signature = ed25519Sign(message, privateKey)
      signature[0] ^= 1 // Corrupt signature

      const isValid = ed25519Validate(publicKey, signature, message)
      assert.ok(!isValid)
    })

    it('should reject signature with wrong message', () => {
      const privateKey = randomBytes(32)
      const publicKey = ed25519PublicForPrivate(privateKey)
      const message1 = new Uint8Array([1, 2, 3, 4, 5])
      const message2 = new Uint8Array([1, 2, 3, 4, 6])

      const signature = ed25519Sign(message1, privateKey)
      const isValid = ed25519Validate(publicKey, signature, message2)
      assert.ok(!isValid)
    })
  })

  describe('X25519 Key Generation', () => {
    it('should create 32-byte private key', () => {
      const privateKey = randomBytes(32)
      assert.strictEqual(privateKey.length, 32)
      assert.ok(privateKey instanceof Uint8Array)
    })

    it('should derive public key from private key', () => {
      const privateKey = randomBytes(32)
      const publicKey = x25519PublicForPrivate(privateKey)
      assert.strictEqual(publicKey.length, 32)
      assert.ok(publicKey instanceof Uint8Array)
    })
  })

  describe('X25519 Key Exchange', () => {
    it('should perform key exchange correctly', () => {
      const alicePrivate = randomBytes(32)
      const alicePublic = x25519PublicForPrivate(alicePrivate)

      const bobPrivate = randomBytes(32)
      const bobPublic = x25519PublicForPrivate(bobPrivate)

      const aliceShared = x25519Exchange(alicePrivate, bobPublic)
      const bobShared = x25519Exchange(bobPrivate, alicePublic)

      assert.ok(equalBytes(aliceShared, bobShared))
    })

    it('should produce 32-byte shared secret', () => {
      const privateKey = randomBytes(32)
      const publicKey = x25519PublicForPrivate(randomBytes(32))

      const shared = x25519Exchange(privateKey, publicKey)
      assert.strictEqual(shared.length, 32)
      assert.ok(shared instanceof Uint8Array)
    })
  })
})
