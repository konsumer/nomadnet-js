import { test, describe } from 'node:test'
import { private_identity, public_identity, private_ratchet, public_ratchet, sha256, hmac_sha256, hkdf, pkcs7_pad, pkcs7_unpad, aes_cbc_encrypt, aes_cbc_decrypt, ed25519_sign, ed25519_validate, ed25519_public_for_private, x25519_exchange, x25519_public_for_private } from '../src/crypto.js'

describe('@noble Encryption Helpers', () => {
  describe('Identity Key Generation', () => {
    test('private_identity generates 64 bytes', ({ assert }) => {
      const priv_key = private_identity()
      assert.ok(priv_key instanceof Uint8Array)
      assert.equal(priv_key.length, 64) // 32 bytes X25519 + 32 bytes Ed25519
    })

    test('public_identity derives 64 byte public key', ({ assert }) => {
      const priv_key = private_identity()
      const pub_key = public_identity(priv_key)
      assert.ok(pub_key instanceof Uint8Array)
      assert.equal(pub_key.length, 64) // 32 bytes X25519 pub + 32 bytes Ed25519 pub
    })

    test('public_identity contains both X25519 and Ed25519 keys', ({ assert }) => {
      const priv_key = private_identity()
      const x25519_priv = priv_key.slice(0, 32)
      const ed25519_priv = priv_key.slice(32, 64)

      const pub_key = public_identity(priv_key)
      const x25519_pub = pub_key.slice(0, 32)
      const ed25519_pub = pub_key.slice(32, 64)

      // Verify X25519 public key derivation
      const expected_x25519_pub = x25519_public_for_private(x25519_priv)
      assert.deepEqual(x25519_pub, expected_x25519_pub)

      // Verify Ed25519 public key derivation
      const expected_ed25519_pub = ed25519_public_for_private(ed25519_priv)
      assert.deepEqual(ed25519_pub, expected_ed25519_pub)
    })

    test('public_identity throws with invalid input length', ({ assert }) => {
      assert.throws(() => {
        public_identity(new Uint8Array(10))
      })
      assert.throws(() => {
        public_identity(new Uint8Array(100))
      })
    })
  })

  describe('Ratchet Key Generation', () => {
    test('private_ratchet generates 32 bytes', ({ assert }) => {
      const priv_key = private_ratchet()
      assert.ok(priv_key instanceof Uint8Array)
      assert.equal(priv_key.length, 32)
    })

    test('public_ratchet derives 32 byte public key', ({ assert }) => {
      const priv_key = private_ratchet()
      const pub_key = public_ratchet(priv_key)
      assert.ok(pub_key instanceof Uint8Array)
      assert.equal(pub_key.length, 32)
    })

    test('public_ratchet throws with invalid input', ({ assert }) => {
      assert.throws(() => {
        public_ratchet(new Uint8Array(10))
      })
    })
  })

  describe('Hash Functions', () => {
    test('sha256 produces 32 byte hash', ({ assert }) => {
      const data = new TextEncoder().encode('hello world')
      const result = sha256(data)
      assert.ok(result instanceof Uint8Array)
      assert.equal(result.length, 32)

      // Same input produces same output
      const result2 = sha256(data)
      assert.deepEqual(result, result2)

      // Different input produces different output
      const different_data = new TextEncoder().encode('different')
      const different_result = sha256(different_data)
      assert.notDeepEqual(result, different_result)
    })

    test('hmac_sha256 produces 32 byte HMAC', ({ assert }) => {
      const key = new TextEncoder().encode('secret_key')
      const data = new TextEncoder().encode('message')
      const result = hmac_sha256(key, data)
      assert.ok(result instanceof Uint8Array)
      assert.equal(result.length, 32)

      // Different key produces different result
      const different_key = new TextEncoder().encode('different_key')
      const different_result = hmac_sha256(different_key, data)
      assert.notDeepEqual(result, different_result)

      // Different data produces different result
      const different_data = new TextEncoder().encode('different_message')
      const different_result2 = hmac_sha256(key, different_data)
      assert.notDeepEqual(result, different_result2)
    })
  })

  describe('HKDF', () => {
    test('hkdf derives key of specified length', ({ assert }) => {
      const ikm = new TextEncoder().encode('input_key_material')
      const length = 32
      const result = hkdf(ikm, length)
      assert.ok(result instanceof Uint8Array)
      assert.equal(result.length, length)
    })

    test('hkdf with salt and info', ({ assert }) => {
      const ikm = new TextEncoder().encode('input_key_material')
      const salt = new TextEncoder().encode('salt_value')
      const info = new TextEncoder().encode('info_value')
      const length = 64
      const result = hkdf(ikm, length, salt, info)
      assert.ok(result instanceof Uint8Array)
      assert.equal(result.length, length)
    })

    test('hkdf with different params produces different output', ({ assert }) => {
      const ikm1 = new TextEncoder().encode('input1')
      const ikm2 = new TextEncoder().encode('input2')
      const length = 32
      const result1 = hkdf(ikm1, length)
      const result2 = hkdf(ikm2, length)
      assert.notDeepEqual(result1, result2)
    })

    test('hkdf throws with empty ikm', ({ assert }) => {
      assert.throws(() => {
        hkdf(new Uint8Array(0), 32)
      })
    })
  })

  describe('PKCS7 Padding', () => {
    test('pkcs7_pad pads data to block size', ({ assert }) => {
      const data = new TextEncoder().encode('hello')
      const padded = pkcs7_pad(data, 16)
      assert.equal(padded.length % 16, 0)
      assert.deepEqual(padded.slice(0, data.length), data)

      // Data that's already block-aligned
      const aligned_data = new Uint8Array(16)
      const padded_aligned = pkcs7_pad(aligned_data, 16)
      assert.equal(padded_aligned.length, 32) // Should add full block of padding
    })

    test('pkcs7_unpad removes padding', ({ assert }) => {
      const original = new TextEncoder().encode('hello')
      const padded = pkcs7_pad(original, 16)
      const unpadded = pkcs7_unpad(padded)
      assert.deepEqual(unpadded, original)
    })

    test('pkcs7 pad/unpad roundtrip', ({ assert }) => {
      const test_data = [
        new TextEncoder().encode('short'),
        new TextEncoder().encode('hello world'),
        new TextEncoder().encode('this is a longer message for testing'),
        new Uint8Array(0), // empty data
        new Uint8Array(16).fill(120), // exactly one block
        new Uint8Array(31).fill(120) // one byte short of two blocks
      ]

      for (const data of test_data) {
        const padded = pkcs7_pad(data, 16)
        const unpadded = pkcs7_unpad(padded)
        assert.deepEqual(unpadded, data)
      }
    })
  })

  describe('AES', () => {
    test('aes_cbc_encrypt and decrypt', ({ assert }) => {
      const key = crypto.getRandomValues(new Uint8Array(32)) // 256-bit key
      const iv = crypto.getRandomValues(new Uint8Array(16)) // 128-bit IV
      const plaintext = new TextEncoder().encode('hello world, this is a test message!')

      const ciphertext = aes_cbc_encrypt(key, iv, plaintext)
      const decrypted = aes_cbc_decrypt(key, iv, ciphertext)

      assert.deepEqual(decrypted, plaintext)
    })

    test('different IV produces different ciphertext', ({ assert }) => {
      const key = crypto.getRandomValues(new Uint8Array(32))
      const plaintext = new TextEncoder().encode('test message')
      const iv1 = crypto.getRandomValues(new Uint8Array(16))
      const iv2 = crypto.getRandomValues(new Uint8Array(16))

      const ciphertext1 = aes_cbc_encrypt(key, iv1, plaintext)
      const ciphertext2 = aes_cbc_encrypt(key, iv2, plaintext)

      assert.notDeepEqual(ciphertext1, ciphertext2)
    })

    test('wrong key throws or produces different data', ({ assert }) => {
      const key1 = crypto.getRandomValues(new Uint8Array(32))
      const key2 = crypto.getRandomValues(new Uint8Array(32))
      const iv = crypto.getRandomValues(new Uint8Array(16))
      const plaintext = new TextEncoder().encode('this is a longer test message')

      const ciphertext = aes_cbc_encrypt(key1, iv, plaintext)

      // Noble ciphers may throw on wrong key due to invalid padding
      try {
        const decrypted = aes_cbc_decrypt(key2, iv, ciphertext)
        // If it doesn't throw, the decrypted data should not match the original
        assert.notDeepEqual(decrypted, plaintext)
      } catch (e) {
        // Throwing an error is also acceptable behavior
        assert.ok(true, 'Decryption with wrong key threw an error (expected)')
      }
    })
  })

  describe('Ed25519', () => {
    test('ed25519_sign and verify', ({ assert }) => {
      const private_key = crypto.getRandomValues(new Uint8Array(32))
      const public_key = ed25519_public_for_private(private_key)
      const message = new TextEncoder().encode('test message for signing')

      const signature = ed25519_sign(private_key, message)
      const is_valid = ed25519_validate(signature, message, public_key)

      assert.equal(is_valid, true)
    })

    test('invalid signature fails verification', ({ assert }) => {
      const private_key1 = crypto.getRandomValues(new Uint8Array(32))
      const private_key2 = crypto.getRandomValues(new Uint8Array(32))
      const public_key1 = ed25519_public_for_private(private_key1)
      const public_key2 = ed25519_public_for_private(private_key2)
      const message = new TextEncoder().encode('test message')

      const signature = ed25519_sign(private_key1, message)
      const is_valid = ed25519_validate(signature, message, public_key2)

      assert.equal(is_valid, false)
    })

    test('different message fails verification', ({ assert }) => {
      const private_key = crypto.getRandomValues(new Uint8Array(32))
      const public_key = ed25519_public_for_private(private_key)
      const message1 = new TextEncoder().encode('original message')
      const message2 = new TextEncoder().encode('different message')

      const signature = ed25519_sign(private_key, message1)
      const is_valid = ed25519_validate(signature, message2, public_key)

      assert.equal(is_valid, false)
    })

    test('ed25519_public_for_private derives public key', ({ assert }) => {
      const private_key = crypto.getRandomValues(new Uint8Array(32))
      const public_key = ed25519_public_for_private(private_key)
      assert.ok(public_key instanceof Uint8Array)
      assert.equal(public_key.length, 32)
    })

    test('ed25519 from identity key', ({ assert }) => {
      const identity_priv = private_identity() // 64 bytes: X25519(32) + Ed25519(32)
      const ed25519_priv = identity_priv.slice(32, 64) // Extract Ed25519 private key
      const ed25519_pub = ed25519_public_for_private(ed25519_priv)

      // Test signing with the Ed25519 portion of the identity key
      const message = new TextEncoder().encode('signed with identity key')
      const signature = ed25519_sign(ed25519_priv, message)
      const is_valid = ed25519_validate(signature, message, ed25519_pub)

      assert.equal(is_valid, true)
      assert.equal(ed25519_pub.length, 32)
    })
  })

  describe('X25519', () => {
    test('x25519_key_exchange produces shared secret', ({ assert }) => {
      const alice_private = private_ratchet()
      const bob_private = private_ratchet()

      const alice_public = x25519_public_for_private(alice_private)
      const bob_public = x25519_public_for_private(bob_private)

      // Alice computes shared secret using her private key and Bob's public key
      const shared_secret_alice = x25519_exchange(alice_private, bob_public)

      // Bob computes shared secret using his private key and Alice's public key
      const shared_secret_bob = x25519_exchange(bob_private, alice_public)

      // Both should compute the same shared secret
      assert.deepEqual(shared_secret_alice, shared_secret_bob)
      assert.ok(shared_secret_alice instanceof Uint8Array)
      assert.equal(shared_secret_alice.length, 32)
    })

    test('x25519_public_for_private derives public key', ({ assert }) => {
      const private_key = private_ratchet()
      const public_key = x25519_public_for_private(private_key)
      assert.ok(public_key instanceof Uint8Array)
      assert.equal(public_key.length, 32)
    })

    test('x25519 from identity key', ({ assert }) => {
      const identity_priv = private_identity() // 64 bytes: X25519(32) + Ed25519(32)
      const x25519_priv = identity_priv.slice(0, 32) // Extract X25519 private key
      const x25519_pub = x25519_public_for_private(x25519_priv)

      // Test key exchange with the X25519 portion of the identity key
      const other_priv = private_ratchet()
      const other_pub = x25519_public_for_private(other_priv)

      const shared_secret_1 = x25519_exchange(x25519_priv, other_pub)
      const shared_secret_2 = x25519_exchange(other_priv, x25519_pub)

      assert.deepEqual(shared_secret_1, shared_secret_2)
      assert.equal(shared_secret_1.length, 32)
    })
  })

  describe('Edge Cases', () => {
    test('hash functions with empty inputs', ({ assert }) => {
      // Hash functions with empty data
      const empty_hash = sha256(new Uint8Array(0))
      assert.ok(empty_hash instanceof Uint8Array)
      assert.equal(empty_hash.length, 32)

      // HMAC with empty data
      const empty_hmac = hmac_sha256(new TextEncoder().encode('key'), new Uint8Array(0))
      assert.ok(empty_hmac instanceof Uint8Array)
      assert.equal(empty_hmac.length, 32)
    })
  })

  describe('Identity Key Structure', () => {
    test('identity key contains both X25519 and Ed25519 keys', ({ assert }) => {
      const identity_priv = private_identity()
      assert.equal(identity_priv.length, 64)

      const x25519_part = identity_priv.slice(0, 32)
      const ed25519_part = identity_priv.slice(32, 64)

      // Both parts should be 32 bytes each
      assert.equal(x25519_part.length, 32)
      assert.equal(ed25519_part.length, 32)

      // Both parts should be valid private keys for their respective algorithms
      const x25519_pub = x25519_public_for_private(x25519_part)
      const ed25519_pub = ed25519_public_for_private(ed25519_part)

      assert.equal(x25519_pub.length, 32)
      assert.equal(ed25519_pub.length, 32)
    })

    test('identity key derivation is consistent', ({ assert }) => {
      const identity_priv = private_identity()
      const pub_identity_1 = public_identity(identity_priv)
      const pub_identity_2 = public_identity(identity_priv)

      // Should produce the same result
      assert.deepEqual(pub_identity_1, pub_identity_2)
      assert.equal(pub_identity_1.length, 64)
    })
  })
})
