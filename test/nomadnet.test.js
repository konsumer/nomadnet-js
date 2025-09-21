import { describe, test } from 'node:test'
import assert from 'node:assert'
import { generateIdentity, getIdentityHash, getDestinationHash, signData, verifySignature, buildPacketHeader, buildAnnouncePacket, parsePacketHeader, parsePacket, parseAnnouncePacket, buildLxmfMessage, parseLxmfMessage, hdlcEncode, hdlcDecode, saveIdentity, parseIdentityBytes, PACKET_ANNOUNCE, HEADER_1, HEADER_2, DESTINATION_SINGLE, TRUNCATED_HASHLENGTH, HDLC_FLAG, HDLC_ESC } from '../src/index.js'

describe('Identity and Crypto', () => {
  test('generateIdentity creates valid identity', async () => {
    const identity = generateIdentity()

    assert.ok(identity.privateKey instanceof Uint8Array)
    assert.strictEqual(identity.privateKey.length, 32)
    assert.ok(identity.publicKey instanceof Uint8Array)
    assert.strictEqual(identity.publicKey.length, 32)
    assert.ok(identity.hash instanceof Uint8Array)
    assert.strictEqual(identity.hash.length, TRUNCATED_HASHLENGTH)
  })

  test('getIdentityHash produces consistent hash', async () => {
    const identity = generateIdentity()
    const hash1 = getIdentityHash(identity.publicKey)
    const hash2 = getIdentityHash(identity.publicKey)

    assert.deepStrictEqual(hash1, hash2)
    assert.strictEqual(hash1.length, TRUNCATED_HASHLENGTH)
  })

  test('getDestinationHash generates proper destination hash', async () => {
    const identity = generateIdentity()
    const appName = 'TestApp'
    const aspects = 'test.aspect'

    const hash = getDestinationHash(identity, appName, aspects)

    assert.ok(hash instanceof Uint8Array)
    assert.strictEqual(hash.length, TRUNCATED_HASHLENGTH)
  })

  test('signData and verifySignature work correctly', async () => {
    const identity = generateIdentity()
    const data = new Uint8Array([1, 2, 3, 4, 5])

    const signature = signData(identity.privateKey, data)
    assert.ok(signature instanceof Uint8Array)
    assert.strictEqual(signature.length, 64)

    const isValid = verifySignature(identity.publicKey, data, signature)
    assert.ok(isValid)

    // Test with wrong data
    const wrongData = new Uint8Array([5, 4, 3, 2, 1])
    const isInvalid = verifySignature(identity.publicKey, wrongData, signature)
    assert.ok(!isInvalid)
  })

  test('saveIdentity and parseIdentityBytes work correctly', async () => {
    const originalIdentity = generateIdentity()

    // Save the identity
    const packed = saveIdentity(originalIdentity)
    assert.ok(packed instanceof Uint8Array)
    assert.ok(packed.length > 64) // Should contain at least two 32-byte keys plus msgpack overhead

    // Parse it back
    const parsedIdentity = parseIdentityBytes(packed)

    // Verify all fields match
    assert.deepStrictEqual(parsedIdentity.privateKey, originalIdentity.privateKey)
    assert.deepStrictEqual(parsedIdentity.publicKey, originalIdentity.publicKey)
    assert.deepStrictEqual(parsedIdentity.hash, originalIdentity.hash)
  })

  test('parseIdentityBytes handles invalid data', async () => {
    // Test with invalid msgpack data
    assert.throws(() => {
      parseIdentityBytes(new Uint8Array([0x00, 0x01, 0x02]))
    }, /Failed to parse identity/)

    // Test with wrong array length
    const msgpack = await import('msgpackr')
    const wrongFormat = msgpack.pack([new Uint8Array(32)]) // Only one key
    assert.throws(() => {
      parseIdentityBytes(wrongFormat)
    }, /Invalid identity format/)

    // Test with wrong key sizes
    const wrongSizes = msgpack.pack([new Uint8Array(16), new Uint8Array(16)])
    assert.throws(() => {
      parseIdentityBytes(wrongSizes)
    }, /Invalid key sizes/)
  })
})

describe('Packet Building and Parsing', () => {
  test('buildPacketHeader creates correct header', async () => {
    const header = buildPacketHeader({
      ifac: false,
      headerType: HEADER_1,
      propagationType: 0,
      destinationType: DESTINATION_SINGLE,
      packetType: PACKET_ANNOUNCE,
      hops: 5
    })

    assert.strictEqual(header.length, 2)
    assert.strictEqual(header[1], 5) // hops
  })

  test('parsePacketHeader correctly parses header', async () => {
    const header = buildPacketHeader({
      ifac: false,
      headerType: HEADER_1,
      propagationType: 0,
      destinationType: DESTINATION_SINGLE,
      packetType: PACKET_ANNOUNCE,
      hops: 7
    })

    const parsed = parsePacketHeader(header)

    assert.strictEqual(parsed.ifac, false)
    assert.strictEqual(parsed.headerType, HEADER_1)
    assert.strictEqual(parsed.propagationType, 0)
    assert.strictEqual(parsed.destinationType, DESTINATION_SINGLE)
    assert.strictEqual(parsed.packetType, PACKET_ANNOUNCE)
    assert.strictEqual(parsed.hops, 7)
  })

  test('buildAnnouncePacket creates valid announce packet', async () => {
    const identity = generateIdentity()
    const appName = 'TestApp'
    const aspects = 'test.aspect'

    const packet = buildAnnouncePacket(identity, appName, aspects)

    assert.ok(packet instanceof Uint8Array)
    assert.ok(packet.length > 100) // Should have header + destination + context + public key + signature
  })

  test('parseAnnouncePacket correctly parses announce', async () => {
    const identity = generateIdentity()
    const appName = 'TestApp'
    const aspects = 'test.aspect'

    const packet = buildAnnouncePacket(identity, appName, aspects)
    const parsed = parseAnnouncePacket(packet)

    assert.deepStrictEqual(parsed.publicKey, identity.publicKey)
    assert.strictEqual(parsed.name, appName)
    assert.strictEqual(parsed.aspects, aspects)
    assert.ok(parsed.isValid)
  })
})

describe('LXMF Messages', () => {
  test('buildLxmfMessage creates valid message', async () => {
    const sourceIdentity = generateIdentity()
    const destinationHash = new Uint8Array(TRUNCATED_HASHLENGTH).fill(0xff)
    const content = 'Hello, World!'
    const title = 'Test Message'
    const fields = { test: 'value' }

    const message = buildLxmfMessage(sourceIdentity, destinationHash, content, title, fields)

    assert.deepStrictEqual(message.destination, destinationHash)
    assert.deepStrictEqual(message.source, sourceIdentity.hash)
    assert.ok(message.signature instanceof Uint8Array)
    assert.strictEqual(message.signature.length, 64)
    assert.ok(message.payload instanceof Uint8Array)
    assert.ok(message.messageId instanceof Uint8Array)
    assert.strictEqual(message.messageId.length, 32)
  })

  test('parseLxmfMessage correctly parses message', async () => {
    const sourceIdentity = generateIdentity()
    const destinationHash = new Uint8Array(TRUNCATED_HASHLENGTH).fill(0xff)
    const content = 'Hello, World!'
    const title = 'Test Message'
    const fields = { test: 'value' }

    const message = buildLxmfMessage(sourceIdentity, destinationHash, content, title, fields)

    // For testing, we need to pack the message in the expected format
    const msgpack = await import('msgpackr')
    const packedMessage = msgpack.pack([message.destination, message.source, message.signature, message.payload])

    const parsed = parseLxmfMessage(packedMessage)

    assert.deepStrictEqual(parsed.destination, destinationHash)
    assert.deepStrictEqual(parsed.source, sourceIdentity.hash)
    assert.strictEqual(parsed.content, content)
    assert.strictEqual(parsed.title, title)
    assert.deepStrictEqual(parsed.fields, fields)
    assert.ok(parsed.timestamp > 0)
  })
})

describe('HDLC Framing', () => {
  test('hdlcEncode properly encodes data', async () => {
    const data = new Uint8Array([1, 2, 3, HDLC_FLAG, 4, 5])
    const encoded = hdlcEncode(data)

    assert.strictEqual(encoded[0], HDLC_FLAG)
    assert.strictEqual(encoded[encoded.length - 1], HDLC_FLAG)
    assert.ok(encoded.length > data.length + 2) // Should be larger due to escaping
  })

  test('hdlcDecode properly decodes data', async () => {
    const originalData = new Uint8Array([1, 2, 3, HDLC_FLAG, 4, 5])
    const encoded = hdlcEncode(originalData)
    const decoded = hdlcDecode(encoded)

    assert.deepStrictEqual(decoded, originalData)
  })

  test('hdlcEncode and hdlcDecode handle escaping correctly', async () => {
    const data = new Uint8Array([HDLC_FLAG, HDLC_ESC, 0x01, 0x02])
    const encoded = hdlcEncode(data)
    const decoded = hdlcDecode(encoded)

    assert.deepStrictEqual(decoded, data)
  })

  test('hdlcDecode returns null for incomplete frame', async () => {
    const data = new Uint8Array([HDLC_FLAG, 1, 2, 3]) // No closing flag
    const decoded = hdlcDecode(data)

    assert.strictEqual(decoded, null)
  })
})

describe('Integration Tests', () => {
  test('complete announce flow', async () => {
    // Create identity
    const identity = generateIdentity()
    const appName = 'IntegrationTest'
    const aspects = 'test.integration'

    // Build announce packet
    const announcePacket = buildAnnouncePacket(identity, appName, aspects)

    // Parse the packet
    const parsedPacket = parsePacket(announcePacket)
    assert.strictEqual(parsedPacket.header.packetType, PACKET_ANNOUNCE)

    // Parse announce data
    const parsedAnnounce = parseAnnouncePacket(announcePacket)
    assert.ok(parsedAnnounce.isValid)
    assert.strictEqual(parsedAnnounce.name, appName)
    assert.strictEqual(parsedAnnounce.aspects, aspects)

    // Verify the public key matches
    assert.deepStrictEqual(parsedAnnounce.publicKey, identity.publicKey)
  })

  test('packet header types', async () => {
    // Test HEADER_1 (single address)
    const header1 = buildPacketHeader({
      ifac: false,
      headerType: HEADER_1,
      propagationType: 0,
      destinationType: DESTINATION_SINGLE,
      packetType: 0,
      hops: 0
    })

    const parsed1 = parsePacketHeader(header1)
    assert.strictEqual(parsed1.headerType, HEADER_1)

    // Test HEADER_2 (two addresses)
    const header2 = buildPacketHeader({
      ifac: false,
      headerType: HEADER_2,
      propagationType: 1,
      destinationType: DESTINATION_SINGLE,
      packetType: 0,
      hops: 3
    })

    const parsed2 = parsePacketHeader(header2)
    assert.strictEqual(parsed2.headerType, HEADER_2)
    assert.strictEqual(parsed2.propagationType, 1)
    assert.strictEqual(parsed2.hops, 3)
  })
})
