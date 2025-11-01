import { describe, test } from 'node:test'
import { strict as assert } from 'node:assert'
import { buildPacket, buildAnnounce, buildData, buildLxmf, buildProof, parsePacket, parseAnnounce, parseLxmf, parseProof, getDestinationHash, getMessageId, privateIdentity, publicIdentity, privateRatchet, publicRatchet, PACKET_DATA, PACKET_ANNOUNCE, PACKET_PROOF, CONTEXT_NONE, DEST_SINGLE, TRANSPORT_BROADCAST, TRANSPORT_TRANSPORT } from '../src/index.js'
import { hexToBytes, bytesToHex, equalBytes } from '../src/utils.js'

const encoder = new TextEncoder()

describe('buildPacket', () => {
  test('creates basic DATA packet', () => {
    const destinationHash = hexToBytes('0123456789abcdef0123456789abcdef')
    // Use a hex string with even length - 'deadbeef' is 8 chars = 4 bytes
    const data = new Uint8Array([0xde, 0xad, 0xbe, 0xef])

    const packet = buildPacket({
      hops: 0,
      destinationType: DEST_SINGLE,
      transportType: TRANSPORT_BROADCAST,
      packetType: PACKET_DATA,
      destinationHash,
      data
    })

    assert.ok(packet instanceof Uint8Array)

    // Parse it back to verify structure
    const parsed = parsePacket(packet)
    assert.equal(parsed.packetType, PACKET_DATA)
    assert.equal(parsed.hops, 0)
    assert.equal(parsed.transportType, TRANSPORT_BROADCAST)
    assert.equal(parsed.destinationType, DEST_SINGLE)
    assert.deepEqual(parsed.destinationHash, destinationHash)
    assert.deepEqual(parsed.data, data)
  })

  test('creates packet with context', () => {
    const destinationHash = hexToBytes('0123456789abcdef0123456789abcdef')
    const data = hexToBytes('cafebabe')

    const packet = buildPacket({
      hops: 5,
      destinationType: DEST_SINGLE,
      transportType: TRANSPORT_BROADCAST,
      packetType: PACKET_DATA,
      context: CONTEXT_NONE,
      destinationHash,
      data
    })

    const parsed = parsePacket(packet)
    assert.equal(parsed.contextFlag, 1)
    assert.equal(parsed.hops, 5)
    assert.deepEqual(parsed.context, new Uint8Array([CONTEXT_NONE]))
  })

  test('creates packet with transportId', () => {
    const transportId = hexToBytes('fedcba9876543210fedcba9876543210')
    const destinationHash = hexToBytes('0123456789abcdef0123456789abcdef')
    const data = hexToBytes('1234')

    const packet = buildPacket({
      hops: 2,
      destinationType: DEST_SINGLE,
      transportType: TRANSPORT_TRANSPORT,
      packetType: PACKET_DATA,
      transportId,
      destinationHash,
      data
    })

    const parsed = parsePacket(packet)
    assert.equal(parsed.headerType, 1)
    assert.equal(parsed.transportType, TRANSPORT_TRANSPORT)
    assert.deepEqual(parsed.transportId, transportId)
    assert.deepEqual(parsed.destinationHash, destinationHash)
  })
})

describe('buildAnnounce', () => {
  test('creates valid ANNOUNCE packet without explicit ratchet', () => {
    const identityPriv = privateIdentity()
    const identityPub = publicIdentity(identityPriv)
    const name = 'lxmf.delivery'
    const appData = 'test app data'

    const packet = buildAnnounce(identityPriv, identityPub, name, undefined, appData)

    assert.ok(packet instanceof Uint8Array)

    // Parse and verify
    const parsed = parsePacket(packet)
    assert.equal(parsed.packetType, PACKET_ANNOUNCE)
    assert.equal(parsed.contextFlag, 0) // No explicit ratchet

    const announce = parseAnnounce(parsed)
    assert.ok(announce.valid, 'Signature should be valid')
    assert.deepEqual(announce.keyPubEncrypt, identityPub.slice(0, 32))
    assert.deepEqual(announce.keyPubSignature, identityPub.slice(32, 64))
    assert.deepEqual(announce.ratchetPub, identityPub.slice(0, 32))

    const appDataBytes = new TextEncoder().encode(appData)
    assert.deepEqual(announce.appData, appDataBytes)
  })

  test('creates valid ANNOUNCE packet with explicit ratchet', () => {
    const identityPriv = privateIdentity()
    const identityPub = publicIdentity(identityPriv)
    const ratchetPriv = privateRatchet()
    const ratchetPub = publicRatchet(ratchetPriv)
    const name = 'test.service'

    const packet = buildAnnounce(identityPriv, identityPub, name, ratchetPub)

    const parsed = parsePacket(packet)
    assert.equal(parsed.packetType, PACKET_ANNOUNCE)
    assert.equal(parsed.contextFlag, 1) // Explicit ratchet present

    const announce = parseAnnounce(parsed)
    assert.ok(announce.valid, 'Signature should be valid')
    assert.deepEqual(announce.ratchetPub, ratchetPub)
    assert.ok(!equalBytes(announce.ratchetPub, identityPub.slice(0, 32)))
  })
})

describe('buildData', () => {
  test('creates DATA packet', () => {
    const destinationHash = hexToBytes('0123456789abcdef0123456789abcdef')
    const data = hexToBytes('48656c6c6f') // "Hello"

    const packet = buildData(destinationHash, data)

    const parsed = parsePacket(packet)
    assert.equal(parsed.packetType, PACKET_DATA)
    assert.deepEqual(parsed.destinationHash, destinationHash)
    assert.deepEqual(parsed.data, data)
  })

  test('creates DATA packet with context', () => {
    const destinationHash = hexToBytes('0123456789abcdef0123456789abcdef')
    const data = encoder.encode('test')
    const context = 0x09

    const packet = buildData(destinationHash, data, context)

    const parsed = parsePacket(packet)
    assert.equal(parsed.contextFlag, 1)
    assert.deepEqual(parsed.context, new Uint8Array([context]))
  })

  test('creates DATA packet with transportId', () => {
    const transportId = hexToBytes('abcdefabcdefabcdefabcdefabcdefab')
    const destinationHash = hexToBytes('0123456789abcdef0123456789abcdef')
    const data = encoder.encode('payload')

    const packet = buildData(destinationHash, data, CONTEXT_NONE, transportId)

    const parsed = parsePacket(packet)
    assert.equal(parsed.headerType, 1)
    assert.equal(parsed.transportType, TRANSPORT_TRANSPORT)
    assert.deepEqual(parsed.transportId, transportId)
  })
})

describe('buildLxmf', () => {
  test('creates encrypted LXMF message', () => {
    // Create sender and receiver identities
    const senderPriv = privateIdentity()
    const senderPub = publicIdentity(senderPriv)
    const senderHash = getDestinationHash(senderPub, 'lxmf.delivery')

    const receiverPriv = privateIdentity()
    const receiverPub = publicIdentity(receiverPriv)
    const receiverRatchetPriv = privateRatchet()
    const receiverRatchetPub = publicRatchet(receiverRatchetPriv)

    // Build LXMF message
    const timestamp = Date.now()
    const title = 'Test Message'
    const content = 'Hello, this is a test!'
    const fields = { field1: 'value1' }

    const packet = buildLxmf({
      sourceHash: senderHash,
      senderPrivBytes: senderPriv,
      receiverPubBytes: receiverPub,
      receiverRatchetPub,
      timestamp,
      title,
      content,
      fields
    })

    assert.ok(packet instanceof Uint8Array)

    // Parse and decrypt
    const parsed = parsePacket(packet)
    assert.equal(parsed.packetType, PACKET_DATA)

    const lxmf = parseLxmf(parsed, receiverPub, [receiverRatchetPriv])
    assert.ok(lxmf, 'Should decrypt successfully')
    assert.deepEqual(lxmf.sourceHash, senderHash)
    assert.equal(lxmf.timestamp, timestamp)
    assert.equal(lxmf.title, title)
    assert.equal(lxmf.content, content)
    assert.deepEqual(lxmf.fields, fields)
  })

  test('buildLxmf with implicit ratchet', () => {
    const senderPriv = privateIdentity()
    const senderPub = publicIdentity(senderPriv)
    const senderHash = getDestinationHash(senderPub, 'lxmf.delivery')

    const receiverPriv = privateIdentity()
    const receiverPub = publicIdentity(receiverPriv)
    // Use encryption key as ratchet (implicit)
    const receiverRatchetPriv = receiverPriv.slice(0, 32)
    const receiverRatchetPub = receiverPub.slice(0, 32)

    const packet = buildLxmf({
      sourceHash: senderHash,
      senderPrivBytes: senderPriv,
      receiverPubBytes: receiverPub,
      receiverRatchetPub,
      timestamp: 123456789,
      title: 'Test',
      content: 'Content',
      fields: {}
    })

    const parsed = parsePacket(packet)
    const lxmf = parseLxmf(parsed, receiverPub, [receiverRatchetPriv])

    assert.ok(lxmf, 'Should decrypt with implicit ratchet')
    assert.equal(lxmf.title, 'Test')
    assert.equal(lxmf.content, 'Content')
  })
})

describe('buildProof', () => {
  test('creates valid PROOF packet', () => {
    const senderPriv = privateIdentity()
    const senderPub = publicIdentity(senderPriv)
    const destinationHash = getDestinationHash(senderPub, 'lxmf.delivery')

    // Create a DATA packet to prove
    const dataPacket = buildData(destinationHash, encoder.encode('testdata'))
    const dataPacketHash = getMessageId(dataPacket)

    // Build proof
    const proofPacket = buildProof(dataPacket, senderPriv)

    assert.ok(proofPacket instanceof Uint8Array)

    // Parse and verify
    const parsed = parsePacket(proofPacket)
    assert.equal(parsed.packetType, PACKET_PROOF)
    assert.deepEqual(parsed.destinationHash, destinationHash)

    const proof = parseProof(parsed, senderPub, dataPacketHash)
    assert.ok(proof.valid, 'Proof signature should be valid')
  })

  test('works with packet object', () => {
    const senderPriv = privateIdentity()
    const senderPub = publicIdentity(senderPriv)
    const destinationHash = getDestinationHash(senderPub, 'test.app')

    const dataBytes = buildData(destinationHash, hexToBytes('abc123'))
    const dataParsed = parsePacket(dataBytes)

    // Build proof from parsed packet object
    const proofPacket = buildProof(dataParsed, senderPriv)

    const parsed = parsePacket(proofPacket)
    const proof = parseProof(parsed, senderPub, dataParsed.packetHash)

    assert.ok(proof.valid, 'Proof should validate')
  })
})

describe('rount-trip', () => {
  test('build and parse ANNOUNCE', () => {
    const identityPriv = privateIdentity()
    const identityPub = publicIdentity(identityPriv)
    const name = 'test.service'
    const appData = hexToBytes('010203')

    // Build and parse
    const built = buildAnnounce(identityPriv, identityPub, name, undefined, appData)
    const parsed = parsePacket(built)
    const announce = parseAnnounce(parsed)

    // Verify destination hash matches
    const expectedDestHash = getDestinationHash(identityPub, name)
    assert.deepEqual(parsed.destinationHash, expectedDestHash)
    assert.ok(announce.valid)
    assert.deepEqual(announce.appData, appData)
  })

  test('build and parse complex packet chain', () => {
    // Setup identities
    const alicePriv = privateIdentity()
    const alicePub = publicIdentity(alicePriv)
    const aliceHash = getDestinationHash(alicePub, 'lxmf.delivery')

    const bobPriv = privateIdentity()
    const bobPub = publicIdentity(bobPriv)
    const bobRatchetPriv = privateRatchet()
    const bobRatchetPub = publicRatchet(bobRatchetPriv)

    // 1. Alice sends LXMF message to Bob
    const message = buildLxmf({
      sourceHash: aliceHash,
      senderPrivBytes: alicePriv,
      receiverPubBytes: bobPub,
      receiverRatchetPub: bobRatchetPub,
      timestamp: 1234567890,
      title: 'Hello',
      content: 'Test message',
      fields: { priority: 'high' }
    })

    // 2. Bob receives and decrypts
    const messageParsed = parsePacket(message)
    const lxmf = parseLxmf(messageParsed, bobPub, [bobRatchetPriv])
    assert.ok(lxmf)
    assert.equal(lxmf.title, 'Hello')
    assert.equal(lxmf.content, 'Test message')

    // 3. Bob sends proof back to Alice
    const proof = buildProof(message, bobPriv)
    const proofParsed = parsePacket(proof)
    const proofData = parseProof(proofParsed, bobPub, messageParsed.packetHash)
    assert.ok(proofData.valid)
  })
})
