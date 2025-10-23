import { describe, test } from 'node:test'
import assert from 'node:assert'

// Import your functions (adjust path as needed)
import { identityCreate, getDestinationHash, ratchetCreateNew, ratchetGetPublic, encodePacket, decodePacket, buildAnnounce, announceParse, buildProof, proofValidate, buildData, messageDecrypt, getMessageId } from '../src/index.js'

describe('Packet Encoding/Decoding', () => {
  test('encodePacket and decodePacket - single header', () => {
    const destHash = new Uint8Array(16).fill(0xaa)
    const data = new TextEncoder().encode('hello')

    const packet = {
      destinationHash: destHash,
      packetType: 0,
      destinationType: 0,
      hops: 0,
      context: 0,
      contextFlag: false,
      data
    }

    const encoded = encodePacket(packet)
    const decoded = decodePacket(encoded)

    assert.deepEqual(decoded.destinationHash, destHash)
    assert.equal(decoded.packetType, 0)
    assert.equal(decoded.hops, 0)
    assert.equal(decoded.context, 0)
    assert.deepEqual(decoded.data, data)
    assert.equal(decoded.headerType, false)
  })

  test('encodePacket and decodePacket - double header', () => {
    const destHash = new Uint8Array(16).fill(0xaa)
    const sourceHash = new Uint8Array(16).fill(0xbb)
    const data = new TextEncoder().encode('test')

    const packet = {
      destinationHash: destHash,
      sourceHash,
      headerType: true,
      packetType: 1,
      destinationType: 0,
      hops: 2,
      context: 1,
      contextFlag: true,
      data
    }

    const encoded = encodePacket(packet)
    const decoded = decodePacket(encoded)

    assert.deepEqual(decoded.destinationHash, destHash)
    assert.deepEqual(decoded.sourceHash, sourceHash)
    assert.equal(decoded.headerType, true)
    assert.equal(decoded.context, 1)
    assert.equal(decoded.hops, 2)
  })
})

describe('Identity and Destination', () => {
  test('identityCreate generates valid identity', () => {
    const identity = identityCreate()

    assert.ok(identity.public)
    assert.ok(identity.private)
    assert.equal(identity.public.encrypt.length, 32)
    assert.equal(identity.public.sign.length, 32)
    assert.equal(identity.private.encrypt.length, 32)
    assert.equal(identity.private.sign.length, 32)
  })

  test('getDestinationHash generates 16-byte hash', () => {
    const identity = identityCreate()
    const destHash = getDestinationHash(identity, 'lxmf.delivery')

    assert.equal(destHash.length, 16)
  })

  test('getDestinationHash is deterministic', () => {
    const identity = identityCreate()
    const hash1 = getDestinationHash(identity, 'lxmf.delivery')
    const hash2 = getDestinationHash(identity, 'lxmf.delivery')

    assert.deepEqual(hash1, hash2)
  })
})

describe('Ratchet', () => {
  test('ratchetCreateNew generates 32-byte key', () => {
    const ratchet = ratchetCreateNew()
    assert.equal(ratchet.length, 32)
  })

  test('ratchetGetPublic derives public key', () => {
    const ratchetPriv = ratchetCreateNew()
    const ratchetPub = ratchetGetPublic(ratchetPriv)

    assert.equal(ratchetPub.length, 32)
    assert.notDeepEqual(ratchetPriv, ratchetPub)
  })
})

describe('Announce', () => {
  test('buildAnnounce and announceParse - no explicit ratchet', () => {
    const identity = identityCreate()
    const destination = getDestinationHash(identity, 'lxmf.delivery')

    const announceBytes = buildAnnounce(identity, destination, 'lxmf.delivery')
    const packet = decodePacket(announceBytes)

    console.log('contextFlag:', packet.contextFlag)
    console.log('context:', packet.context)

    const announce = announceParse(packet)

    console.log('valid:', announce.valid)
    console.log('keyPubEncrypt match:', Buffer.from(announce.keyPubEncrypt).equals(Buffer.from(identity.public.encrypt)))

    assert.equal(announce.valid, true)
    assert.deepEqual(announce.keyPubEncrypt, identity.public.encrypt)
    assert.deepEqual(announce.keyPubSignature, identity.public.sign)
    assert.deepEqual(announce.destinationHash, destination)
  })

  test('buildAnnounce with app data', () => {
    const identity = identityCreate()
    const destination = getDestinationHash(identity, 'lxmf.delivery')
    const appData = new TextEncoder().encode('test data')

    const announceBytes = buildAnnounce(identity, destination, 'lxmf.delivery', null, appData)
    const packet = decodePacket(announceBytes)
    const announce = announceParse(packet)

    assert.equal(announce.valid, true)
    assert.deepEqual(announce.appData, appData)
  })

  test('announceParse rejects invalid signature', () => {
    const identity = identityCreate()
    const destination = getDestinationHash(identity, 'lxmf.delivery')

    const announceBytes = buildAnnounce(identity, destination, 'lxmf.delivery')
    const packet = decodePacket(announceBytes)

    // Corrupt the signature
    packet.data[100] ^= 0xff

    const announce = announceParse(packet)
    assert.equal(announce.valid, false)
  })
})

describe('Proof', () => {
  test('buildProof creates valid proof packet', () => {
    const identity = identityCreate()
    const destination = getDestinationHash(identity, 'lxmf.delivery')

    // Create a dummy data packet to prove
    const dataPacket = {
      destinationHash: destination,
      packetType: 0,
      destinationType: 0,
      hops: 0,
      context: 0,
      contextFlag: false,
      data: new TextEncoder().encode('test')
    }
    const dataBytes = encodePacket(dataPacket)
    const dataParsed = decodePacket(dataBytes)

    const messageId = getMessageId(dataParsed)
    const proofBytes = buildProof(identity, dataParsed, messageId)
    const proofPacket = decodePacket(proofBytes)

    assert.equal(proofPacket.packetType, 3) // PACKET_PROOF
    assert.ok(proofPacket.data.length >= 64)
  })

  test('proofValidate verifies valid proof', () => {
    const identity = identityCreate()
    const destination = getDestinationHash(identity, 'lxmf.delivery')

    const dataPacket = {
      destinationHash: destination,
      packetType: 0,
      destinationType: 0,
      hops: 0,
      context: 0,
      contextFlag: false,
      data: new TextEncoder().encode('test')
    }
    const dataBytes = encodePacket(dataPacket)
    const dataParsed = decodePacket(dataBytes)
    const messageId = getMessageId(dataParsed)

    const proofBytes = buildProof(identity, dataParsed, messageId)
    const proofPacket = decodePacket(proofBytes)

    const isValid = proofValidate(proofPacket, identity, messageId)
    assert.equal(isValid, true)
  })

  test('proofValidate rejects wrong identity', () => {
    const identity1 = identityCreate()
    const identity2 = identityCreate()
    const destination = getDestinationHash(identity1, 'lxmf.delivery')

    const dataPacket = {
      destinationHash: destination,
      packetType: 0,
      destinationType: 0,
      hops: 0,
      context: 0,
      contextFlag: false,
      data: new TextEncoder().encode('test')
    }
    const dataBytes = encodePacket(dataPacket)
    const dataParsed = decodePacket(dataBytes)
    const messageId = getMessageId(dataParsed)

    const proofBytes = buildProof(identity1, dataParsed, messageId)
    const proofPacket = decodePacket(proofBytes)

    const isValid = proofValidate(proofPacket, identity2, messageId)
    assert.equal(isValid, false)
  })
})

describe('Data Encryption/Decryption', () => {
  test('buildData and messageDecrypt - basic encryption', () => {
    const sender = identityCreate()
    const recipient = identityCreate()
    const recipientDest = getDestinationHash(recipient, 'lxmf.delivery')

    // Create recipient announce
    const announceBytes = buildAnnounce(recipient, recipientDest, 'lxmf.delivery')
    const announcePacket = decodePacket(announceBytes)
    const recipientAnnounce = announceParse(announcePacket)

    const plaintext = new TextEncoder().encode('Hello, World!')
    const dataBytes = buildData(sender, recipientAnnounce, plaintext)
    const dataPacket = decodePacket(dataBytes)

    const decrypted = messageDecrypt(dataPacket, recipient)
    assert.deepEqual(decrypted, plaintext)
  })

  test('buildData and messageDecrypt - with ratchet', () => {
    const sender = identityCreate()
    const recipient = identityCreate()
    const recipientDest = getDestinationHash(recipient, 'lxmf.delivery')
    const ratchetPriv = ratchetCreateNew()
    const ratchetPub = ratchetGetPublic(ratchetPriv)

    // Create recipient announce with ratchet
    const announceBytes = buildAnnounce(recipient, recipientDest, 'lxmf.delivery', ratchetPub)
    const announcePacket = decodePacket(announceBytes)
    const recipientAnnounce = announceParse(announcePacket)

    const plaintext = new TextEncoder().encode('Secret message')
    const dataBytes = buildData(sender, recipientAnnounce, plaintext)
    const dataPacket = decodePacket(dataBytes)

    // Try decrypting with ratchet
    const decrypted = messageDecrypt(dataPacket, recipient, [ratchetPriv])
    assert.deepEqual(decrypted, plaintext)
  })

  test('messageDecrypt fails with wrong identity', () => {
    const sender = identityCreate()
    const recipient = identityCreate()
    const wrongRecipient = identityCreate()
    const recipientDest = getDestinationHash(recipient, 'lxmf.delivery')

    const announceBytes = buildAnnounce(recipient, recipientDest, 'lxmf.delivery')
    const announcePacket = decodePacket(announceBytes)
    const recipientAnnounce = announceParse(announcePacket)

    const plaintext = new TextEncoder().encode('Secret')
    const dataBytes = buildData(sender, recipientAnnounce, plaintext)
    const dataPacket = decodePacket(dataBytes)

    const decrypted = messageDecrypt(dataPacket, wrongRecipient)
    assert.equal(decrypted, null)
  })

  test('messageDecrypt handles corrupted data', () => {
    const sender = identityCreate()
    const recipient = identityCreate()
    const recipientDest = getDestinationHash(recipient, 'lxmf.delivery')

    const announceBytes = buildAnnounce(recipient, recipientDest, 'lxmf.delivery')
    const announcePacket = decodePacket(announceBytes)
    const recipientAnnounce = announceParse(announcePacket)

    const plaintext = new TextEncoder().encode('Test')
    const dataBytes = buildData(sender, recipientAnnounce, plaintext)
    const dataPacket = decodePacket(dataBytes)

    // Corrupt the data
    dataPacket.data[50] ^= 0xff

    const decrypted = messageDecrypt(dataPacket, recipient)
    assert.equal(decrypted, null)
  })
})

describe('Message ID', () => {
  test('getMessageId generates 32-byte hash', () => {
    const identity = identityCreate()
    const destination = getDestinationHash(identity, 'lxmf.delivery')

    const packet = {
      destinationHash: destination,
      packetType: 0,
      destinationType: 0,
      hops: 0,
      context: 0,
      contextFlag: false,
      data: new TextEncoder().encode('test')
    }
    const packetBytes = encodePacket(packet)
    const parsed = decodePacket(packetBytes)

    const messageId = getMessageId(parsed)
    assert.equal(messageId.length, 32)
  })

  test('getMessageId is deterministic', () => {
    const identity = identityCreate()
    const destination = getDestinationHash(identity, 'lxmf.delivery')

    const packet = {
      destinationHash: destination,
      packetType: 0,
      destinationType: 0,
      hops: 0,
      context: 0,
      contextFlag: false,
      data: new TextEncoder().encode('test')
    }
    const packetBytes = encodePacket(packet)
    const parsed = decodePacket(packetBytes)

    const id1 = getMessageId(parsed)
    const id2 = getMessageId(parsed)
    assert.deepEqual(id1, id2)
  })
})

describe('End-to-End', () => {
  test('complete announce -> data -> proof flow', () => {
    // Setup
    const alice = identityCreate()
    const bob = identityCreate()
    const aliceDest = getDestinationHash(alice, 'lxmf.delivery')
    const bobDest = getDestinationHash(bob, 'lxmf.delivery')

    // Bob announces
    const bobAnnounceBytes = buildAnnounce(bob, bobDest, 'lxmf.delivery')
    const bobAnnouncePacket = decodePacket(bobAnnounceBytes)
    const bobAnnounce = announceParse(bobAnnouncePacket)
    assert.equal(bobAnnounce.valid, true)

    // Alice sends data to Bob
    const message = new TextEncoder().encode('Hello Bob!')
    const dataBytes = buildData(alice, bobAnnounce, message)
    const dataPacket = decodePacket(dataBytes)

    // Bob decrypts
    const decrypted = messageDecrypt(dataPacket, bob)
    assert.deepEqual(decrypted, message)

    // Bob sends proof
    const messageId = getMessageId(dataPacket)
    const proofBytes = buildProof(bob, dataPacket, messageId)
    const proofPacket = decodePacket(proofBytes)

    // Alice validates proof
    const isValid = proofValidate(proofPacket, bob, messageId)
    assert.equal(isValid, true)
  })
})
