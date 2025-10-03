// Full end-to-end conversation between Bob & Alice

import { test, describe } from 'node:test'
import assert from 'node:assert'
import * as nomad from '../src/index.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'

const ALLOW_LOG = false
const testLog = ALLOW_LOG ? console.trace : () => {}

let alice, bob
let aliceRatchet, bobRatchet
let aliceAnnounce, bobAnnounce
let bobMessage, aliceMessage

describe('Conversation', () => {
  test('Create two identities (Alice and Bob)', () => {
    alice = nomad.generateIdentity()
    bob = nomad.generateIdentity()
    assert.ok(alice.encPriv.length === 32, 'Alice encryption private key is 32 bytes')
    assert.ok(alice.sigPriv.length === 32, 'Alice signing private key is 32 bytes')
    assert.ok(alice.identityHash.length === 16, 'Alice identity hash is 16 bytes')
    assert.ok(alice.destinationHash.length === 16, 'Alice destination hash is 16 bytes')
    assert.ok(bob.encPriv.length === 32, 'Bob encryption private key is 32 bytes')
    assert.ok(bob.sigPriv.length === 32, 'Bob signing private key is 32 bytes')
    assert.ok(bob.identityHash.length === 16, 'Bob identity hash is 16 bytes')
    assert.ok(bob.destinationHash.length === 16, 'Bob destination hash is 16 bytes')
    testLog('Alice destination:', bytesToHex(alice.destinationHash))
    testLog('Bob destination:', bytesToHex(bob.destinationHash))
  })
  test('Generate ratchet keys for Alice and Bob', () => {
    aliceRatchet = nomad.generateRatchet()
    bobRatchet = nomad.generateRatchet()
    assert.ok(aliceRatchet.ratchetPriv.length === 32, 'Alice ratchet private key is 32 bytes')
    assert.ok(aliceRatchet.ratchetPub.length === 32, 'Alice ratchet public key is 32 bytes')
    assert.ok(bobRatchet.ratchetPriv.length === 32, 'Bob ratchet private key is 32 bytes')
    assert.ok(bobRatchet.ratchetPub.length === 32, 'Bob ratchet public key is 32 bytes')
    testLog('Alice ratchet pub:', bytesToHex(aliceRatchet.ratchetPub))
    testLog('Bob ratchet pub:', bytesToHex(bobRatchet.ratchetPub))
  })

  test.skip('Alice and Bob send ANNOUNCE packets with ratchet info', () => {
    const aliceAnnouncePacket = nomad.buildAnnounce(
      {
        appName: 'lxmf',
        aspects: ['delivery'],
        peerName: 'Alice',
        ratchet: aliceRatchet.ratchetPub,
        transportType: 2,
        destinationType: 0
      },
      alice
    )

    const bobAnnouncePacket = nomad.buildAnnounce(
      {
        encPriv: bob.encPriv,
        sigPriv: bob.sigPriv,
        appName: 'lxmf',
        aspects: ['delivery'],
        peerName: 'Bob',
        ratchet: bobRatchet.ratchetPub,
        transportType: 2,
        destinationType: 0,
        data: 0
      },
      bob
    )

    testLog(aliceAnnouncePacket)
    testLog(bobAnnouncePacket)

    // Serialize to bytes
    const aliceRawAnnounce = nomad.buildPacket(aliceAnnouncePacket)
    const bobRawAnnounce = nomad.buildPacket(bobAnnouncePacket)

    testLog('Alice announce length:', aliceRawAnnounce.length)
    testLog('Alice announce:', bytesToHex(aliceRawAnnounce))
    testLog('Bob announce length:', bobRawAnnounce.length)
    testLog('Bob announce:', bytesToHex(bobRawAnnounce))

    // Parse announces (simulating receiving them)
    aliceAnnounce = nomad.parseAnnounce(nomad.loadPacket(aliceRawAnnounce))
    bobAnnounce = nomad.parseAnnounce(nomad.loadPacket(bobRawAnnounce))

    testLog(aliceAnnounce)
    testLog(bobAnnounce)

    assert.ok(aliceAnnounce.destinationHash, 'Alice announce has destination hash')
    assert.ok(aliceAnnounce.ratchetPub, 'Alice announce has ratchet public key')
    assert.ok(aliceAnnounce.ratchetPub.length === 32, 'Alice ratchet pub is 32 bytes')

    assert.ok(bobAnnounce.destinationHash, 'Bob announce has destination hash')
    assert.ok(bobAnnounce.ratchetPub, 'Bob announce has ratchet public key')
    assert.ok(bobAnnounce.ratchetPub.length === 32, 'Bob ratchet pub is 32 bytes')

    testLog('Alice announce parsed - peer:', aliceAnnounce.peerName)
    testLog('Bob announce parsed - peer:', bobAnnounce.peerName)
  })

  test.skip('Each peer derives ratchet from received announce', () => {
    // Alice stores Bob's ratchet public key from his announce
    const aliceKnowsBobRatchetPub = bobAnnounce.ratchetPub

    // Bob stores Alice's ratchet public key from her announce
    const bobKnowsAliceRatchetPub = aliceAnnounce.ratchetPub

    assert.deepEqual(aliceKnowsBobRatchetPub, bobRatchet.ratchetPub, "Alice learned Bob's ratchet pub key")
    assert.deepEqual(bobKnowsAliceRatchetPub, aliceRatchet.ratchetPub, "Bob learned Alice's ratchet pub key")
  })

  test.skip('Alice sends encrypted message to Bob', () => {
    const message = {
      content: 'Hello Bob, this is Alice!',
      title: '',
      fields: {}
    }

    // Alice encrypts to Bob's ratchet public key
    aliceMessage = nomad.buildMessage(message, bobAnnounce.destinationHash, bobAnnounce.ratchetPub, bobAnnounce.identityHash)

    const rawPacket = nomad.buildPacket(aliceMessage)
    testLog('Alice → Bob packet length:', rawPacket.length)
    testLog('Alice → Bob packet:', bytesToHex(rawPacket))

    // Bob receives and decrypts with his ratchet private key
    const receivedPacket = nomad.loadPacket(rawPacket)
    const decryptedMessage = nomad.processMessage(receivedPacket, bob, [bobRatchet.ratchetPriv])

    assert.equal(decryptedMessage.content, message.content, "Bob decrypted Alice's message")
    testLog('Bob received:', decryptedMessage.content)
  })

  test.skip('Bob sends encrypted message to Alice', () => {
    const message = {
      content: 'Hi Alice, Bob here!',
      title: '',
      fields: {}
    }

    // Bob encrypts to Alice's ratchet public key
    bobMessage = nomad.buildMessage(message, aliceAnnounce.destinationHash, aliceAnnounce.ratchetPub, aliceAnnounce.identityHash)

    const rawPacket = nomad.buildPacket(bobMessage)
    testLog('Bob → Alice packet length:', rawPacket.length)
    testLog('Bob → Alice packet:', bytesToHex(rawPacket))

    // Alice receives and decrypts with her ratchet private key
    const receivedPacket = nomad.loadPacket(rawPacket)
    const decryptedMessage = nomad.processMessage(receivedPacket, alice, [aliceRatchet.ratchetPriv])

    assert.equal(decryptedMessage.content, message.content, "Alice decrypted Bob's message")
    testLog('Alice received:', decryptedMessage.content)
  })

  test.skip('Multiple ratchets support', async () => {
    // Generate a new ratchet for Bob
    const bobNewRatchet = nomad.generateRatchet()

    // Bob announces new ratchet
    const bobNewAnnouncePacket = await nomad.buildAnnounce(
      {
        encPriv: bob.encPriv,
        sigPriv: bob.sigPriv,
        appName: 'lxmf',
        aspects: ['delivery'],
        peerName: 'Bob',
        ratchet: bobNewRatchet.ratchetPub,
        transportType: 2,
        destinationType: 0,
        data: 0
      },
      bob
    )

    const bobNewRawAnnounce = nomad.buildPacket(bobNewAnnouncePacket)
    const bobNewAnnounce = nomad.parseAnnounce(nomad.loadPacket(bobNewRawAnnounce))

    // Alice sends to Bob's NEW ratchet
    const message = {
      content: 'Message to new ratchet',
      title: '',
      fields: {}
    }

    const dataPacket = nomad.buildMessage(message, bobAnnounce.destinationHash, bobAnnounce.ratchetPub, bobAnnounce.identityHash)

    const rawPacket = nomad.buildPacket(dataPacket)
    const receivedPacket = nomad.loadPacket(rawPacket)

    // Bob tries to decrypt with BOTH ratchets (old and new)
    const decryptedMessage = nomad.processMessage(
      receivedPacket,
      bob,
      [bobRatchet.ratchetPriv, bobNewRatchet.ratchetPriv] // Multiple ratchets
    )

    assert.equal(decryptedMessage.content, message.content, 'Bob decrypted with new ratchet from list')
    testLog('Bob (with multiple ratchets) received:', decryptedMessage.content)
  })
})
