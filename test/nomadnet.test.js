import { describe, test } from 'node:test'
import assert from 'node:assert'
import { readFile } from 'node:fs/promises'
import { parseReticulum, hex, createAnnounce, createLinkRequest, createLinkedMessage } from '../src/index.js'
import { SenderIdentity, DestinationIdentity } from '../src/identity.js'

// TODO: these are just basic smoke-tests, should put in lots more checks

let sender
let destination
let packetAnnounce
let linkReq
let serialized

describe('SenderIdentity', () => {
  test('generate', async () => {
    sender = await SenderIdentity.generate('chat')
    // console.log('Sender ID:', sender.toString())
    assert.ok(sender)
  })
  test('serialize', () => {
    serialized = sender.serialize()
    // console.log('Sender Serialized:', serialized)
    assert.ok(serialized)
  })
  test('fromSerialized', async () => {
    const restored = await SenderIdentity.fromSerialized(serialized)
    // console.log('Sender Restored:', restored)
    assert.ok(restored)
  })
})

describe('DestinationIdentity', () => {
  test('fromAnnounce', async () => {
    packetAnnounce = await parseReticulum(await readFile('test/packets/announce.bin'))
    destination = await DestinationIdentity.fromAnnounce(packetAnnounce.announce)
    // console.log('Destination ID:', destination.toString())
    assert.ok(destination)
  })
  test('serialize', () => {
    const serialized = destination.serialize()
    assert.ok(serialized)
  })
  test('fromSerialized', async () => {
    const restored = await SenderIdentity.fromSerialized(serialized)
    assert.ok(restored)
  })
})

describe('Packets', () => {
  test('announce: parseReticulum', async () => {
    packetAnnounce = await parseReticulum(await readFile('test/packets/announce.bin'))
    assert.ok(packetAnnounce)
  })
  test('announce: createAnnounce', async () => {
    const announcePacket = await createAnnounce(sender, 'Hello Network!', false)
    // console.log('Announce packet:', hex(announcePacket))
  })
  test('link: createLinkRequest', async () => {
    linkReq = await createLinkRequest(sender, destination)
    // console.log('Link request packet:', hex(linkReq.packet))
  })
  test('message: createLinkedMessage', async () => {
    const msgPacket = await createLinkedMessage(sender, destination, 'Secret message!', linkReq.link)
    // console.log('Message packet:', hex(msgPacket))
  })
})
