import { describe, test } from 'node:test'
import { readFile } from 'node:fs/promises'
import { lxmfLinkMessage, generateSourceId, parsePacket, parseAnnouncePacket, parseDataPacket, isPacketForMe } from '../src/index.js'

let me
let them

const p = (await readFile('test/testtraffic.txt', 'utf8'))
  .split('\n')
  .map((l) => l.trim())
  .filter((l) => !!l)
const packets = { sent: [], received: [] }

for (const pk of p) {
  if (pk.startsWith('S')) {
    packets.sent.push(
      new Uint8Array(
        pk
          .substring(2)
          .split(' ')
          .map((c) => parseInt(c, 16))
      )
    )
  } else if (pk.startsWith('R')) {
    packets.received.push(
      new Uint8Array(
        pk
          .substring(2)
          .split(' ')
          .map((c) => parseInt(c, 16))
      )
    )
  }
}

describe('Nomad', () => {
  test('generateSourceId', async ({ assert }) => {
    me = await generateSourceId()
    assert.ok(me?.ed25519PrivateKey)
    assert.ok(me?.x25519PrivateKey)
    assert.ok(me?.x25519PublicKey)
    assert.ok(me?.keysetHash)
  })

  // Test two-stage parseAnnouncePacket function
  test('parseAnnouncePacket', async ({ assert }) => {
    // First stage - parse basic packet structure
    const packet = parsePacket(packets.sent[0])
    assert.equal(packet.type, 'data')
    assert.equal(packet.destinationType, 'group')
    assert.equal(packet.propagationType, 'broadcast')

    // Second stage - parse announce data
    them = await parseAnnouncePacket(packet)
    assert.ok(them?.x25519PublicKey)
    assert.ok(them?.keysetHash)
    assert.ok(them?.appData)
    assert.ok(them?.destinationHash)
    assert.ok(them?.nameHash)
    assert.ok(them?.randomHash)
    assert.ok(them?.signature)
    assert.ok(them?.appHash)
    assert.ok(them?.appRatchet)
  })

  // Test general parsePacket with traffic log
  test('parsePacket traffic log', async ({ assert }) => {
    const announces = []
    const dataPackets = []
    const linkRequests = []
    const proofs = []

    // First stage - parse all sent packets
    for (const packetBytes of packets.sent) {
      const packet = parsePacket(packetBytes)

      // Check if addressed to me (for data packets)
      if (packet.type === 'data' && isPacketForMe(packet, me)) {
        packet.addressedToMe = true
      }

      switch (packet.type) {
        case 'announce':
          announces.push(packet)
          break
        case 'data':
          // Second stage - check if it contains announce data
          const parsed = await parseDataPacket(packet)
          if (parsed.announce) {
            announces.push(parsed)
          } else {
            dataPackets.push(packet)
          }
          break
        case 'link_request':
          linkRequests.push(packet)
          break
        case 'proof':
          proofs.push(packet)
          break
      }
    }

    // Check that we found announce packets
    assert.ok(announces.length > 0, 'Should have found announce packets')

    // Check announce packet structure
    if (announces.length > 0) {
      const firstAnnounce = announces[0]

      // If it's a data packet with announce, get the announce data
      const announceData = firstAnnounce.announce || (await parseAnnouncePacket(firstAnnounce))

      assert.ok(announceData?.x25519PublicKey)
      assert.ok(announceData?.keysetHash)
      assert.ok(announceData?.appData)
    }
  })
})
