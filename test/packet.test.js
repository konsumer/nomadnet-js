import { describe, test } from 'node:test'
import assert from 'node:assert'
import { bytesToHex, hexToBytes } from '@noble/curves/utils.js'
import { unpackHeader, verifyAnnounce, PACKET_ANNOUNCE } from '../src/index.js'

// this is real traffic
// xxd -c 0 -p logfile.bin
const packetAnnounceBytes = hexToBytes('2100848ee1c5fa95580b9801e1932590e3cb00234ccdf2fe2dc18713ae73b87754c56c3446a05e802d4c5f97e66daec391fd602a3e0b113f0782f7a2df6acbf8367289f76a33ba3cb0842f2bb9f379d39ce7fc6ec60bc318e2c0f0d9084f9c92c21d0068d01afa909f2cf34adec012c9f2114753a601b176553958d79850c2ebc13c587e7ae53d351d7b69e0c6a299381fe7f231c0c6f06cfdec7cabd847db1cbb352d76b228a3242986b4137098c02c3682beb6a5c5b9639a7f9f20d8fe7107638d33cceea00092c40e416e6f6e796d6f75732050656572c0')

let packet

describe('Packet', () => {
  test('unpackHeader', () => {
    packet = unpackHeader(packetAnnounceBytes)
    assert.ok(packet)

    // is it an announce?
    assert.equal(packet.packetType, PACKET_ANNOUNCE)
  })

  test('verifyAnnounce', () => {
    // verify and get some data
    const a = verifyAnnounce(packet)
    assert.ok(a.verified)
    assert.equal(a.peerName, 'Anonymous Peer')
  })
})
